use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use rt_dns::{effective_policy, resolve_servers, should_configure_resolved, DnsPolicy};
use rt_nftables::{apply_table, render_table, restore as nft_restore};
use rt_routing::{restore_added, run_ip, AddedRoute};
use rt_tun::ipc::{ApplySpec, HelperRequest, HelperResponse, IPC_VERSION};
use rt_tun::{
    create_named_tun, recv_frame, send_frame, NFT_TABLE, SESSION_JOURNAL, TUN_ADDR_V6, TUN_NAME,
    TUN_PREFIX_V6,
};
use serde::{Deserialize, Serialize};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "easy-helper", about = "Privileged TUN/nftables/route helper")]
struct Args {
    #[arg(long, default_value = rt_tun::DEFAULT_SOCKET)]
    socket: PathBuf,
    /// UIDs allowed to call the helper (repeatable).
    #[arg(long = "allow-uid")]
    allow_uid: Vec<u32>,
    /// Allow any uid that has /run/user/$UID (typical desktop session).
    /// Accepts `--allow-active-sessions`, `--allow-active-sessions=true`, and `=false`.
    #[arg(
        long,
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    allow_active_sessions: bool,
    #[arg(long, default_value_t = false)]
    world_socket: bool,
    /// Remove leftover TUN/routes/nftables and exit.
    #[arg(long, default_value_t = false)]
    cleanup_and_exit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionJournalFile {
    tun_name: String,
    added: Vec<AddedRoute>,
}

struct ActiveSession {
    added: Vec<AddedRoute>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    std::fs::create_dir_all(rt_tun::RUN_DIR).ok();

    cleanup_stale().await;

    if args.cleanup_and_exit {
        info!("cleanup complete");
        return Ok(());
    }

    if args.socket.exists() {
        let _ = std::fs::remove_file(&args.socket);
    }
    if let Some(parent) = args.socket.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let prev = unsafe { libc::umask(0o000) };
    let listener = UnixListener::bind(&args.socket)?;
    unsafe { libc::umask(prev) };

    let mode = if args.world_socket || args.allow_active_sessions {
        0o666
    } else {
        0o660
    };
    chmod(&args.socket, mode)?;

    info!(socket = %args.socket.display(), "easy-helper listening");

    let state = Arc::new(Mutex::new(None::<ActiveSession>));
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("SIGTERM — restoring networking");
                teardown_session(&state).await;
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT — restoring networking");
                teardown_session(&state).await;
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let args_allow = args.allow_uid.clone();
                        let allow_sessions = args.allow_active_sessions;
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, state, &args_allow, allow_sessions).await {
                                warn!(error = %e, "helper client ended");
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept failed");
                    }
                }
            }
        }
    }

    let _ = std::fs::remove_file(&args.socket);
    Ok(())
}

fn chmod(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

fn peer_uid(stream: &UnixStream) -> anyhow::Result<u32> {
    let fd = stream.as_raw_fd();
    unsafe {
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            anyhow::bail!("SO_PEERCRED: {}", std::io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
}

fn authorized(uid: u32, allow_uid: &[u32], allow_active_sessions: bool) -> bool {
    if uid == 0 || allow_uid.contains(&uid) {
        return true;
    }
    if allow_active_sessions && Path::new(&format!("/run/user/{uid}")).is_dir() {
        return true;
    }
    false
}

async fn handle_client(
    stream: UnixStream,
    state: Arc<Mutex<Option<ActiveSession>>>,
    allow_uid: &[u32],
    allow_active_sessions: bool,
) -> anyhow::Result<()> {
    let uid = peer_uid(&stream)?;
    if !authorized(uid, allow_uid, allow_active_sessions) {
        let resp = HelperResponse::Error {
            message: format!(
                "uid {uid} is not authorized to use easy-helper. Pass --allow-uid {uid} or add the user to an active session."
            ),
        };
        let payload = serde_json::to_vec(&resp)?;
        send_frame(&stream, &payload, None, "helper deny unauthorized uid").await?;
        return Ok(());
    }

    loop {
        let frame = match recv_frame(&stream, "helper recv client request").await {
            Ok(f) => f,
            Err(e) if e.is_disconnect() => {
                warn!(uid, error = %e, "client disconnected; restoring if this session owned the TUN");
                teardown_session(&state).await;
                break;
            }
            Err(e) => {
                warn!(uid, error = %e, "helper IPC recv failed; restoring if this session owned the TUN");
                teardown_session(&state).await;
                break;
            }
        };
        let req: HelperRequest = serde_json::from_slice(&frame.payload)?;
        match req {
            HelperRequest::Ping { .. } => {
                let resp = HelperResponse::Pong {
                    version: IPC_VERSION,
                    uid,
                };
                send_json(&stream, &resp, None).await?;
            }
            HelperRequest::Cleanup | HelperRequest::EmergencyRestore => {
                teardown_session(&state).await;
                cleanup_stale().await;
                send_json(
                    &stream,
                    &HelperResponse::Ok {
                        message: "networking restored; leftover Easy Connection state removed"
                            .into(),
                        tun_name: None,
                    },
                    None,
                )
                .await?;
            }
            HelperRequest::Teardown => {
                teardown_session(&state).await;
                send_json(
                    &stream,
                    &HelperResponse::Ok {
                        message: "tunnel networking restored".into(),
                        tun_name: None,
                    },
                    None,
                )
                .await?;
            }
            HelperRequest::Apply { spec } => match apply_spec(spec, &state).await {
                Ok((msg, tun_fd)) => {
                    send_json(
                        &stream,
                        &HelperResponse::Ok {
                            message: msg,
                            tun_name: Some(TUN_NAME.into()),
                        },
                        Some(tun_fd.as_raw_fd()),
                    )
                    .await?;
                    drop(tun_fd);
                }
                Err(e) => {
                    error!(error = %e, "apply failed");
                    send_json(
                        &stream,
                        &HelperResponse::Error {
                            message: e.to_string(),
                        },
                        None,
                    )
                    .await?;
                }
            },
        }
    }
    Ok(())
}

async fn send_json(
    stream: &UnixStream,
    resp: &HelperResponse,
    fd: Option<RawFd>,
) -> anyhow::Result<()> {
    let op = match resp {
        HelperResponse::Pong { .. } => "helper send Pong",
        HelperResponse::Ok { .. } if fd.is_some() => "helper send Apply (with TUN fd)",
        HelperResponse::Ok { .. } => "helper send Ok",
        HelperResponse::Error { .. } => "helper send Error",
    };
    let payload = serde_json::to_vec(resp)?;
    send_frame(stream, &payload, fd, op).await?;
    Ok(())
}

async fn apply_spec(
    spec: ApplySpec,
    state: &Mutex<Option<ActiveSession>>,
) -> anyhow::Result<(String, std::os::fd::OwnedFd)> {
    spec.validate().map_err(|e| anyhow::anyhow!(e))?;
    {
        let guard = state.lock().await;
        if guard.is_some() {
            anyhow::bail!("a tunnel session is already active; disconnect first");
        }
    }

    cleanup_stale().await;

    let tun_fd = create_named_tun(&spec.tun_name)?;
    if let Err(e) = configure_tun(&spec).await {
        let _ = run_ip(&["link", "delete", TUN_NAME]).await;
        return Err(e);
    }

    let added: Vec<AddedRoute> = Vec::new();

    let bypass = if spec.bypass_private {
        spec.extra_bypass
            .iter()
            .cloned()
            .chain(rt_routing::private_cidrs())
            .collect::<Vec<_>>()
    } else {
        spec.extra_bypass.clone()
    };
    let script = render_table(
        &spec.server_ips,
        &bypass,
        spec.kill_switch,
        spec.transproxy_port,
        spec.dns_port,
        spec.ipv6,
        spec.udp_port,
    );
    if let Err(e) = apply_table(&script).await {
        let _ = restore_added(&added).await;
        let _ = run_ip(&["link", "delete", TUN_NAME]).await;
        return Err(e.into());
    }

    let policy = effective_policy(true, DnsPolicy::parse(&spec.dns_mode));
    let servers = resolve_servers(policy, &spec.dns_servers);
    let dns_note = if should_configure_resolved(policy) {
        configure_resolved(&spec.tun_name, &servers).await
    } else {
        "system DNS left unchanged".into()
    };
    info!(%dns_note, policy = policy.as_str(), "systemd-resolved policy");

    write_journal(&added)?;
    *state.lock().await = Some(ActiveSession {
        added: added.clone(),
    });

    Ok((
        format!(
            "TUN {} up, nftables table inet {} (TCP :{}, DNS :{}, UDP :{}, ipv6={}, dns={})",
            spec.tun_name,
            NFT_TABLE,
            spec.transproxy_port,
            spec.dns_port,
            if spec.udp_port == 0 {
                "reject".into()
            } else {
                spec.udp_port.to_string()
            },
            spec.ipv6,
            policy.as_str()
        ),
        tun_fd,
    ))
}

async fn configure_resolved(tun_name: &str, servers: &[String]) -> String {
    let mut notes = Vec::new();
    let mut dns_args = vec!["dns".to_string(), tun_name.to_string()];
    if servers.is_empty() {
        dns_args.extend(["1.1.1.1".into(), "8.8.8.8".into()]);
    } else {
        dns_args.extend(servers.iter().cloned());
    }
    for args in [
        dns_args,
        vec!["domain".into(), tun_name.into(), "~.".into()],
        vec!["default-route".into(), tun_name.into(), "yes".into()],
        vec!["flush-caches".into()],
    ] {
        match tokio::process::Command::new("resolvectl")
            .args(&args)
            .output()
            .await
        {
            Ok(out) if out.status.success() => notes.push(format!("{}:ok", args.join(" "))),
            Ok(out) => notes.push(format!(
                "{}:{}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            Err(e) => notes.push(format!("{}:{}", args.join(" "), e)),
        }
    }
    notes.join(" | ")
}

async fn revert_resolved(tun_name: &str) {
    let _ = tokio::process::Command::new("resolvectl")
        .args(["revert", tun_name])
        .output()
        .await;
    let _ = tokio::process::Command::new("resolvectl")
        .args(["flush-caches"])
        .output()
        .await;
}

async fn configure_tun(spec: &ApplySpec) -> anyhow::Result<()> {
    let mtu = spec.mtu.to_string();
    run_ip(&["link", "set", &spec.tun_name, "mtu", &mtu]).await?;
    let addr = format!("{}/{}", spec.tun_addr, spec.tun_prefix);
    match run_ip(&["addr", "add", &addr, "dev", &spec.tun_name]).await {
        Ok(_) => {}
        Err(e) if e.to_string().contains("File exists") => {}
        Err(e) => return Err(e.into()),
    }
    if spec.ipv6 {
        let v6 = format!("{TUN_ADDR_V6}/{TUN_PREFIX_V6}");
        match run_ip(&["addr", "add", &v6, "dev", &spec.tun_name]).await {
            Ok(_) => {}
            Err(e) if e.to_string().contains("File exists") => {}
            Err(e) => return Err(e.into()),
        }
    }
    run_ip(&["link", "set", &spec.tun_name, "up"]).await?;
    Ok(())
}

async fn teardown_session(state: &Mutex<Option<ActiveSession>>) {
    revert_resolved(TUN_NAME).await;
    let session = state.lock().await.take();
    if let Some(s) = session {
        let _ = restore_added(&s.added).await;
    }
    cleanup_stale().await;
}

async fn cleanup_stale() {
    revert_resolved(TUN_NAME).await;
    if let Some(j) = read_journal() {
        let _ = restore_added(&j.added).await;
    }
    let _ = nft_restore().await;
    if let Err(e) = run_ip(&["link", "delete", TUN_NAME]).await {
        let msg = e.to_string();
        if !msg.contains("Cannot find device") && !msg.contains("does not exist") {
            warn!(error = %msg, tun = TUN_NAME, "ip link delete");
        }
    }
    let _ = std::fs::remove_file(SESSION_JOURNAL);
}

fn write_journal(added: &[AddedRoute]) -> anyhow::Result<()> {
    let doc = SessionJournalFile {
        tun_name: TUN_NAME.into(),
        added: added.to_vec(),
    };
    let tmp = format!("{SESSION_JOURNAL}.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&doc)?)?;
    std::fs::rename(tmp, SESSION_JOURNAL)?;
    Ok(())
}

fn read_journal() -> Option<SessionJournalFile> {
    let raw = std::fs::read(SESSION_JOURNAL).ok()?;
    serde_json::from_slice(&raw).ok()
}
