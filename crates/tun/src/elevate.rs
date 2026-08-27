//! Ensure the privileged helper is reachable; elevate via polkit/pkexec when needed.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use thiserror::Error;
use tokio::process::Command;
use tracing::{info, warn};

use crate::client::HelperClient;
use crate::{Result, TunError, DEFAULT_SOCKET};

#[derive(Debug, Error)]
pub enum ElevateError {
    #[error("Elevation denied: polkit authentication was cancelled or rejected.")]
    Denied,
    #[error(
        "pkexec is not available on this system. Install polkitd and pkexec, or run: sudo easy-helper --allow-uid $(id -u)"
    )]
    PkexecMissing,
    #[error("Helper binary not found at {0}. Reinstall the easy-connection package.")]
    HelperMissing(String),
    #[error("Failed to start helper via pkexec: {0}")]
    Spawn(String),
    #[error("Helper started but the control socket never appeared at {0}")]
    SocketTimeout(String),
    #[error("{0}")]
    Other(String),
}

const HELPER_BIN: &str = "/usr/lib/easy/easy-helper";
const HELPER_BIN_ALT: &str = "/usr/local/lib/easy/easy-helper";

fn helper_bin() -> Option<&'static str> {
    if Path::new(HELPER_BIN).is_file() {
        Some(HELPER_BIN)
    } else if Path::new(HELPER_BIN_ALT).is_file() {
        Some(HELPER_BIN_ALT)
    } else {
        None
    }
}

/// Returns true if the helper Unix socket accepts a Ping.
pub async fn helper_reachable() -> bool {
    match HelperClient::connect_default().await {
        Ok(c) => c.ping().await.is_ok(),
        Err(_) => false,
    }
}

/// If the helper is already up (systemd or prior pkexec), do nothing.
/// Otherwise launch `pkexec easy-helper --allow-uid <uid>` so the OS shows
/// its native auth dialog. Never uses NOPASSWD sudoers or setuid.
pub async fn ensure_helper_running() -> std::result::Result<(), ElevateError> {
    if helper_reachable().await {
        info!("privileged helper already reachable");
        return Ok(());
    }

    if Path::new("/usr/lib/systemd/system/easy-helper.service").exists()
        || Path::new("/etc/systemd/system/easy-helper.service").exists()
    {
        let _ = Command::new("systemctl")
            .args(["start", "easy-helper.service"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if helper_reachable().await {
                info!("privileged helper started via systemd");
                return Ok(());
            }
        }
    }

    if which("pkexec").is_none() {
        return Err(ElevateError::PkexecMissing);
    }
    let bin = helper_bin().ok_or_else(|| ElevateError::HelperMissing(HELPER_BIN.into()))?;
    let uid = unsafe { libc::getuid() };

    info!(uid, bin, "launching helper via pkexec (polkit)");
    let mut child = Command::new("pkexec")
        .arg(bin)
        .arg("--socket")
        .arg(DEFAULT_SOCKET)
        .arg("--allow-uid")
        .arg(uid.to_string())
        .arg("--allow-active-sessions")
        .arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false)
        .spawn()
        .map_err(|e| ElevateError::Spawn(e.to_string()))?;

    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if helper_reachable().await {
            info!("privileged helper reachable after pkexec");
            // Leave the helper running; drop without kill_on_drop.
            return Ok(());
        }
        match child.try_wait() {
            Ok(Some(st)) => {
                let code = st.code().unwrap_or(-1);
                if code == 126 || code == 127 {
                    return Err(ElevateError::PkexecMissing);
                }
                if !st.success() {
                    return Err(ElevateError::Denied);
                }
                return Err(ElevateError::SocketTimeout(DEFAULT_SOCKET.into()));
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "pkexec try_wait failed"),
        }
    }

    let _ = child.kill().await;
    Err(ElevateError::SocketTimeout(DEFAULT_SOCKET.into()))
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let p = dir.join(bin);
            p.is_file().then_some(p)
        })
    })
}

/// Convenience for tunnel engine: map elevate errors into TunError.
pub async fn ensure_helper_or_tun_error() -> Result<()> {
    ensure_helper_running()
        .await
        .map_err(|e| TunError::HelperUnavailable(e.to_string()))
}
