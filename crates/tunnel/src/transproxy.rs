use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use rt_dns::{default_dns_servers, exchange_over_tcp};
use rt_socks::UpstreamConnector;
use rt_udpgw::UdpgwHandle;
use tokio::io::{AsyncReadExt, Interest};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::Result;

const SOL_IP: i32 = libc::SOL_IP;
const SOL_IPV6: i32 = libc::SOL_IPV6;
const SO_ORIGINAL_DST: i32 = 80;
const IP6T_SO_ORIGINAL_DST: i32 = 80;
const IP_RECVORIGDSTADDR: i32 = 20;
const IP_ORIGDSTADDR: i32 = 20;
const IPV6_RECVORIGDSTADDR: i32 = 74;
const IPV6_ORIGDSTADDR: i32 = 74;

pub async fn run_transproxy(
    listener: TcpListener,
    upstream: Arc<dyn UpstreamConnector>,
    stop: CancellationToken,
) -> Result<()> {
    let listen = listener.local_addr().ok();
    info!(?listen, "transparent TCP intercept listening");
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let upstream = Arc::clone(&upstream);
                        tokio::spawn(async move {
                            if let Err(e) = handle_intercepted(stream, upstream.as_ref()).await {
                                debug!(%peer, error = %e, "transproxy session ended");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "transproxy accept failed");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_intercepted(
    mut client: TcpStream,
    upstream: &dyn UpstreamConnector,
) -> io::Result<()> {
    let dest = original_dst(&client)?;
    debug!(%dest, "intercepted TCP → SSH direct-tcpip");
    match upstream.connect(&dest.ip().to_string(), dest.port()).await {
        Ok(mut rhs) => {
            if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut rhs).await {
                debug!(%dest, error = %e, "transproxy relay ended");
            }
        }
        Err(e) => debug!(%dest, error = %e, "SSH forward failed"),
    }
    Ok(())
}

fn original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    if let Some(v4) = original_dst_v4(fd) {
        return Ok(v4);
    }
    if let Some(v6) = original_dst_v6(fd) {
        return Ok(v6);
    }
    stream.peer_addr()
}

fn original_dst_v4(fd: i32) -> Option<SocketAddr> {
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc == 0 && i32::from(addr.sin_family) == libc::AF_INET {
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
        }
    }
    None
}

fn original_dst_v6(fd: i32) -> Option<SocketAddr> {
    unsafe {
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc == 0 && i32::from(addr.sin6_family) == libc::AF_INET6 {
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            return Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )));
        }
    }
    None
}

pub async fn run_dns_intercept(
    sock: UdpSocket,
    upstream: Arc<dyn UpstreamConnector>,
    dns_servers: Vec<String>,
    udpgw: Option<UdpgwHandle>,
    stop: CancellationToken,
) -> Result<()> {
    let listen = sock.local_addr().ok();
    let sock = Arc::new(sock);
    let via = if udpgw.is_some() {
        "UDPGW then DNS-over-TCP"
    } else {
        "DNS-over-TCP"
    };
    info!(?listen, %via, "transparent DNS intercept listening");
    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            recv = sock.recv_from(&mut buf) => {
                match recv {
                    Ok((n, from)) => {
                        let query = buf[..n].to_vec();
                        let upstream = Arc::clone(&upstream);
                        let servers = dns_servers.clone();
                        let sock = Arc::clone(&sock);
                        let gw = udpgw.clone();
                        tokio::spawn(async move {
                            if let Some(resp) =
                                resolve_dns_query(&query, upstream.as_ref(), &servers, gw.as_ref()).await
                            {
                                let _ = sock.send_to(&resp, from).await;
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "DNS intercept recv failed");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn resolve_dns_query(
    query: &[u8],
    upstream: &dyn UpstreamConnector,
    dns_servers: &[String],
    udpgw: Option<&UdpgwHandle>,
) -> Option<Vec<u8>> {
    if let Some(gw) = udpgw {
        let mut servers: Vec<String> = dns_servers.to_vec();
        if servers.is_empty() {
            servers = default_dns_servers()
                .iter()
                .map(|s| (*s).to_string())
                .collect();
        }
        for host in &servers {
            let dest = format!("{host}:53");
            if let Ok(addr) = dest.parse() {
                match gw.query_dns(addr, query).await {
                    Ok(resp) if !resp.is_empty() => return Some(resp),
                    Ok(_) => debug!(%host, "UDPGW DNS empty"),
                    Err(e) => debug!(%host, error = %e, "UDPGW DNS failed"),
                }
            } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                let addr = SocketAddr::from((ip, 53));
                match gw.query_dns(addr, query).await {
                    Ok(resp) if !resp.is_empty() => return Some(resp),
                    Ok(_) => debug!(%host, "UDPGW DNS empty"),
                    Err(e) => debug!(%host, error = %e, "UDPGW DNS failed"),
                }
            }
        }
    }
    dns_over_tcp_query(query, upstream, dns_servers).await
}

pub async fn pump_udpgw_replies(
    socks: Vec<Arc<UdpSocket>>,
    mut replies: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    stop: CancellationToken,
) {
    while let Some((from, payload)) = tokio::select! {
        _ = stop.cancelled() => None,
        msg = replies.recv() => msg,
    } {
        for sock in &socks {
            if sock.send_to(&payload, from).await.is_ok() {
                break;
            }
        }
    }
}

pub async fn run_udp_intercept(
    sock: Arc<UdpSocket>,
    udpgw: UdpgwHandle,
    stop: CancellationToken,
) -> Result<()> {
    let listen = sock.local_addr().ok();
    info!(?listen, "transparent UDP intercept listening (UDPGW)");
    let fd = sock.as_raw_fd();
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            ready = sock.readable() => {
                if ready.is_err() {
                    break;
                }
                match sock.try_io(Interest::READABLE, || recv_udp_origdst(fd, &mut buf)) {
                    Ok((n, from, dest)) => {
                        if dest.ip().is_loopback() {
                            continue;
                        }
                        let payload = buf[..n].to_vec();
                        let gw = udpgw.clone();
                        tokio::spawn(async move {
                            if let Err(e) = gw.send_udp(from, dest, &payload, dest.port() == 53).await {
                                debug!(%dest, error = %e, "UDPGW send failed");
                            }
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        warn!(error = %e, "UDP intercept recv failed");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn bind_udp_origdst(addr: SocketAddr) -> io::Result<UdpSocket> {
    let std_sock = std::net::UdpSocket::bind(addr)?;
    std_sock.set_nonblocking(true)?;
    let fd = std_sock.as_raw_fd();
    let on: libc::c_int = 1;
    unsafe {
        if addr.is_ipv4() {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                IP_RECVORIGDSTADDR,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of_val(&on) as libc::socklen_t,
            );
        } else {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IPV6_RECVORIGDSTADDR,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of_val(&on) as libc::socklen_t,
            );
        }
    }
    UdpSocket::from_std(std_sock)
}

fn recv_udp_origdst(fd: i32, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; 256];
        let mut src_storage: libc::sockaddr_storage = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let src = sockaddr_storage(&src_storage).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "UDP source address missing")
        })?;
        let dest = origdst_from_cmsg(&msg).unwrap_or(src);
        Ok((n as usize, src, dest))
    }
}

fn sockaddr_storage(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match ss.ss_family as i32 {
        libc::AF_INET => {
            let a = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            Some(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let a = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(a.sin6_addr.s6_addr);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

unsafe fn origdst_from_cmsg(msg: &libc::msghdr) -> Option<SocketAddr> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    while !cmsg.is_null() {
        let hdr = &*cmsg;
        if hdr.cmsg_level == libc::IPPROTO_IP && hdr.cmsg_type == IP_ORIGDSTADDR {
            let a = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            return Some(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(a.sin_port),
            )));
        }
        if hdr.cmsg_level == libc::IPPROTO_IPV6 && hdr.cmsg_type == IPV6_ORIGDSTADDR {
            let a = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6);
            let ip = Ipv6Addr::from(a.sin6_addr.s6_addr);
            return Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )));
        }
        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
    }
    None
}

async fn dns_over_tcp_query(
    query: &[u8],
    upstream: &dyn UpstreamConnector,
    dns_servers: &[String],
) -> Option<Vec<u8>> {
    let mut servers: Vec<String> = dns_servers.to_vec();
    if servers.is_empty() {
        servers = default_dns_servers()
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }
    for host in servers {
        match upstream.connect(&host, 53).await {
            Ok(stream) => match exchange_over_tcp(query, stream).await {
                Ok(resp) => return Some(resp),
                Err(e) => debug!(%host, error = %e, "DNS-over-TCP failed"),
            },
            Err(e) => debug!(%host, error = %e, "DNS-over-TCP connect failed"),
        }
    }
    None
}

/// Read and discard TUN frames so a leftover route cannot fill the kernel queue.
pub async fn drain_tun(mut tun: rt_tun::TunIo, stop: CancellationToken) {
    let mut buf = vec![0u8; 2048];
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            n = tun.read(&mut buf) => {
                match n {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }
}
