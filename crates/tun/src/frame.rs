use std::io::{self, ErrorKind};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

use tokio::io::Interest;
use tokio::net::UnixStream;

use crate::{Result, TunError};

const MAX_FRAME: usize = 1024 * 1024;

fn cmsg_space_fd() -> usize {
    unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize }
}

fn retryable(err: &io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted)
}

/// Send a length-prefixed frame, optionally passing one file descriptor (SCM_RIGHTS).
///
/// Tokio Unix sockets are nonblocking. `readable()`/`writable()` may complete as a
/// false-positive; a following `sendmsg`/`recvmsg` can then return EAGAIN. This
/// loops with `try_io` until the kernel accepts the bytes (or a real error occurs).
pub async fn send_frame(
    stream: &UnixStream,
    payload: &[u8],
    mut pass_fd: Option<RawFd>,
    op: &'static str,
) -> Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(TunError::Ipc(format!("{op}: IPC frame too large")));
    }
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);

    let mut off = 0usize;
    while off < framed.len() {
        stream.writable().await.map_err(|e| TunError::io(op, e))?;
        match stream.try_io(Interest::WRITABLE, || {
            sendmsg_raw(stream.as_raw_fd(), &framed[off..], pass_fd)
        }) {
            Ok(0) => {
                return Err(TunError::io(
                    op,
                    io::Error::new(ErrorKind::WriteZero, "sendmsg wrote 0 bytes"),
                ));
            }
            Ok(n) => {
                off += n;
                // SCM_RIGHTS is delivered with the first successful sendmsg.
                pass_fd = None;
            }
            Err(e) if retryable(&e) => continue,
            Err(e) => {
                return Err(TunError::io(op, e));
            }
        }
    }
    Ok(())
}

fn sendmsg_raw(sock: RawFd, data: &[u8], pass_fd: Option<RawFd>) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let mut cmsg_buf = vec![0u8; cmsg_space_fd()];
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(fd) = pass_fd {
            msg.msg_control = cmsg_buf.as_mut_ptr().cast();
            msg.msg_controllen = cmsg_buf.len() as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return Err(io::Error::other("CMSG_FIRSTHDR failed"));
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
            ptr::copy_nonoverlapping(&fd, libc::CMSG_DATA(cmsg) as *mut RawFd, 1);
        }
        let n = libc::sendmsg(sock, &msg, 0);
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

pub struct RecvFrame {
    pub payload: Vec<u8>,
    pub fd: Option<OwnedFd>,
}

/// Receive one length-prefixed frame (and at most one passed FD).
pub async fn recv_frame(stream: &UnixStream, op: &'static str) -> Result<RecvFrame> {
    let mut buf = Vec::new();
    let mut passed_fd = None;

    while buf.len() < 4 {
        let (chunk, fd) = recv_chunk(stream, op).await?;
        if chunk.is_empty() {
            return Err(TunError::io(
                op,
                io::Error::new(ErrorKind::UnexpectedEof, "helper socket closed"),
            ));
        }
        buf.extend_from_slice(&chunk);
        if passed_fd.is_none() {
            passed_fd = fd;
        }
    }

    let len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
    if len > MAX_FRAME {
        return Err(TunError::Ipc(format!(
            "{op}: IPC frame length {len} exceeds {MAX_FRAME}"
        )));
    }

    while buf.len() < 4 + len {
        let (chunk, fd) = recv_chunk(stream, op).await?;
        if chunk.is_empty() {
            return Err(TunError::io(
                op,
                io::Error::new(
                    ErrorKind::UnexpectedEof,
                    format!(
                        "helper socket closed mid-frame (have {} of {} bytes)",
                        buf.len(),
                        4 + len
                    ),
                ),
            ));
        }
        buf.extend_from_slice(&chunk);
        if passed_fd.is_none() {
            passed_fd = fd;
        }
    }

    Ok(RecvFrame {
        payload: buf[4..4 + len].to_vec(),
        fd: passed_fd,
    })
}

async fn recv_chunk(stream: &UnixStream, op: &'static str) -> Result<(Vec<u8>, Option<OwnedFd>)> {
    loop {
        stream.readable().await.map_err(|e| TunError::io(op, e))?;
        match stream.try_io(Interest::READABLE, || recvmsg_raw(stream.as_raw_fd())) {
            Ok(v) => return Ok(v),
            Err(e) if retryable(&e) => continue,
            Err(e) => return Err(TunError::io(op, e)),
        }
    }
}

fn recvmsg_raw(sock: RawFd) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut cmsg_buf = vec![0u8; cmsg_space_fd()];
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast();
        msg.msg_controllen = cmsg_buf.len() as _;
        let flags = {
            #[cfg(target_os = "linux")]
            {
                libc::MSG_CMSG_CLOEXEC
            }
            #[cfg(not(target_os = "linux"))]
            {
                0
            }
        };
        let n = libc::recvmsg(sock, &mut msg, flags);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        let mut owned_fd = None;
        if n > 0 {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let fd = ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const RawFd);
                    if fd >= 0 {
                        owned_fd = Some(OwnedFd::from_raw_fd(fd));
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        buf.truncate(n);
        Ok((buf, owned_fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;
    use std::time::Duration;

    #[tokio::test]
    async fn second_roundtrip_after_delayed_reply_does_not_eagain() {
        let (client, server) = UnixStream::pair().unwrap();

        let server_task = tokio::spawn(async move {
            let f = recv_frame(&server, "test-server-recv-1").await.unwrap();
            send_frame(&server, &f.payload, None, "test-server-send-1")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(75)).await;
            let f = recv_frame(&server, "test-server-recv-2").await.unwrap();
            send_frame(&server, &f.payload, None, "test-server-send-2")
                .await
                .unwrap();
        });

        send_frame(&client, b"one", None, "test-client-send-1")
            .await
            .unwrap();
        let r1 = recv_frame(&client, "test-client-recv-1").await.unwrap();
        assert_eq!(r1.payload, b"one");

        send_frame(&client, b"two", None, "test-client-send-2")
            .await
            .unwrap();
        let r2 = recv_frame(&client, "test-client-recv-2").await.unwrap();
        assert_eq!(r2.payload, b"two");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn passes_file_descriptor() {
        let (client, server) = UnixStream::pair().unwrap();
        let (r, w) = std::os::unix::net::UnixStream::pair().unwrap();
        let raw = w.into_raw_fd();

        let server_task = tokio::spawn(async move {
            let f = recv_frame(&server, "fd-recv").await.unwrap();
            send_frame(&server, &f.payload, Some(raw), "fd-send")
                .await
                .unwrap();
            let _ = unsafe { libc::close(raw) };
        });

        send_frame(&client, b"give-fd", None, "fd-req")
            .await
            .unwrap();
        let got = recv_frame(&client, "fd-resp").await.unwrap();
        assert_eq!(got.payload, b"give-fd");
        assert!(got.fd.is_some(), "expected SCM_RIGHTS file descriptor");
        drop(got.fd);
        drop(r);
        server_task.await.unwrap();
    }
}
