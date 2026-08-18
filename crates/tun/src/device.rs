use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Result, TunError, TUN_NAME};

/// Create `easy0` (IFF_TUN | IFF_NO_PI) and return an owned FD.
pub fn create_named_tun(name: &str) -> Result<OwnedFd> {
    if name != TUN_NAME {
        return Err(TunError::InvalidName(name.to_string()));
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(|e| {
            TunError::Other(format!(
                "cannot open /dev/net/tun: {e}. The privileged helper needs CAP_NET_ADMIN."
            ))
        })?;

    let fd = file.as_raw_fd();
    tunsetiff(fd, name)?;
    set_nonblocking(fd)?;
    Ok(file.into())
}

fn tunsetiff(fd: RawFd, name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(TunError::InvalidName(name.to_string()));
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr().cast::<libc::c_char>(),
            ifr.ifr_name.as_mut_ptr(),
            bytes.len(),
        );
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        if libc::ioctl(fd, libc::TUNSETIFF as _, &mut ifr) < 0 {
            return Err(TunError::io("ioctl TUNSETIFF", io::Error::last_os_error()));
        }
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(TunError::io(
            "fcntl F_GETFL (TUN)",
            io::Error::last_os_error(),
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(TunError::io(
            "fcntl O_NONBLOCK (TUN)",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Async packet IO over a TUN file descriptor (IFF_NO_PI).
pub struct TunIo {
    inner: AsyncFd<File>,
}

impl TunIo {
    pub fn from_owned_fd(fd: OwnedFd) -> Result<Self> {
        set_nonblocking(fd.as_raw_fd())?;
        let file = File::from(fd);
        Ok(Self {
            inner: AsyncFd::new(file).map_err(|e| TunError::io("AsyncFd::new(TUN)", e))?,
        })
    }

    /// # Safety
    /// `fd` must be a valid TUN descriptor the caller uniquely owns.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Result<Self> {
        Self::from_owned_fd(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

impl AsyncRead for TunIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = std::task::ready!(this.inner.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        unfilled.as_mut_ptr().cast(),
                        unfilled.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(0)) => return Poll::Ready(Ok(())),
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) if e.kind() == ErrorKind::Interrupted => continue,
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for TunIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = std::task::ready!(this.inner.poll_write_ready(cx))?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(inner.get_ref().as_raw_fd(), buf.as_ptr().cast(), buf.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
