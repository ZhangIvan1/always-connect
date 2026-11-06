//! Waiting for the kernel to say the network changed (DESIGN.md §32.15),
//! instead of asking every few seconds: a routing socket delivers a
//! message for every route, address and interface change. Watchers block
//! on it and wake only when something changed (or on a slow fallback).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

pub enum Wake {
    Changed,
    Timeout,
    Stopped,
}

pub struct RouteWatch {
    socket: OwnedFd,
}

impl RouteWatch {
    pub fn new() -> Option<RouteWatch> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        let fd = -1;
        if fd < 0 {
            return None;
        }
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK);
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        Some(RouteWatch { socket: unsafe { OwnedFd::from_raw_fd(fd) } })
    }

    fn drain(&self) {
        let mut buf = [0u8; 2048];
        while unsafe { libc::read(self.socket.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) } > 0 {}
    }

    /// Blocks until a routing change (then waits `settle` for the burst
    /// that usually follows and drains it), `timeout`, or `stop` readable.
    pub fn wait(&self, timeout: Duration, settle: Duration, stop: Option<RawFd>) -> Wake {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Wake::Timeout;
            }
            let mut fds = [
                libc::pollfd { fd: self.socket.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: stop.unwrap_or(-1), events: libc::POLLIN, revents: 0 },
            ];
            let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, left.as_millis().min(i32::MAX as u128) as i32) };
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Wake::Timeout;
            }
            if n == 0 {
                return Wake::Timeout;
            }
            if fds[1].revents != 0 {
                return Wake::Stopped;
            }
            if fds[0].revents != 0 {
                std::thread::sleep(settle);
                self.drain();
                return Wake::Changed;
            }
        }
    }
}
