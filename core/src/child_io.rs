//! Private descriptor creation and child exec share one short critical section.
//! Never hold it during network IO, output draining or child wait.
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, ExitStatus};
use std::sync::Mutex;

#[derive(Default)]
struct Window {
    lock: Mutex<()>,
}
impl Window {
    fn within<T>(&self, body: impl FnOnce() -> T) -> T {
        let _guard = self.lock.lock().unwrap_or_else(|error| error.into_inner());
        body()
    }
}
static PROCESS_WINDOW: Window = Window {
    lock: Mutex::new(()),
};

// Callers must keep creation sections limited to descriptor initialization.
// No callbacks, name resolution, blocking accept, read or wait belong here.
pub(crate) fn creation<T>(body: impl FnOnce() -> T) -> T {
    PROCESS_WINDOW.within(body)
}
pub(crate) fn spawn(command: &mut Command) -> io::Result<Child> {
    PROCESS_WINDOW.within(|| command.spawn())
}
/// Wait only for in-progress exec handoffs after closing a private descriptor.
/// CLOEXEC removes transient fork copies at exec, not at the parent's close.
/// New spawns cannot copy a descriptor the parent has already closed.
pub(crate) fn after_close() {
    PROCESS_WINDOW.within(|| ());
}
pub(crate) fn status(command: &mut Command) -> io::Result<ExitStatus> {
    spawn(command)?.wait()
}
pub(crate) fn socket(domain: Domain, kind: Type, protocol: Option<Protocol>) -> io::Result<Socket> {
    creation(|| Socket::new(domain, kind, protocol))
}
fn cloexec(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn raw_socket(domain: i32, kind: i32, protocol: i32) -> io::Result<OwnedFd> {
    creation(|| {
        let fd = unsafe { libc::socket(domain, kind, protocol) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        cloexec(fd)?;
        Ok(owned)
    })
}
pub(crate) fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    creation(|| {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        cloexec(read.as_raw_fd())?;
        cloexec(write.as_raw_fd())?;
        Ok((read, write))
    })
}
pub(crate) fn udp_bind(address: SocketAddrV4) -> io::Result<UdpSocket> {
    creation(|| UdpSocket::bind(address))
}
/// The listener must already be nonblocking; accept only creates the new FD.
pub(crate) fn accept(listener: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    creation(|| listener.accept())
}
pub(crate) fn unix_pair() -> io::Result<(UnixStream, UnixStream)> {
    creation(UnixStream::pair)
}
pub(crate) fn duplicate(fd: i32) -> io::Result<OwnedFd> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::process::Stdio;
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    #[test]
    fn exec_waits_until_a_registered_creation_finishes() {
        let window = Arc::new(Window::default());
        let creator_window = window.clone();
        let (entered, ready) = mpsc::channel();
        let (finish, release) = mpsc::channel();
        let creator = std::thread::spawn(move || {
            creator_window.within(|| {
                let socket = creation(|| UdpSocket::bind("127.0.0.1:0")).unwrap();
                entered.send(socket.local_addr().unwrap()).unwrap();
                release.recv().unwrap();
                socket
            })
        });
        let address = ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let (spawned, child_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            window.within(|| {
                let mut command = Command::new("/bin/sleep");
                command
                    .arg("5")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                crate::reset_child_signals(&mut command);
                spawned.send(spawn(&mut command).unwrap()).unwrap();
            })
        });
        let early = child_rx.recv_timeout(Duration::from_millis(150)).ok();
        let blocked = early.is_none();
        finish.send(()).unwrap();
        let socket = creator.join().unwrap();
        let mut child =
            early.unwrap_or_else(|| child_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        drop(socket);
        after_close();
        let rebound = UdpSocket::bind(address);
        child.kill().unwrap();
        child.wait().unwrap();
        worker.join().unwrap();
        assert!(
            blocked,
            "a child exec must not overlap a registered descriptor creation"
        );
        assert!(
            rebound.is_ok(),
            "closing the parent socket must free its port while the unrelated child lives"
        );
    }

    #[test]
    fn private_pipe_writer_does_not_escape_into_a_child() {
        let (read, write) = pipe().unwrap();
        let flags = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(
            unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let mut command = Command::new("/bin/sleep");
        command
            .arg("5")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn(&mut command).unwrap();
        drop(write);
        after_close();
        let result = std::fs::File::from(read).read(&mut [0u8; 1]);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            matches!(result, Ok(0)),
            "a child must not keep a private pipe alive: {result:?}"
        );
    }
    #[test]
    fn explicit_standard_streams_and_spawn_errors_keep_working() {
        use std::io::Write;
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "IFS= read -r value; printf '%s' \"$value\"; printf 'diagnostic' >&2",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        crate::reset_child_signals(&mut command);
        let mut child = spawn(&mut command).unwrap();
        // The child is still waiting for input: creation must already work.
        let extra = pipe().unwrap();
        drop(extra);
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"fixture-input\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"fixture-input");
        assert_eq!(output.stderr, b"diagnostic");
        let mut missing = Command::new(std::env::temp_dir().join(format!(
            "alwaysconnect-missing-executable-{}",
            std::process::id()
        )));
        assert_eq!(
            spawn(&mut missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        drop(pipe().unwrap());
    }

    #[test]
    fn duplex_and_duplicate_do_not_escape_into_a_child() {
        let (mut read, write) = unix_pair().unwrap();
        read.set_nonblocking(true).unwrap();
        let duplicate = duplicate(write.as_raw_fd()).unwrap();
        let mut command = Command::new("/bin/sleep");
        command
            .arg("5")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn(&mut command).unwrap();
        drop(write);
        drop(duplicate);
        after_close();
        let result = read.read(&mut [0; 1]);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            matches!(result, Ok(0)),
            "unrelated exec must not keep a duplex peer alive: {result:?}"
        );
        assert!(self::duplicate(-1).is_err());
    }
}
