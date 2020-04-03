//! Establish connections to, and run commands on remote machines via ssh.
//!
//! `sessh` implements a lightweight wrapper over the [`ssh2`](https://crates.io/crates/ssh2) crate which makes
//! it easy to connect to and run commands on remote machines.
//!
//! See [`Session`](struct.Session.html) for more details.

use educe::Educe;
use failure::{bail, format_err};
use failure::{Error, Fail, ResultExt};
use slog;
use slog::{trace, warn};
use ssh2;
use std::fs::File;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Fail)]
#[fail(display = "error transferring file {}: {}", file, msg)]
struct FileTransferFailure {
    file: String,
    msg: String,
}

/// An established SSH session.
///
/// See [`ssh2::Session`](https://docs.rs/ssh2/0.8/ssh2/struct.Session.html) in general, and
/// [`ssh2::Session#channel_session`](https://docs.rs/ssh2/0.8/ssh2/struct.Session.html#method.channel_session)
/// specifically, for how to execute commands on the remote host.
///
/// To execute a command and get its `STDOUT` output, use
/// [`Session#cmd`](struct.Session.html#method.cmd).
#[derive(Educe)]
#[educe(Debug)]
pub struct Session {
    /// The connected address
    pub addr: SocketAddr,
    #[educe(Debug(ignore))]
    ssh: ssh2::Session,
}

impl From<ssh2::Session> for Session {
    fn from(s: ssh2::Session) -> Self {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let addr = unsafe { std::net::TcpStream::from_raw_fd(s.as_raw_fd()) }
            .peer_addr()
            .unwrap();
        Self { addr, ssh: s }
    }
}

impl Session {
    /// Connect to the remote machine at `addr`, using user `username`.
    ///
    /// Analogous to `ssh -i <key> <username>@<addr>`.
    ///
    /// If `timeout` is `None`, will block for a TCP response forever.
    ///
    /// If `key` is `None`, attempts to use ssh-agent authentication.
    pub fn connect(
        log: &slog::Logger,
        username: &str,
        addr: SocketAddr,
        key: Option<&Path>,
        timeout: Option<Duration>,
    ) -> Result<Self, Error> {
        let start = Instant::now();
        let tcp = loop {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(s) => break s,
                Err(e) => {
                    if let Some(to) = timeout {
                        if start.elapsed() <= to {
                            trace!(log, "still can't ssh to {}", addr);
                            thread::sleep(Duration::from_secs(1));
                        } else {
                            Err(Error::from(e).context("failed to connect to ssh port"))?;
                        }
                    } else if start.elapsed() > Duration::from_secs(30) {
                        Err(Error::from(e).context("failed to connect to ssh port"))?;
                    }
                }
            }
        };

        trace!(log, "ssh: connection established"; "addr" => addr, "elapsed" => ?start.elapsed());

        let mut sess = ssh2::Session::new().context("libssh2 not available")?;
        sess.set_tcp_stream(tcp);
        sess.handshake()
            .context("failed to perform ssh handshake")?;
        if let Some(key) = key {
            sess.userauth_pubkey_file(username, None, key, None)
                .context("failed to authenticate ssh session with key")?;
        } else {
            let mut ag = sess.agent()?;
            ag.connect().context("could not connect to ssh-agent")?;
            ag.list_identities()
                .context("could not list ssh-agent identities")?;
            let ok = ag.identities()?.into_iter().any(|id| {
                ag.userauth(username, &id)
                    .map_err(|e| {
                        warn!(log, "agent identity failed"; "username" => username,  "identity" => id.comment(), "err" => ?e);
                        e
                    })
                    .is_ok()
            });
            if !ok {
                bail!("failed to authenticate ssh session with ssh-agent");
            }
        }

        Ok(Session { addr, ssh: sess })
    }

    /// Issue the given command and return the command's raw stdout and stderr.
    pub fn cmd_raw(&self, cmd: &str) -> Result<(Vec<u8>, Vec<u8>), Error> {
        use std::io::Read;

        let mut channel = self
            .ssh
            .channel_session()
            .map_err(Error::from)
            .map_err(|e| {
                e.context(format!(
                    "failed to create ssh channel for command '{}'",
                    cmd
                ))
            })?;

        channel
            .exec(cmd)
            .map_err(Error::from)
            .map_err(|e| e.context(format!("failed to execute command '{}'", cmd)))?;

        channel
            .send_eof()
            .map_err(Error::from)
            .map_err(|e| e.context(format!("failed to finish command '{}'", cmd)))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        // NOTE: the loop is needed because libssh2 can return reads of size 0 without EOF
        // https://www.libssh2.org/libssh2_channel_read_ex.html
        // NOTE: we must read from *both* stdout and stderr. EOF is only sent when they're both
        // drained.
        while !channel.eof() {
            channel
                .read_to_end(&mut stdout)
                .map_err(Error::from)
                .map_err(|e| e.context(format!("failed to read stdout of command '{}'", cmd)))?;
            channel
                .stderr()
                .read_to_end(&mut stderr)
                .map_err(Error::from)
                .map_err(|e| e.context(format!("failed to read stderr of command '{}'", cmd)))?;
        }

        channel
            .wait_close()
            .map_err(Error::from)
            .map_err(|e| e.context(format!("command '{}' never completed", cmd)))?;

        match channel.exit_status() {
            Ok(x) if x == 0 => Ok((stdout, stderr)),
            Ok(e) => {
                let stdout_str =
                    String::from_utf8(stdout).unwrap_or_else(|_| String::from("malformed stdout"));
                let stderr_str =
                    String::from_utf8(stderr).unwrap_or_else(|_| String::from("malformed stderr"));

                Err(
                    format_err!("SSH command '{}' failed with exit code {}", cmd, e)
                        .context(format!(
                            "stdout:\n{}\n\nstderr:\n{}",
                            stdout_str, stderr_str
                        ))
                        .into(),
                )
            }
            Err(e) => Err(Error::from(e)),
        }
    }

    /// Copy a file from the local machine to the remote host.
    ///
    /// Both remote and local paths can be absolute or relative.
    ///
    /// ```rust,no_run
    /// # use sessh::Session;
    /// # use failure::Error;
    /// # fn upload_artifact(ssh: Session) -> Result<(), Error> {
    ///     use std::path::Path;
    ///     ssh.upload(
    ///         Path::new("build/output.tar.gz"), // on the local machine
    ///         Path::new("/srv/output.tar.gz"), // on the remote machine
    ///     )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn upload(&self, local_src: &Path, remote_dst: &Path) -> Result<(), Error> {
        let sftp = self.ssh.sftp().map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to create ssh channel while uploading file '{}'",
                local_src.display()
            ))
        })?;
        let mut dst_file = sftp.create(&remote_dst).map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to create file '{}' on remote host",
                remote_dst.display()
            ))
        })?;

        let mut src_file = File::open(&local_src).map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to open file '{}' on local machine",
                local_src.display()
            ))
        })?;

        let copied = io::copy(&mut src_file, &mut dst_file)
            .map_err(Error::from)
            .map_err(|e| {
                e.context(format!(
                    "failed to upload file '{}' to remote host",
                    local_src.display()
                ))
            })?;

        let expected = src_file.metadata()?.len();
        if copied < expected {
            Err(FileTransferFailure {
                file: local_src.display().to_string(),
                msg: format!("only copied {}/{} bytes", copied, expected),
            })?
        }

        Ok(())
    }

    /// Issue the given command and return the command's stdout and stderr.
    pub fn cmd(&self, cmd: &str) -> Result<(String, String), Error> {
        let (out, err) = self.cmd_raw(cmd)?;
        Ok((String::from_utf8(out)?, String::from_utf8(err)?))
    }

    /// Copy a file from the remote host to the local machine.
    ///
    /// Both remote and local paths can be absolute or relative.
    ///
    /// ```rust,no_run
    /// # use sessh::Session;
    /// # use failure::Error;
    /// # fn download_hostname(ssh: Session) -> Result<(), Error> {
    ///     use std::path::Path;
    ///     ssh.download(
    ///         Path::new("/etc/hostname"), // on the remote machine
    ///         Path::new("remote-hostname"), // on the local machine
    ///     )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn download(&self, remote_src: &Path, local_dst: &Path) -> Result<(), Error> {
        let sftp = self.ssh.sftp().map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to create ssh channel while downloading file '{}'",
                remote_src.display()
            ))
        })?;
        let mut src_file = sftp.open(&remote_src).map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to open file '{}' on remote host",
                remote_src.display()
            ))
        })?;

        let mut dst_file = File::create(&local_dst).map_err(Error::from).map_err(|e| {
            e.context(format!(
                "failed to create file '{}' on local machine",
                local_dst.display()
            ))
        })?;

        let copied = io::copy(&mut src_file, &mut dst_file)
            .map_err(Error::from)
            .map_err(|e| {
                e.context(format!(
                    "failed to download file '{}' from remote host",
                    remote_src.display()
                ))
            })?;

        // `stat().size` can be None. A little odd but not worth failing if
        // everything else seemed to succeed.
        if let Some(expected) = src_file.stat()?.size {
            if copied < expected {
                Err(FileTransferFailure {
                    file: remote_src.display().to_string(),
                    msg: format!("only copied {}/{} bytes", copied, expected),
                })?
            }
        }

        Ok(())
    }
}

use std::ops::{Deref, DerefMut};
impl Deref for Session {
    type Target = ssh2::Session;
    fn deref(&self) -> &Self::Target {
        &self.ssh
    }
}

impl DerefMut for Session {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ssh
    }
}

#[cfg(test)]
mod tests {
    use super::Session;
    use failure::Error;
    use slog::o;
    use std::fs::File;
    use std::io::Write;

    pub fn test_logger() -> slog::Logger {
        use slog::Drain;
        let plain = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(plain).build().fuse();
        slog::Logger::root(drain, o!())
    }

    fn get_curr_user() -> Result<String, Error> {
        let curr_user = std::process::Command::new("whoami").output()?.stdout;
        let curr_user = String::from_utf8(curr_user)?;
        Ok(curr_user.split_whitespace().next().unwrap().to_string())
    }

    #[test]
    #[ignore] // ignore by default since there is no ssh-agent in travis ci
    fn localhost() -> Result<(), Error> {
        let log = test_logger();

        let curr_user = get_curr_user()?;
        slog::trace!(log, "current user"; "user" => &curr_user);
        let s = Session::connect(&log, &curr_user, "127.0.0.1:22".parse()?, None, None)?;
        slog::trace!(log, "connected to localhost");
        let (ssh_user, _) = s.cmd("whoami")?;
        let ssh_user = ssh_user.split_whitespace().next().unwrap();
        assert_eq!(ssh_user, curr_user);
        Ok(())
    }

    /// Tests uploading a file via SSH-to-localhost (using a running SSH agent).
    #[test]
    #[ignore] // ignore by default since there is no ssh-agent in travis ci
    fn localhost_upload() -> Result<(), Error> {
        const CONTENTS: &'static str = "hello";

        let log = test_logger();

        let temp_dir = tempfile::TempDir::new()?;

        let local_file = temp_dir.path().join("source");
        {
            let file = File::create(&local_file)?;
            write!(&file, "{}", CONTENTS)?;
        }

        let curr_user = get_curr_user()?;
        let s = Session::connect(&log, &curr_user, "127.0.0.1:22".parse()?, None, None)?;
        slog::trace!(log, "current user"; "user" => &curr_user);

        // we're SSHing to localhost, so we can use the same temp dir!
        let remote_file = temp_dir.path().join("dest");
        s.upload(&local_file, &remote_file)?;
        let (ssh_contents, _) = s.cmd(&format!("cat {}", remote_file.to_string_lossy()))?;
        let ssh_contents = ssh_contents.split_whitespace().next().unwrap();
        assert_eq!(ssh_contents, CONTENTS);
        Ok(())
    }

    /// Tests downloading a file via SSH-to-localhost (using a running SSH agent).
    #[test]
    #[ignore] // ignore by default since there is no ssh-agent in travis ci
    fn localhost_download() -> Result<(), Error> {
        const CONTENTS: &'static str = "hello";

        let log = test_logger();

        let temp_dir = tempfile::TempDir::new()?;

        let remote_file = temp_dir.path().join("source");
        {
            let file = File::create(&remote_file)?;
            write!(&file, "{}", CONTENTS)?;
        }

        let curr_user = get_curr_user()?;
        let s = Session::connect(&log, &curr_user, "127.0.0.1:22".parse()?, None, None)?;
        slog::trace!(log, "current user"; "user" => &curr_user);

        // we're SSHing to localhost, so we can use the same temp dir!
        let local_file = temp_dir.path().join("dest");
        s.download(&remote_file, &local_file)?;
        let (ssh_contents, _) = s.cmd(&format!("cat {}", remote_file.to_string_lossy()))?;
        let ssh_contents = ssh_contents.split_whitespace().next().unwrap();
        assert_eq!(ssh_contents, CONTENTS);
        Ok(())
    }
}
