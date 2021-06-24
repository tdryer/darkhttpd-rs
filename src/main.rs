use std::cmp::{max, min};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{remove_file, File, OpenOptions};
use std::io::{BufRead, BufWriter, Read, Write};
use std::mem::MaybeUninit;
use std::net::{
    AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
    TcpListener, TcpStream,
};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Local, Utc};
use nix::errno::Errno;
use nix::sys::select::{select, FdSet};
use nix::sys::sendfile::sendfile64;
use nix::sys::signal::{signal, SigHandler, Signal};
use nix::sys::socket;
use nix::sys::time::TimeVal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{
    chdir, chroot, close, dup2, fork, getpid, getuid, pipe, read, setgid, setgroups, setsid,
    setuid, ForkResult, Gid, Group, Pid, Uid, User,
};

#[cfg(test)]
mod test;

const COPYRIGHT: &str = "copyright (c) 2021 Tom Dryer";
const DEFAULT_INDEX_NAME: &str = "index.html";
const DEFAULT_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_MIMETYPES: &str = include_str!("default_mimetypes.txt");
const DEFAULT_MIME_TYPE: &str = "application/octet-stream";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const PATH_DEVNULL: &str = "/dev/null";
const SENDFILE_SIZE_LIMIT: u64 = 1 << 20;
const MAX_REQUEST_LENGTH: usize = 4000;

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn stop_running(_signal: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}

fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

fn main() -> Result<()> {
    println!(
        "{}/{}, {}.",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        COPYRIGHT,
    );

    let mut server = Server::from_command_line()?;

    if !server.want_no_server_id {
        server.server_hdr = format!(
            "Server: {}/{}\r\n",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
    }

    let listener = server.create_listener()?;

    let daemonize = server
        .want_daemon
        .then(|| Daemonize::start().context("failed to daemonize"))
        .transpose()?;

    // set signal handlers
    unsafe { signal(Signal::SIGPIPE, SigHandler::SigIgn) }
        .context("failed to set SIGPIPE handler")?;
    unsafe { signal(Signal::SIGINT, SigHandler::Handler(stop_running)) }
        .context("failed to set SIGINT handler")?;
    unsafe { signal(Signal::SIGTERM, SigHandler::Handler(stop_running)) }
        .context("failed to set SIGTERM handler")?;

    if server.want_chroot {
        // Force reading the local timezone before chroot makes this impossible.
        Local::now();

        chdir(server.wwwroot.as_os_str()).with_context(|| {
            format!(
                "failed to change working directory to {}",
                server.wwwroot.to_string_lossy()
            )
        })?;
        chroot(server.wwwroot.as_os_str()).with_context(|| {
            format!(
                "failed to change root directory to {}",
                server.wwwroot.to_string_lossy()
            )
        })?;
        println!("chrooted to `{}'", server.wwwroot.to_string_lossy());

        server.wwwroot.clear();
    }

    if let Some(gid) = server.drop_gid {
        setgroups(&[gid])
            .with_context(|| format!("failed to set supplementary group IDs to [{}]", gid))?;
        setgid(gid).with_context(|| format!("failed to set group ID to {}", gid))?;
        println!("set gid to {}", gid);
    }

    if let Some(uid) = server.drop_uid {
        setuid(uid).with_context(|| format!("failed to set user ID to {}", uid))?;
        println!("set uid to {}", uid);
    }

    let pidfile = server
        .pidfile_name
        .take()
        .map(PidFile::create)
        .transpose()?;

    daemonize
        .map(|daemonize| daemonize.finish().context("failed to daemonize"))
        .transpose()?;

    let mut files_exhausted = false;
    let mut connections = Vec::new();
    let mut stats = ServerStats::default();

    // main loop
    while is_running() {
        httpd_poll(
            &mut server,
            &listener,
            &mut files_exhausted,
            &mut stats,
            &mut connections,
        );
    }

    pidfile.map(|pidfile| pidfile.remove()).transpose()?;

    // free connections
    let now = SystemTime::now();
    for conn in connections.drain(..) {
        log_connection(&mut server, &conn, now);
    }

    // Original darkhttpd only prints usage stats if logfile is specified, because otherwise stdout
    // will be closed. It's not clear whether this was intentional.
    if !matches!(server.log_sink, LogSink::Stdout) {
        stats.print()?;
    }
    Ok(())
}

/// Where to put the access log.
#[derive(Debug)]
enum LogSink {
    Stdout,
    Syslog,
    File(BufWriter<File>),
}
impl LogSink {
    fn log(&mut self, message: &str) -> std::io::Result<()> {
        match self {
            Self::Stdout => {
                print!("{}", message);
            }
            Self::Syslog => {
                let message = CString::new(message).expect("log message contains null byte");
                unsafe { libc::syslog(libc::LOG_INFO, message.as_c_str().as_ptr()) };
            }
            Self::File(file) => {
                write!(file, "{}", message)?;
                file.flush()?;
            }
        }
        Ok(())
    }
}
impl Default for LogSink {
    fn default() -> Self {
        Self::Stdout
    }
}

fn expect_string_after(args: &mut std::env::ArgsOs, arg_name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("missing argument after {}", arg_name))?
        .into_string()
        .map_err(|_| anyhow!("UTF-8 required after {}", arg_name))
}

#[derive(Debug, Default)]
struct Server {
    forward_map: ForwardMap,
    forward_all_url: Option<String>,
    timeout: Option<Duration>,
    keep_alive_header: String,
    bindaddr: Option<String>,
    bindport: u16,
    max_connections: Option<usize>,
    index_name: OsString,
    no_listing: bool,
    inet6: bool,
    wwwroot: OsString,
    log_sink: LogSink,
    pidfile_name: Option<OsString>,
    want_chroot: bool,
    want_daemon: bool,
    want_no_keepalive: bool,
    want_no_server_id: bool,
    server_hdr: String,
    auth_key: Option<String>,
    mime_map: MimeMap,
    drop_uid: Option<Uid>,
    drop_gid: Option<Gid>,
}
impl Server {
    fn from_command_line() -> Result<Self> {
        let mut server = Self {
            timeout: Some(DEFAULT_TIMEOUT),
            bindport: if getuid().is_root() { 80 } else { 8080 },
            index_name: OsString::from(DEFAULT_INDEX_NAME),
            ..Default::default()
        };
        let mut args = std::env::args_os();
        let name = args.next().expect("expected at least one argument");
        match args.next().as_deref() {
            Some(wwwroot) if wwwroot != "--help" => {
                let mut wwwroot = wwwroot.as_bytes();
                // Strip ending slash.
                if wwwroot.ends_with(b"/") {
                    wwwroot = &wwwroot[0..wwwroot.len() - 1];
                }
                server.wwwroot = OsStr::from_bytes(wwwroot).to_os_string();
            }
            _ => {
                // no wwwroot or help flag given
                server.usage(&name.to_string_lossy());
                std::process::exit(0);
            }
        };
        while let Some(arg) = args.next().as_deref() {
            let arg = arg
                .to_str()
                .ok_or_else(|| anyhow!("argument is not UTF-8"))?;
            match arg {
                "--port" => {
                    let number = expect_string_after(&mut args, "--port")?;
                    server.bindport = number
                        .parse()
                        .with_context(|| format!("port number {} is invalid", number))?;
                }
                "--addr" => {
                    server.bindaddr = Some(expect_string_after(&mut args, "--addr")?);
                }
                "--maxconn" => {
                    let number = expect_string_after(&mut args, "--maxconn")?;
                    server.max_connections = Some(
                        number
                            .parse()
                            .with_context(|| format!("maxconn number {} is invalid", number))?,
                    );
                }
                "--log" => {
                    let filename = args.next().context("missing filename after --log")?;
                    server.log_sink = LogSink::File(BufWriter::new(
                        OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(&filename)
                            .with_context(|| {
                                format!("failed to open log file {}", filename.to_string_lossy())
                            })?,
                    ))
                }
                "--chroot" => server.want_chroot = true,
                "--daemon" => server.want_daemon = true,
                "--index" => {
                    server.index_name = args.next().context("missing filename after --index")?;
                }
                "--no-listing" => server.no_listing = true,
                "--mimetypes" => {
                    let filename = args.next().context("missing filename after --mimetypes")?;
                    server.mime_map.parse_extension_map_file(&filename)?;
                }
                "--default-mimetype" => {
                    server.mime_map.default_mimetype =
                        expect_string_after(&mut args, "--default-mimetype")?;
                }
                "--uid" => {
                    let uid = expect_string_after(&mut args, "--uid")?;
                    let user1 = User::from_name(&uid).context("getpwnam failed")?;
                    let user2 = uid
                        .parse()
                        .ok()
                        .and_then(|uid| User::from_uid(Uid::from_raw(uid)).transpose())
                        .transpose()
                        .context("getpwuid failed")?;
                    let user = user1
                        .or(user2)
                        .with_context(|| format!("no such uid: `{}'", uid))?;
                    server.drop_uid = Some(user.uid)
                }
                "--gid" => {
                    let gid = expect_string_after(&mut args, "--gid")?;
                    let group1 = Group::from_name(&gid).context("getgrnam failed")?;
                    let group2 = gid
                        .parse()
                        .ok()
                        .and_then(|gid| Group::from_gid(Gid::from_raw(gid)).transpose())
                        .transpose()
                        .context("getgrgid failed")?;
                    let group = group1
                        .or(group2)
                        .with_context(|| format!("no such gid: `{}'", gid))?;
                    server.drop_gid = Some(group.gid)
                }
                "--pidfile" => {
                    server.pidfile_name =
                        Some(args.next().context("missing filename after --pidfile")?);
                }
                "--no-keepalive" => server.want_no_keepalive = true,
                "--syslog" => server.log_sink = LogSink::Syslog,
                "--forward" => {
                    let host = expect_string_after(&mut args, "--forward")?;
                    let url = expect_string_after(&mut args, "--forward")?;
                    server.forward_map.insert(host, url);
                }
                "--forward-all" => {
                    server.forward_all_url = Some(expect_string_after(&mut args, "--forward-all")?)
                }
                "--no-server-id" => server.want_no_server_id = true,
                "--timeout" => {
                    let number = expect_string_after(&mut args, "--timeout")?;
                    let timeout_secs = number
                        .parse::<u64>()
                        .with_context(|| format!("timeout number {} is invalid", number))?;
                    server.timeout = match timeout_secs {
                        0 => None,
                        timeout_secs => Some(Duration::from_secs(timeout_secs)),
                    };
                }
                "--auth" => {
                    let user_pass = expect_string_after(&mut args, "--auth")?;
                    if !user_pass.contains(':') {
                        return Err(anyhow!("expected user:pass after --auth"));
                    }
                    server.auth_key =
                        Some(format!("Basic {}", Base64Encoded(user_pass.as_bytes())));
                }
                "--ipv6" => server.inet6 = true,
                _ => {
                    return Err(anyhow!("unknown argument `{}'", arg));
                }
            }
        }
        server.keep_alive_header = format!(
            "Keep-Alive: timeout={}\r\n",
            server
                .timeout
                .unwrap_or(DEFAULT_KEEP_ALIVE_TIMEOUT)
                .as_secs()
        );
        Ok(server)
    }
    fn usage(&self, argv0: &str) {
        print!(
            "usage:\t{} /path/to/wwwroot [flags]\n\n\
            flags:\t--port number (default: {}, or 80 if running as root)\n\
            \t\tSpecifies which port to listen on for connections.\n\
            \t\tPass 0 to let the system choose any free port for you.\n\n\
            \t--addr ip (default: all)\n\
            \t\tIf multiple interfaces are present, specifies\n\
            \t\twhich one to bind the listening port to.\n\n\
            \t--maxconn number (default: system maximum)\n\
            \t\tSpecifies how many concurrent connections to accept.\n\n\
            \t--log filename (default: stdout)\n\
            \t\tSpecifies which file to append the request log to.\n\n\
            \t--syslog\n\
            \t\tUse syslog for request log.\n\n\
            \t--chroot (default: don't chroot)\n\
            \t\tLocks server into wwwroot directory for added security.\n\n\
            \t--daemon (default: don't daemonize)\n\
            \t\tDetach from the controlling terminal and run in the background.\n\n\
            \t--index filename (default: {})\n\
            \t\tDefault file to serve when a directory is requested.\n\n\
            \t--no-listing\n\
            \t\tDo not serve listing if directory is requested.\n\n\
            \t--mimetypes filename (optional)\n\
            \t\tParses specified file for extension-MIME associations.\n\n\
            \t--default-mimetype string (optional, default: {})\n\
            \t\tFiles with unknown extensions are served as this mimetype.\n\n\
            \t--uid uid/uname, --gid gid/gname (default: don't privdrop)\n\
            \t\tDrops privileges to given uid:gid after initialization.\n\n\
            \t--pidfile filename (default: no pidfile)\n\
            \t\tWrite PID to the specified file.  Note that if you are\n\
            \t\tusing --chroot, then the pidfile must be relative to,\n\
            \t\tand inside the wwwroot.\n\n\
            \t--no-keepalive\n\
            \t\tDisables HTTP Keep-Alive functionality.\n\n\
            \t--forward host url (default: don't forward)\n\
            \t\tWeb forward (301 redirect).\n\
            \t\tRequests to the host are redirected to the corresponding url.\n\
            \t\tThe option may be specified multiple times, in which case\n\
            \t\tthe host is matched in order of appearance.\n\n\
            \t--forward-all url (default: don't forward)\n\
            \t\tWeb forward (301 redirect).\n\
            \t\tAll requests are redirected to the corresponding url.\n\n\
            \t--no-server-id\n\
            \t\tDon't identify the server type in headers\n\
            \t\tor directory listings.\n\n\
            \t--timeout secs (default: {})\n\
            \t\tIf a connection is idle for more than this many seconds,\n\
            \t\tit will be closed. Set to zero to disable timeouts.\n\n\
            \t--auth username:password\n\
            \t\tEnable basic authentication.\n\n\
            \t--ipv6\n\
            \t\tListen on IPv6 address.\n\n",
            argv0,
            self.bindport,
            DEFAULT_INDEX_NAME,
            DEFAULT_MIME_TYPE,
            self.timeout.map(|timeout| timeout.as_secs()).unwrap_or(0)
        );
    }
    fn keep_alive_header(&self, conn_close: bool) -> &str {
        match conn_close {
            true => "Connection: close\r\n",
            false => &self.keep_alive_header,
        }
    }
    fn socket_addr(&self) -> Result<SocketAddr, AddrParseError> {
        Ok(if self.inet6 {
            let addr = Ipv6Addr::from_str(self.bindaddr.as_deref().unwrap_or("::"))?;
            SocketAddr::V6(SocketAddrV6::new(addr, self.bindport, 0, 0))
        } else {
            let addr = Ipv4Addr::from_str(self.bindaddr.as_deref().unwrap_or("0.0.0.0"))?;
            SocketAddr::V4(SocketAddrV4::new(addr, self.bindport))
        })
    }
    /// Initialize the TcpListener. This is the socket that we accept connections from.
    fn create_listener(&self) -> Result<TcpListener> {
        let socket_addr = self.socket_addr().context("malformed --addr argument")?;
        // Sets `SO_REUSEADDR` implicitly.
        let listener = TcpListener::bind(socket_addr)
            .with_context(|| format!("failed to create listening socket for {}", socket_addr))?;
        println!("listening on: http://{}/", socket_addr);
        Ok(listener)
    }
}

#[derive(Debug, Default)]
struct ServerStats {
    num_requests: u64,
    total_in: u64,
    total_out: u64,
}
impl ServerStats {
    fn print(&self) -> Result<()> {
        let rusage = getrusage().context("failed to get resource usage")?;
        println!(
            "CPU time used: {}.{:02} user, {}.{:02} system",
            rusage.ru_utime.tv_sec,
            rusage.ru_utime.tv_usec / 10000,
            rusage.ru_stime.tv_sec,
            rusage.ru_stime.tv_usec / 10000,
        );
        println!("Requests: {}", self.num_requests);
        println!("Bytes: {} in, {} out", self.total_in, self.total_out);
        Ok(())
    }
}

/// Safe wrapper for `libc::getrusage`.
fn getrusage() -> std::io::Result<libc::rusage> {
    let mut rusage = MaybeUninit::<libc::rusage>::zeroed();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, rusage.as_mut_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { rusage.assume_init() })
}

const PIDFILE_MODE: u32 = 0o600;

#[derive(Debug)]
struct PidFile {
    name: OsString,
    file: File,
}
impl PidFile {
    fn create(pidfile_name: OsString) -> Result<Self> {
        // Create the pidfile, failing if it already exists.
        // Unlike the original darkhttpd, we use O_EXCL instead of O_EXLOCK.
        let mut pidfile_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PIDFILE_MODE)
            .open(&pidfile_name)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    match Self::read(&pidfile_name) {
                        Ok(pid) => anyhow!("daemon already running with pid {}", pid),
                        Err(e) => e,
                    }
                } else {
                    anyhow::Error::new(e).context(format!(
                        "failed to create pidfile {}",
                        pidfile_name.to_string_lossy()
                    ))
                }
            })?;

        // Write pid to the pidfile.
        if let Err(e) = write!(pidfile_file, "{}", getpid()) {
            Self::remove_raw(&pidfile_name, pidfile_file).ok();
            return Err(e).with_context(|| {
                format!(
                    "failed to write to pidfile {}",
                    pidfile_name.to_string_lossy()
                )
            });
        };

        Ok(Self {
            name: pidfile_name,
            file: pidfile_file,
        })
    }
    fn read(pidfile_name: &OsStr) -> Result<Pid> {
        let mut pidfile = File::open(pidfile_name).with_context(|| {
            format!("failed to open pidfile {}", pidfile_name.to_string_lossy())
        })?;
        let mut buf = String::new();
        pidfile.read_to_string(&mut buf).with_context(|| {
            format!("failed to read pidfile {}", pidfile_name.to_string_lossy())
        })?;
        Ok(Pid::from_raw(
            buf.parse().context("invalid pidfile contents")?,
        ))
    }
    fn remove(self) -> Result<()> {
        Self::remove_raw(&self.name, self.file)
    }
    fn remove_raw(pidfile_name: &OsStr, pidfile_file: File) -> Result<()> {
        remove_file(pidfile_name).with_context(|| {
            format!(
                "failed to remove pidfile {}",
                pidfile_name.to_string_lossy()
            )
        })?;
        drop(pidfile_file);
        Ok(())
    }
}

struct Daemonize {
    lifeline_read: RawFd,
    lifeline_write: RawFd,
    fd_null: RawFd,
}
impl Daemonize {
    fn start() -> Result<Self> {
        // create lifeline pipe
        let (lifeline_read, lifeline_write) = pipe().context("failed to create pipe")?;

        // populate fd_null
        let fd_null = OpenOptions::new()
            .read(true)
            .write(true)
            .open(PATH_DEVNULL)
            .with_context(|| format!("failed to open {}", PATH_DEVNULL))?
            .into_raw_fd();

        if let ForkResult::Parent { child } = unsafe { fork() }.context("failed to fork process")? {
            // wait for the child
            if let Err(e) = close(lifeline_write) {
                eprintln!("warning: failed to close lifeline in parent: {}", e);
            }
            let mut buf = [0; 1];
            if let Err(e) = read(lifeline_read, &mut buf) {
                eprintln!("warning: failed read lifeline in parent: {}", e);
            }
            // exit with status depending on child status
            match waitpid(child, Some(WaitPidFlag::WNOHANG))
                .with_context(|| format!("failed to wait for process {}", child))?
            {
                WaitStatus::StillAlive => std::process::exit(0),
                WaitStatus::Exited(_, status) => std::process::exit(status),
                _ => return Err(anyhow!("waitpid returned unknown status")),
            }
        }
        Ok(Self {
            lifeline_read,
            lifeline_write,
            fd_null,
        })
    }
    fn finish(self) -> Result<()> {
        setsid().context("failed to create session")?;
        if let Err(e) = close(self.lifeline_read) {
            eprintln!(
                "warning: failed to close read end of lifeline in child: {}",
                e
            );
        }
        if let Err(e) = close(self.lifeline_write) {
            eprintln!("warning: failed to cut the lifeline: {}", e);
        }

        // close all our std fds
        if let Err(e) = dup2(self.fd_null, libc::STDIN_FILENO) {
            eprintln!("warning: failed to close stdin: {}", e);
        }
        if let Err(e) = dup2(self.fd_null, libc::STDOUT_FILENO) {
            eprintln!("warning: failed to close stdout: {}", e);
        }
        if let Err(e) = dup2(self.fd_null, libc::STDERR_FILENO) {
            eprintln!("warning: failed to close stderr: {}", e);
        }
        if self.fd_null > 2 {
            close(self.fd_null).ok();
        }
        Ok(())
    }
}

const BASE64_TABLE: &[char] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

/// Encode data as base64.
struct Base64Encoded<'a>(&'a [u8]);

impl<'a> std::fmt::Display for Base64Encoded<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for chunk in self.0.chunks(3) {
            let mut triple: u32 = 0;
            for i in 0..3 {
                triple <<= 8;
                triple += *chunk.get(i).unwrap_or(&0) as u32;
            }
            for i in (0..4).rev().take(chunk.len() + 1) {
                write!(f, "{}", BASE64_TABLE[(triple as usize >> (i * 6)) & 0x3F])?;
            }
            for _ in 0..(3 - chunk.len()) {
                write!(f, "=")?;
            }
        }
        Ok(())
    }
}

/// A request target. See RFC7230 section 5.3.
struct RequestTarget {
    path: String,
    query: String,
}
impl RequestTarget {
    fn parse(buffer: &str) -> Option<RequestTarget> {
        let mut target = buffer.splitn(2, '?');
        let path = target.next()?.to_string();
        if !path.starts_with('/') {
            return None;
        }
        let query = target.next().unwrap_or("").to_string();
        Some(RequestTarget { path, query })
    }
}
impl std::fmt::Display for RequestTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path)?;
        if !self.query.is_empty() {
            write!(f, "?{}", self.query)?;
        }
        Ok(())
    }
}

/// An HTTP request.
struct Request {
    method: String,
    target: RequestTarget,
    protocol: Option<String>,
    headers: HashMap<String, String>,
}
impl Request {
    /// Parse an HTTP request.
    fn parse(buffer: &[u8]) -> Option<Request> {
        let request = std::str::from_utf8(buffer).ok()?;
        let mut lines = request.lines();
        let mut request_line = lines.next()?.split(' ');
        let method = request_line.next()?.to_uppercase();
        let target = RequestTarget::parse(request_line.next()?)?;
        let protocol = request_line.next().map(|s| s.to_uppercase());
        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let mut header_line = line.splitn(2, ": ");
            let name = header_line.next();
            let value = header_line.next();
            if let (Some(name), Some(value)) = (name, value) {
                headers.insert(name.to_lowercase(), value.to_string());
            }
        }
        Some(Request {
            method,
            target,
            protocol,
            headers,
        })
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|s| s.as_str())
    }
    fn range(&self) -> (Option<u64>, Option<u64>) {
        // get range header value and strip prefix
        let prefix = "bytes=";
        let range = match self.header("range") {
            Some(range) if range.starts_with("bytes=") => &range[prefix.len()..],
            _ => return (None, None),
        };

        // parse number up to hyphen
        let (range_begin, remaining) = parse_offset(range.as_bytes());

        // there must be a hyphen here
        if remaining.is_empty() || remaining[0] != b'-' {
            return (None, None);
        }
        let remaining = &remaining[1..];

        // parse number after hyphen
        let (range_end, remaining) = parse_offset(remaining);

        // must be end of string or a list to be valid
        if !remaining.is_empty() && remaining[0] != b',' {
            return (None, None);
        }

        (range_begin, range_end)
    }
    fn connection_close(&self) -> bool {
        let mut conn_close = true;
        if let Some("HTTP/1.1") = self.protocol.as_deref() {
            conn_close = false;
        }
        let connection = self.headers.get("connection").map(|s| s.to_lowercase());
        match connection.as_deref() {
            Some("close") => conn_close = true,
            Some("keep-alive") => conn_close = false,
            _ => {}
        }
        conn_close
    }
}

struct Response {
    http_code: u16,
    headers: String,
    body: Option<Body>,
}

struct Connection {
    socket: TcpStream,
    client: IpAddr,
    last_active: SystemTime,
    state: ConnectionState,
    request: Option<Request>,
    response: Option<Response>,
    header_sent: usize,
    conn_close: bool,
    total_sent: u64,
}
impl Connection {
    /// Allocate and initialize an empty connection.
    fn new(now: SystemTime, stream: TcpStream, client: IpAddr) -> Self {
        Self {
            socket: stream,
            client,
            last_active: now,
            state: ConnectionState::receive_request(),
            request: None,
            response: None,
            header_sent: 0,
            conn_close: true,
            total_sent: 0,
        }
    }

    /// Recycle a finished connection for HTTP/1.1 Keep-Alive.
    fn recycle(&mut self) {
        // don't reset conn.client
        self.request = None;
        self.response = None;
        self.header_sent = 0;
        self.conn_close = true;
        self.total_sent = 0;
        self.state = ConnectionState::receive_request(); // ready for another
    }
}

#[derive(Debug, PartialEq)]
enum ConnectionState {
    ReceiveRequest {
        buffer: Box<[u8; MAX_REQUEST_LENGTH]>,
        length: usize,
    },
    SendHeader,
    SendReply,
    Done,
}
impl ConnectionState {
    fn receive_request() -> Self {
        Self::ReceiveRequest {
            buffer: Box::new([0; MAX_REQUEST_LENGTH]),
            length: 0,
        }
    }
}

enum Body {
    Generated {
        data: String,
        start_index: usize,
        end_index: usize,
    },
    FromFile {
        file: File,
        offset: i64,
        length: u64,
    },
}
impl Body {
    fn generated(data: String) -> Self {
        let data_length = data.as_bytes().len();
        Self::Generated {
            data,
            start_index: 0,
            end_index: data_length,
        }
    }
    fn poll_send(&mut self, stream: &TcpStream) -> nix::Result<usize> {
        match self {
            Self::Generated {
                data,
                start_index,
                end_index,
            } => {
                let sent = socket::send(
                    stream.as_raw_fd(),
                    &data.as_bytes()[*start_index..*end_index],
                    socket::MsgFlags::empty(),
                )?;
                *start_index += sent;
                Ok(sent)
            }
            Self::FromFile {
                file,
                offset,
                length,
            } => {
                let count = usize::try_from(min(*length, SENDFILE_SIZE_LIMIT))
                    .expect("SENDFILE_SIZE_LIMIT does not fit in usize");
                let sent = sendfile64(stream.as_raw_fd(), file.as_raw_fd(), Some(offset), count)?;
                *length -= u64::try_from(sent).expect("sent more data than possible");
                Ok(sent)
            }
        }
    }
    fn done_sending(&self) -> bool {
        match self {
            Self::Generated {
                data: _,
                start_index,
                end_index,
            } => start_index == end_index,
            Self::FromFile {
                file: _,
                offset: _,
                length,
            } => *length == 0,
        }
    }
}

type ForwardMap = HashMap<String, String>;

#[derive(Debug)]
struct MimeMap {
    mimetypes: HashMap<OsString, String>,
    default_mimetype: String,
}

impl MimeMap {
    /// Add extension map from a file.
    fn parse_extension_map_file(&mut self, filename: &OsStr) -> Result<()> {
        let file = File::open(filename)
            .with_context(|| format!("failed to open {}", filename.to_string_lossy()))?;
        for line in std::io::BufReader::new(file).lines() {
            let line =
                line.with_context(|| format!("failed to read {}", filename.to_string_lossy()))?;
            self.add_mimetype_line(&line);
        }
        Ok(())
    }

    /// Add line from an extension map.
    fn add_mimetype_line(&mut self, line: &str) {
        let mut fields = line
            .split(|c| matches!(c, ' ' | '\t'))
            .filter(|field| !field.is_empty());
        let mimetype = match fields.next() {
            Some(mimetype) => mimetype,
            None => return, // empty line
        };
        if mimetype.starts_with('#') {
            return; // comment
        }
        for extension in fields {
            self.mimetypes.insert(extension.into(), mimetype.into());
        }
    }

    /// Get content type for a URL.
    fn content_type(&self, path: &Path) -> &str {
        path.extension()
            .and_then(|extension| self.mimetypes.get(extension))
            .unwrap_or(&self.default_mimetype)
    }
}

impl Default for MimeMap {
    /// Create MimeMap using the default extension map.
    fn default() -> Self {
        let mut mime_map = Self {
            mimetypes: HashMap::new(),
            default_mimetype: DEFAULT_MIME_TYPE.to_string(),
        };
        for line in DEFAULT_MIMETYPES.lines() {
            mime_map.add_mimetype_line(line);
        }
        mime_map
    }
}

/// RFC1123 formatted date.
struct HttpDate(SystemTime);

impl std::fmt::Display for HttpDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let datetime = DateTime::<Utc>::from(self.0);
        write!(f, "{}", datetime.format("%a, %d %b %Y %H:%M:%S GMT"))
    }
}

/// Common Log Format (CLF) formatted date in local timezone.
struct ClfDate(SystemTime);

impl std::fmt::Display for ClfDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let datetime = DateTime::<Local>::from(self.0);
        write!(f, "{}", datetime.format("[%d/%b/%Y:%H:%M:%S %z]"))
    }
}

/// "Generated by" string.
struct GeneratedOn<'a>(&'a Server, SystemTime);

impl<'a> std::fmt::Display for GeneratedOn<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let date = HttpDate(self.1);
        if !self.0.want_no_server_id {
            writeln!(
                f,
                "Generated by {}/{} on {}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                date
            )?;
        }
        Ok(())
    }
}

/// Resolve //, /./, and /../ in a URL.
///
/// Returns Error if the URL is invalid/unsafe.
fn make_safe_url(url: &mut Vec<u8>) -> Result<()> {
    assert!(url.starts_with(b"/"));
    let mut src_index = 0;
    let mut dst_index = 0;
    while src_index < url.len() {
        if url[src_index] == b'/' && url.get(src_index + 1) == Some(&b'/') {
            // skip slash
            src_index += 1;
        } else if url[src_index] == b'/'
            && url.get(src_index + 1) == Some(&b'.')
            && matches!(url.get(src_index + 2), Some(&b'/') | None)
        {
            // skip slash dot slash
            src_index += 2;
        } else if url[src_index] == b'/'
            && url.get(src_index + 1) == Some(&b'.')
            && url.get(src_index + 2) == Some(&b'.')
            && matches!(url.get(src_index + 3), Some(&b'/') | None)
        {
            // skip slash dot dot slash
            src_index += 3;
            // overwrite previous component
            loop {
                if dst_index == 0 {
                    bail!("url ascends above root");
                }
                dst_index -= 1;
                if url[dst_index] == b'/' {
                    break;
                }
            }
        } else {
            url[dst_index] = url[src_index];
            src_index += 1;
            dst_index += 1;
        }
    }

    // Always preserve leading slash
    dst_index = max(dst_index, 1);
    url.truncate(dst_index);

    Ok(())
}

/// Encode data to be an RFC3986-compliant URL part.
struct UrlEncoded<T: AsRef<[u8]>>(T);

impl<T: AsRef<[u8]>> std::fmt::Display for UrlEncoded<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0.as_ref() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                write!(f, "{}", *byte as char)?;
            } else {
                write!(f, "%{:02X}", byte)?;
            }
        }
        Ok(())
    }
}

/// Decode URL by converting %XX (where XX are hexadecimal digits) to the character it represents.
fn url_decode<T: AsRef<[u8]>>(url: T) -> Vec<u8> {
    let url = url.as_ref();
    let mut decoded = Vec::with_capacity(url.len());
    let mut i = 0;
    while i < url.len() {
        let c = url[i];
        assert!(c != 0); // TODO: Handle embedded null byte?
        if c == b'%'
            && i + 2 < url.len()
            && url[i + 1].is_ascii_hexdigit()
            && url[i + 2].is_ascii_hexdigit()
        {
            decoded.push(hex_to_digit(url[i + 1]) * 16 + hex_to_digit(url[i + 2]));
            i += 3;
        } else {
            decoded.push(c);
            i += 1;
        }
    }
    decoded
}

/// Convert hex digit to integer.
fn hex_to_digit(hex: u8) -> u8 {
    if (b'A'..=b'F').contains(&hex) {
        hex - b'A' + 10
    } else if (b'a'..=b'f').contains(&hex) {
        hex - b'a' + 10
    } else {
        hex - b'0'
    }
}

/// Escape < > & ' " into HTML entities.
struct HtmlEscaped<'a>(&'a str);

impl<'a> std::fmt::Display for HtmlEscaped<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for c in self.0.chars() {
            match c {
                '<' => write!(f, "&lt;")?,
                '>' => write!(f, "&gt;")?,
                '&' => write!(f, "&amp;")?,
                '\'' => write!(f, "&apos;")?,
                '"' => write!(f, "&quot;")?,
                c => write!(f, "{}", c)?,
            }
        }
        Ok(())
    }
}

fn parse_offset(data: &[u8]) -> (Option<u64>, &[u8]) {
    let mut digits_len = 0;
    while digits_len < data.len() && data[digits_len].is_ascii_digit() {
        digits_len += 1;
    }
    // Must be valid UTF-8 because range only contains ASCII digits.
    let offset = std::str::from_utf8(&data[0..digits_len])
        .expect("offset digits are not valid UTF-8")
        .parse()
        .ok();
    (offset, &data[digits_len..])
}

/// A default reply for any (erroneous) occasion.
fn default_reply(
    server: &Server,
    conn: &mut Connection,
    now: SystemTime,
    errcode: u16,
    errname: &str,
    reason: &str,
) -> Response {
    let reply = format!(
        "<html><head><title>{} {}</title></head><body>\n\
        <h1>{}</h1>\n\
        {}\n\
        <hr>\n\
        {}\
        </body></html>\n",
        errcode,
        errname,
        errname,
        reason,
        GeneratedOn(server, now),
    );
    let headers = format!(
        "HTTP/1.1 {} {}\r\n\
        Date: {}\r\n\
        {}\
        Accept-Ranges: bytes\r\n\
        {}\
        Content-Length: {}\r\n\
        Content-Type: text/html; charset=UTF-8\r\n\
        {}\
        \r\n",
        errcode,
        errname,
        HttpDate(now),
        server.server_hdr,
        server.keep_alive_header(conn.conn_close),
        reply.as_bytes().len(),
        if server.auth_key.is_some() {
            "WWW-Authenticate: Basic realm=\"User Visible Realm\"\r\n"
        } else {
            ""
        }
    );
    Response {
        http_code: errcode,
        headers,
        body: Some(Body::generated(reply)),
    }
}

/// A redirect reply.
fn redirect(server: &Server, conn: &mut Connection, now: SystemTime, location: &str) -> Response {
    let reply = format!(
        "<html><head><title>301 Moved Permanently</title></head><body>\n\
        <h1>Moved Permanently</h1>\n\
        Moved to: <a href=\"{}\">{}</a>\n\
        <hr>\n\
        {}\
        </body></html>\n",
        location,
        location,
        GeneratedOn(server, now),
    );
    let headers = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
        Date: {}\r\n\
        {}\
        Location: {}\r\n\
        {}\
        Content-Length: {}\r\n\
        Content-Type: text/html; charset=UTF-8\r\n\
        \r\n",
        HttpDate(now),
        server.server_hdr,
        location,
        server.keep_alive_header(conn.conn_close),
        reply.as_bytes().len(),
    );
    Response {
        http_code: 301,
        headers,
        body: Some(Body::generated(reply)),
    }
}

/// Directory listing.
struct Listing(Vec<std::fs::DirEntry>);

impl std::fmt::Display for Listing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let max_len = self
            .0
            .iter()
            .map(|dir_entry| dir_entry.file_name().len())
            .max()
            .unwrap_or(2);

        writeln!(f, "<a href=\"..\">..</a>/")?;

        for dir_entry in &self.0 {
            let metadata = match dir_entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            let name = dir_entry.file_name();
            write!(
                f,
                "<a href=\"{}\">{}</a>",
                UrlEncoded(name.as_bytes()),
                name.to_string_lossy()
            )?;
            if metadata.is_dir() {
                writeln!(f, "/")?;
            } else {
                let num_spaces = max_len - name.len();
                for _ in 0..num_spaces {
                    write!(f, " ")?;
                }
                writeln!(f, "{:10}", metadata.len())?;
            }
        }
        Ok(())
    }
}

/// A directory listing reply.
fn generate_dir_listing(
    server: &Server,
    conn: &mut Connection,
    now: SystemTime,
    path: &Path,
    decoded_url: &[u8],
) -> Response {
    let mut entries: Vec<_> = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) => {
            let reason = format!("Couldn't list directory: {}", e);
            return default_reply(server, conn, now, 500, "Internal Server Error", &reason);
        }
    }
    .filter_map(|entry| entry.ok())
    .collect();
    entries
        .as_mut_slice()
        .sort_by_key(|dir_entry| dir_entry.file_name());

    let decoded_url = String::from_utf8_lossy(decoded_url);
    let reply = format!(
        "<html>\n<head>\n<title>{}</title>\n\
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
        </head>\n<body>\n<h1>{}</h1>\n<tt><pre>\n\
        {}\
        </pre></tt>\n\
        <hr>\n\
        {}\
        </body>\n</html>\n",
        HtmlEscaped(&decoded_url),
        HtmlEscaped(&decoded_url),
        Listing(entries),
        GeneratedOn(server, now),
    );
    let headers = format!(
        "HTTP/1.1 200 OK\r\n\
        Date: {}\r\n\
        {}\
        Accept-Ranges: bytes\r\n\
        {}\
        Content-Length: {}\r\n\
        Content-Type: text/html; charset=UTF-8\r\n\
        \r\n",
        HttpDate(now),
        server.server_hdr,
        server.keep_alive_header(conn.conn_close),
        reply.as_bytes().len(),
    );
    Response {
        http_code: 200,
        headers,
        body: Some(Body::generated(reply)),
    }
}

/// A not modified reply.
fn not_modified(server: &Server, conn: &mut Connection, now: SystemTime) -> Response {
    let headers = format!(
        "HTTP/1.1 304 Not Modified\r\n\
        Date: {}\r\n\
        {}\
        Accept-Ranges: bytes\r\n\
        {}\
        \r\n",
        HttpDate(now),
        server.server_hdr,
        server.keep_alive_header(conn.conn_close),
    );
    Response {
        http_code: 304,
        headers,
        body: None,
    }
}

/// Get URL to forward to based on host header, if any.
fn get_forward_to_url<'a>(server: &'a Server, host: Option<&str>) -> Option<&'a str> {
    if !server.forward_map.is_empty() {
        if let Some(target) = host.and_then(|host| server.forward_map.get(host)) {
            return Some(target);
        }
    }
    server.forward_all_url.as_deref()
}

/// Return range based on header values and file length.
fn get_range(request_range: (Option<u64>, Option<u64>), file_len: u64) -> Option<(u64, u64)> {
    let last = file_len.saturating_sub(1);
    match request_range {
        // eg. 100-200
        (Some(from), Some(to)) => Some((from, min(to, last))),
        // eg. 100- :: yields 100 to end
        (Some(from), None) => Some((from, last)),
        // eg. -200 :: yields last 200
        (None, Some(to)) => Some((file_len.saturating_sub(to), last)),
        (None, None) => None,
    }
}

/// Process a GET/HEAD request.
fn process_get(server: &Server, conn: &mut Connection, now: SystemTime) -> Response {
    let request = conn.request.as_ref().expect("missing request");

    let authorization = request.header("authorization");
    if server.auth_key.is_some() && (authorization != server.auth_key.as_deref()) {
        let reason = "Access denied due to invalid credentials.";
        return default_reply(server, conn, now, 401, "Unauthorized", reason);
    }

    // test the host against web forward options
    let host = request.header("host");
    if let Some(forward_to_url) = get_forward_to_url(server, host) {
        let redirect_url = format!("{}{}", forward_to_url, request.target);
        return redirect(server, conn, now, &redirect_url);
    }

    // work out path of file being requested
    let mut decoded_url = url_decode(&request.target.path);

    // Make sure URL is safe
    if make_safe_url(&mut decoded_url).is_err() {
        let reason = "You requested an invalid URL.".to_string();
        return default_reply(server, conn, now, 400, "Bad Request", &reason);
    }

    // Build path to target file
    let is_directory = decoded_url.ends_with(b"/");
    let mut target = PathBuf::new();
    target.push(&server.wwwroot);
    target.push(OsStr::from_bytes(&decoded_url[1..])); // leading slash removed
    if is_directory {
        target.push(&server.index_name);
    }

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&target)
    {
        Ok(file) => file,
        Err(e) => {
            // If `--no-listing` is specified, always fall back to 404 to avoid leaking whether the
            // directory exists.
            if is_directory && e.kind() == std::io::ErrorKind::NotFound && !server.no_listing {
                target.pop();
                return generate_dir_listing(server, conn, now, &target, &decoded_url);
            }
            let (errcode, errname, reason) = match e.kind() {
                std::io::ErrorKind::PermissionDenied => (
                    403,
                    "Forbidden",
                    "You don't have permission to access this URL.".to_string(),
                ),
                std::io::ErrorKind::NotFound => (
                    404,
                    "Not Found",
                    "The URL you requested was not found.".to_string(),
                ),
                _ => (
                    500,
                    "Internal Server Error",
                    format!("The URL you requested cannot be returned: {}.", e),
                ),
            };
            return default_reply(server, conn, now, errcode, errname, &reason);
        }
    };

    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(e) => {
            let reason = format!("fstat() failed: {}.", e);
            return default_reply(server, conn, now, 500, "Internal Server Error", &reason);
        }
    };

    if metadata.is_dir() {
        let url = format!("{}/", request.target.path);
        return redirect(server, conn, now, &url);
    } else if !metadata.is_file() {
        let reason = "Not a regular file.";
        return default_reply(server, conn, now, 403, "Forbidden", &reason);
    }

    let lastmod = metadata.modified().expect("modified not available");

    // handle If-Modified-Since
    if let Some(if_mod_since) = request.header("if-modified-since") {
        if HttpDate(lastmod).to_string() == if_mod_since {
            return not_modified(server, conn, now);
        }
    }

    let mimetype = server.mime_map.content_type(&target);

    // handle Range
    let file_length = metadata.len();
    let request_range = request.range();
    if let Some((from, to)) = get_range(request_range, file_length) {
        if from >= file_length {
            let errname = "Requested Range Not Satisfiable";
            let reason = "You requested a range outside of the file.".to_string();
            return default_reply(server, conn, now, 416, errname, &reason);
        }

        if to < from {
            let errname = "Requested Range Not Satisfiable";
            let reason = "You requested a backward range.".to_string();
            return default_reply(server, conn, now, 416, errname, &reason);
        }

        let reply_length = to - from + 1;
        let body = Body::FromFile {
            file,
            // If we somehow have a file larger than `i64::MAX`, offset will become negative, and
            // sendfile64 will return an error, causing us to close the connection.
            offset: from as i64,
            length: reply_length,
        };
        let headers = format!(
            "HTTP/1.1 206 Partial Content\r\n\
            Date: {}\r\n\
            {}\
            Accept-Ranges: bytes\r\n\
            {}\
            Content-Length: {}\r\n\
            Content-Range: bytes {}-{}/{}\r\n\
            Content-Type: {}\r\n\
            Last-Modified: {}\r\n\
            \r\n",
            HttpDate(now),
            server.server_hdr,
            server.keep_alive_header(conn.conn_close),
            reply_length,
            from,
            to,
            file_length,
            mimetype,
            HttpDate(lastmod)
        );
        return Response {
            http_code: 206,
            headers,
            body: Some(body),
        };
    }

    let body = Body::FromFile {
        file,
        offset: 0,
        length: file_length,
    };

    let headers = format!(
        "HTTP/1.1 200 OK\r\n\
        Date: {}\r\n\
        {}\
        Accept-Ranges: bytes\r\n\
        {}\
        Content-Length: {}\r\n\
        Content-Type: {}\r\n\
        Last-Modified: {}\r\n\
        \r\n",
        HttpDate(now),
        server.server_hdr,
        server.keep_alive_header(conn.conn_close),
        file_length,
        mimetype,
        HttpDate(lastmod)
    );
    Response {
        http_code: 200,
        headers,
        body: Some(body),
    }
}

/// Process a request and return corresponding response.
fn process_request(server: &mut Server, conn: &mut Connection, now: SystemTime) -> Response {
    let (buffer, length) = match &conn.state {
        ConnectionState::ReceiveRequest { buffer, length } => (buffer, length),
        connection_state => panic!("unexpected state: {:?}", connection_state),
    };
    conn.request = Request::parse(&buffer[..*length]);
    if let Some(request) = conn.request.as_ref() {
        // cmdline flag can be used to deny keep-alive
        conn.conn_close = request.connection_close() || server.want_no_keepalive;
        match request.method.as_str() {
            "GET" => process_get(server, conn, now),
            "HEAD" => {
                let mut response = process_get(server, conn, now);
                response.body = None;
                response
            }
            _ => {
                let reason = "The method you specified is not implemented.";
                default_reply(server, conn, now, 501, "Not Implemented", reason)
            }
        }
    } else {
        let reason = "You sent a request that the server couldn't understand.";
        default_reply(server, conn, now, 400, "Bad Request", reason)
    }
}

/// Sending reply.
fn poll_send_reply(conn: &mut Connection, now: SystemTime, stats: &mut ServerStats) {
    assert!(conn.state == ConnectionState::SendReply);
    let response = conn.response.as_mut().expect("missing response");
    let body = response.body.as_mut().expect("reply has no body");

    conn.last_active = now;

    let sent = match body.poll_send(&conn.socket) {
        Ok(sent) if sent > 0 => sent,
        Err(nix::Error::Sys(Errno::EAGAIN)) => {
            // would block
            return;
        }
        _ => {
            // closure or other error
            conn.conn_close = true;
            conn.state = ConnectionState::Done;
            return;
        }
    };
    let sent = sent as u64; // usize shouldn't overflow u64
    conn.total_sent = conn.total_sent.saturating_add(sent);
    stats.total_out = stats.total_out.saturating_add(sent);
    if body.done_sending() {
        conn.state = ConnectionState::Done;
    }
}

/// Sending header. Assumes conn->header is not NULL.
fn poll_send_header(conn: &mut Connection, now: SystemTime, stats: &mut ServerStats) {
    assert_eq!(conn.state, ConnectionState::SendHeader);
    let response = conn.response.as_ref().expect("missing response");

    let header = response.headers.as_bytes();

    conn.last_active = now;

    let sent = match socket::send(
        conn.socket.as_raw_fd(),
        &header[conn.header_sent..header.len() - conn.header_sent],
        socket::MsgFlags::empty(),
    ) {
        Ok(sent) if sent > 0 => sent,
        Err(nix::Error::Sys(Errno::EAGAIN)) => {
            // would block
            return;
        }
        _ => {
            // closure or other error
            conn.conn_close = true;
            conn.state = ConnectionState::Done;
            return;
        }
    };

    conn.header_sent += sent;
    let sent = sent as u64; // usize shouldn't overflow u64
    conn.total_sent = conn.total_sent.saturating_add(sent);
    stats.total_out = stats.total_out.saturating_add(sent);

    // check if we're done sending header
    if conn.header_sent == header.len() {
        if response.body.is_none() {
            conn.state = ConnectionState::Done;
        } else {
            conn.state = ConnectionState::SendReply;
            // go straight on to body, don't go through another iteration of the select() loop
            poll_send_reply(conn, now, stats);
        }
    }
}

/// Receiving request.
fn poll_recv_request(
    server: &mut Server,
    conn: &mut Connection,
    now: SystemTime,
    stats: &mut ServerStats,
) {
    let (buffer, length) = match &mut conn.state {
        ConnectionState::ReceiveRequest { buffer, length } => (buffer, length),
        connection_state => panic!("unexpected state: {:?}", connection_state),
    };

    let recvd = match socket::recv(
        conn.socket.as_raw_fd(),
        &mut buffer[*length..],
        socket::MsgFlags::empty(),
    ) {
        Ok(recvd) if recvd > 0 => recvd,
        Err(nix::Error::Sys(Errno::EAGAIN)) => {
            // would block
            return;
        }
        _ => {
            // closure or other error
            conn.conn_close = true;
            conn.state = ConnectionState::Done;
            return;
        }
    };
    conn.last_active = now;

    *length += recvd;
    let recvd = recvd as u64; // usize shouldn't overflow u64
    stats.total_in = stats.total_in.saturating_add(recvd);

    // TODO: Handle HTTP pipelined requests
    if (*length >= 2 && &buffer[*length - 2..*length] == b"\n\n")
        || (*length >= 4 && &buffer[*length - 4..*length] == b"\r\n\r\n")
    {
        stats.num_requests += 1;
        conn.response = Some(process_request(server, conn, now));
        conn.state = ConnectionState::SendHeader;
    } else if *length == buffer.len() {
        // Prevent a malformed request from eating up too much memory by rejecting requests larger
        // than the buffer size.
        let errname = "Request Entity Too Large";
        let reason = "Your request was dropped because it was too long.";
        conn.response = Some(default_reply(server, conn, now, 413, errname, reason));
        conn.state = ConnectionState::SendHeader;
    }

    // if we've moved on to the next state, try to send right away, instead of going through
    // another iteration of the select() loop.
    if conn.state == ConnectionState::SendHeader {
        poll_send_header(conn, now, stats);
    }
}

/// Encode string for logging. Logs should not contain control characters or double quotes.
struct LogEncoded<'a>(&'a str);

impl<'a> std::fmt::Display for LogEncoded<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for c in self.0.chars() {
            if !c.is_ascii() || c.is_ascii_control() || c == '"' {
                let mut buf = [0; 4];
                c.encode_utf8(&mut buf);
                for b in buf.iter().take(c.len_utf8()) {
                    write!(f, "%{:02X}", b)?;
                }
            } else {
                write!(f, "{}", c)?;
            }
        }
        Ok(())
    }
}

/// Add a connection's details to the logfile.
fn log_connection(server: &mut Server, conn: &Connection, now: SystemTime) {
    // TODO: Make logging request-oriented?
    let request = match conn.request.as_ref() {
        Some(request) => request,
        None => return, // request was not parsed
    };
    let message = format!(
        "{} - - {} \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\"\n",
        conn.client,
        ClfDate(now),
        LogEncoded(&request.method),
        LogEncoded(&request.target.to_string()),
        conn.response
            .as_ref()
            .map(|response| response.http_code)
            .unwrap_or(0),
        conn.total_sent,
        LogEncoded(request.header("referer").unwrap_or("")),
        LogEncoded(request.header("user-agent").unwrap_or(""))
    );
    server
        .log_sink
        .log(&message)
        .expect("failed to write log message");
}

/// If a connection has been idle for more than `server.timeout`, it will be marked as DONE and
/// killed off in httpd_poll().
fn poll_check_timeout(server: &Server, conn: &mut Connection, now: SystemTime) {
    if let Some(timeout) = server.timeout {
        let elapsed = now
            .duration_since(conn.last_active)
            .unwrap_or_else(|_| Duration::from_secs(0));
        if elapsed >= timeout {
            conn.conn_close = true;
            conn.state = ConnectionState::Done;
        }
    }
}

/// Accept a connection from TcpListener and add it to the connection queue.
fn accept_connection(
    server: &mut Server,
    listener: &TcpListener,
    files_exhausted: &mut bool,
    now: SystemTime,
    stats: &mut ServerStats,
    connections: &mut Vec<Connection>,
) {
    let (stream, addr) = match listener.accept() {
        Ok((stream, addr)) => (stream, addr),
        Err(e) => {
            // Failed to accept, but try to keep serving existing connections.
            if matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE)) {
                *files_exhausted = true;
            }
            eprintln!("warning: accept() failed: {}", e);
            return;
        }
    };

    stream
        .set_nonblocking(true)
        .expect("set_nonblocking failed");

    // Reduce latency by sending data as soon as possible, rather than delaying it to coalesce
    // small packets. The server avoids doing small writes by buffering in user-space. This greatly
    // reduces latency for keep-alive requests.
    // TODO: Use TCP_CORK to avoid putting the headers and body in separate packets?
    stream.set_nodelay(true).expect("set_nodelay failed");

    // Allocate and initialize struct connection.
    let conn = Connection::new(now, stream, addr.ip());

    connections.push(conn);
    let num_connections = connections.len();

    // Try to read straight away rather than going through another iteration of the select() loop.
    poll_recv_request(server, &mut connections[num_connections - 1], now, stats);
}

/// Main loop of the httpd - a select() and then delegation to accept connections, handle receiving
/// of requests, and sending of replies.
fn httpd_poll(
    server: &mut Server,
    listener: &TcpListener,
    files_exhausted: &mut bool,
    stats: &mut ServerStats,
    connections: &mut Vec<Connection>,
) {
    let mut recv_set = FdSet::new();
    let mut send_set = FdSet::new();
    let mut timeout_required = false;

    let reached_max_connections =
        matches!(server.max_connections, Some(num) if num >= connections.len());
    if !*files_exhausted && !reached_max_connections {
        recv_set.insert(listener.as_raw_fd());
    }

    for conn in connections.iter() {
        match conn.state {
            ConnectionState::Done => {}
            ConnectionState::ReceiveRequest { .. } => {
                recv_set.insert(conn.socket.as_raw_fd());
                timeout_required = true;
            }
            ConnectionState::SendHeader | ConnectionState::SendReply => {
                send_set.insert(conn.socket.as_raw_fd());
                timeout_required = true;
            }
        }
    }

    let mut timeout = server
        .timeout
        .map(|timeout| {
            TimeVal::from(libc::timeval {
                tv_sec: timeout.as_secs() as libc::time_t,
                tv_usec: 0,
            })
        })
        .filter(|_| timeout_required);

    match select(
        None,
        Some(&mut recv_set),
        Some(&mut send_set),
        None,
        timeout.as_mut(),
    ) {
        Ok(0) => {
            if !timeout_required {
                panic!("select() timed out");
            }
        }
        Ok(_) => {}
        Err(e) => {
            if e.as_errno() == Some(Errno::EINTR) {
                return; // interrupted by signal
            } else {
                panic!("select() failed: {}", e)
            }
        }
    }

    // update time
    let now = SystemTime::now();

    // poll connections that select() says need attention
    if recv_set.contains(listener.as_raw_fd()) {
        accept_connection(server, listener, files_exhausted, now, stats, connections);
    }
    let mut index = 0;
    while index < connections.len() {
        let conn = &mut connections[index];

        poll_check_timeout(server, conn, now);

        match conn.state {
            ConnectionState::ReceiveRequest { .. } => {
                if recv_set.contains(conn.socket.as_raw_fd()) {
                    poll_recv_request(server, conn, now, stats);
                }
            }
            ConnectionState::SendHeader => {
                if send_set.contains(conn.socket.as_raw_fd()) {
                    poll_send_header(conn, now, stats);
                }
            }
            ConnectionState::SendReply => {
                if send_set.contains(conn.socket.as_raw_fd()) {
                    poll_send_reply(conn, now, stats);
                }
            }
            ConnectionState::Done => {
                // (handled later; ignore for now as it's a valid state)
            }
        };

        // Handling SEND_REPLY could have set the state to done.
        if conn.state == ConnectionState::Done {
            // clean out finished connection
            log_connection(server, conn, now);
            if conn.conn_close {
                connections.remove(index);
                // Try to resume accepting if we ran out of sockets.
                *files_exhausted = false;
            } else {
                conn.recycle();
                index += 1;
            }
        } else {
            index += 1;
        }
    }
}
