use std::cmp::{max, min};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
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
const DEFAULT_MIME_TYPE: &str = "application/octet-stream";
const PATH_DEVNULL: &str = "/dev/null";
const SENDFILE_SIZE_LIMIT: usize = 1 << 20;

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

        chdir(server.wwwroot.as_str())
            .with_context(|| format!("failed to change working directory to {}", server.wwwroot))?;
        chroot(server.wwwroot.as_str())
            .with_context(|| format!("failed to change root directory to {}", server.wwwroot))?;
        println!("chrooted to `{}'", &server.wwwroot);

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
                let message = CString::new(message).unwrap();
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

#[derive(Debug, Default)]
struct Server {
    forward_map: ForwardMap,
    forward_all_url: Option<String>,
    timeout: Option<Duration>,
    bindaddr: Option<String>,
    bindport: u16,
    max_connections: Option<usize>,
    index_name: String,
    no_listing: bool,
    inet6: bool,
    wwwroot: String,
    log_sink: LogSink,
    pidfile_name: Option<String>,
    want_chroot: bool,
    want_daemon: bool,
    want_accf: bool,
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
            timeout: Some(Duration::from_secs(30)),
            bindport: if getuid().is_root() { 80 } else { 8080 },
            index_name: DEFAULT_INDEX_NAME.to_string(),
            ..Default::default()
        };
        // TODO: use std::env::args_os to allow non-UTF-8 filenames
        let mut args = std::env::args();
        let name = args.next().expect("expected at least one argument");
        match args.next().as_deref() {
            None | Some("--help") => {
                server.usage(&name); // no wwwroot given
                std::process::exit(0);
            }
            Some(wwwroot) => {
                server.wwwroot = wwwroot.to_string();
                // Strip ending slash.
                if server.wwwroot.ends_with('/') {
                    server.wwwroot.pop();
                }
            }
        };
        while let Some(arg) = args.next().as_deref() {
            match arg {
                "--port" => {
                    let number = args.next().context("missing number after --port")?;
                    server.bindport = number
                        .parse()
                        .with_context(|| format!("port number {} is invalid", number))?;
                }
                "--addr" => {
                    server.bindaddr = Some(args.next().context("missing ip after --addr")?);
                }
                "--maxconn" => {
                    let number = args.next().context("missing number after --maxconn")?;
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
                            .with_context(|| format!("failed to open log file {}", filename))?,
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
                    server
                        .mime_map
                        .parse_extension_map_file(&OsString::from(filename))?;
                }
                "--default-mimetype" => {
                    server.mime_map.default_mimetype = args
                        .next()
                        .context("missing string after --default-mimetype")?;
                }
                "--uid" => {
                    let uid = args.next().context("missing uid after --uid")?;
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
                    let gid = args.next().context("missing gid after --gid")?;
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
                "--accf" => server.want_accf = true, // TODO: remove?
                "--syslog" => server.log_sink = LogSink::Syslog,
                "--forward" => {
                    let host = args.next().context("missing host after --forward")?;
                    let url = args.next().context("missing url after --forward")?;
                    server.forward_map.insert(host, url);
                }
                "--forward-all" => {
                    server.forward_all_url =
                        Some(args.next().context("missing url after --forward-all")?)
                }
                "--no-server-id" => server.want_no_server_id = true,
                "--timeout" => {
                    let number = args.next().context("missing number after --timeout")?;
                    let timeout_secs = number
                        .parse::<u64>()
                        .with_context(|| format!("timeout number {} is invalid", number))?;
                    server.timeout = match timeout_secs {
                        0 => None,
                        timeout_secs => Some(Duration::from_secs(timeout_secs)),
                    };
                }
                "--auth" => {
                    let user_pass = args.next().context("missing user:pass after --auth")?;
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
    fn keep_alive_header(&self, conn_close: bool) -> String {
        // TODO: Build this string once and reuse it.
        if conn_close {
            "Connection: close\r\n".to_string()
        } else {
            // TODO: Figure out how to handle timeout being disabled while keep-alive is enabled.
            format!(
                "Keep-Alive: timeout={}\r\n",
                self.timeout.map(|timeout| timeout.as_secs()).unwrap_or(0)
            )
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
    name: String,
    file: File,
}
impl PidFile {
    fn create(pidfile_name: String) -> Result<Self> {
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
                    anyhow::Error::new(e)
                        .context(format!("failed to create pidfile {}", pidfile_name))
                }
            })?;

        // Write pid to the pidfile.
        if let Err(e) = write!(pidfile_file, "{}", getpid()) {
            Self::remove_raw(&pidfile_name, pidfile_file).ok();
            return Err(e).with_context(|| format!("failed to write to pidfile {}", pidfile_name));
        };

        Ok(Self {
            name: pidfile_name,
            file: pidfile_file,
        })
    }
    fn read(pidfile_name: &str) -> Result<Pid> {
        let mut pidfile = File::open(pidfile_name)
            .with_context(|| format!("failed to open pidfile {}", pidfile_name))?;
        let mut buf = String::new();
        pidfile
            .read_to_string(&mut buf)
            .with_context(|| format!("failed to read pidfile {}", pidfile_name))?;
        Ok(Pid::from_raw(
            buf.parse().context("invalid pidfile contents")?,
        ))
    }
    fn remove(self) -> Result<()> {
        Self::remove_raw(&self.name, self.file)
    }
    fn remove_raw(pidfile_name: &str, pidfile_file: File) -> Result<()> {
        remove_file(pidfile_name)
            .with_context(|| format!("failed to remove pidfile {}", pidfile_name))?;
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

/// An HTTP request.
struct Request {
    method: String,
    url: String,
    protocol: Option<String>,
    headers: HashMap<String, String>,
}
impl Request {
    /// Parse an HTTP request.
    fn parse(buffer: &[u8]) -> Option<Request> {
        let request = std::str::from_utf8(buffer).ok()?;
        let mut lines = request.lines();
        let mut request_line = lines.next().unwrap().split(' ');
        let method = request_line.next()?.to_uppercase();
        let url = request_line.next()?.to_string();
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
            url,
            protocol,
            headers,
        })
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|s| s.as_str())
    }
    fn range(&self) -> (Option<i64>, Option<i64>) {
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
    reply_start: i64,
    reply_length: i64,
}

struct Connection {
    socket: TcpStream,
    client: IpAddr,
    last_active: SystemTime,
    state: ConnectionState,
    buffer: Vec<u8>,
    request: Option<Request>,
    response: Option<Response>,
    header_sent: usize,
    conn_close: bool,
    reply_sent: i64,
    total_sent: i64,
}
impl Connection {
    /// Allocate and initialize an empty connection.
    fn new(now: SystemTime, stream: TcpStream, client: IpAddr) -> Self {
        Self {
            socket: stream,
            client,
            last_active: now,
            state: ConnectionState::ReceiveRequest,
            buffer: Vec::new(),
            request: None,
            response: None,
            header_sent: 0,
            conn_close: true,
            reply_sent: 0,
            total_sent: 0,
        }
    }

    /// Recycle a finished connection for HTTP/1.1 Keep-Alive.
    fn recycle(&mut self) {
        // don't reset conn.client
        self.buffer = Vec::new();
        self.request = None;
        self.response = None;
        self.header_sent = 0;
        self.conn_close = true;
        self.reply_sent = 0;
        self.total_sent = 0;

        self.state = ConnectionState::ReceiveRequest; // ready for another
    }
}

#[derive(Debug, PartialEq)]
enum ConnectionState {
    ReceiveRequest,
    SendHeader,
    SendReply,
    Done,
}

#[derive(Debug)]
enum Body {
    Generated(String),
    FromFile(File),
}
impl Body {
    /// Send `length` bytes of body starting from offset `offset`.
    fn send(&self, stream: &TcpStream, offset: i64, length: usize) -> nix::Result<usize> {
        match self {
            Body::Generated(reply) => {
                // It's not possible for a generated body to be larger than `usize`.
                let offset = usize::try_from(offset).unwrap();
                let buf = &reply.as_bytes()[offset..offset + length];
                socket::send(stream.as_raw_fd(), buf, socket::MsgFlags::empty())
            }
            Body::FromFile(file) => {
                let mut offset = offset;
                let size = min(length, SENDFILE_SIZE_LIMIT); // Limit size per syscall.
                sendfile64(
                    stream.as_raw_fd(),
                    file.as_raw_fd(),
                    Some(&mut offset),
                    size,
                )
            }
        }
    }
}

type ForwardMap = HashMap<String, String>;

// TODO: Include this as a file.
const DEFAULT_EXTENSIONS_MAP: &[&str] = &[
    "application/ogg         ogg",
    "application/pdf         pdf",
    "application/wasm        wasm",
    "application/xml         xsl xml",
    "application/xml-dtd     dtd",
    "application/xslt+xml    xslt",
    "application/zip         zip",
    "audio/mpeg              mp2 mp3 mpga",
    "image/gif               gif",
    "image/jpeg              jpeg jpe jpg",
    "image/png               png",
    "image/svg+xml           svg",
    "text/css                css",
    "text/html               html htm",
    "text/javascript         js",
    "text/plain              txt asc",
    "video/mpeg              mpeg mpe mpg",
    "video/quicktime         qt mov",
    "video/x-msvideo         avi",
    "video/mp4               mp4",
];

#[derive(Debug)]
struct MimeMap {
    mimetypes: HashMap<String, String>,
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
            self.mimetypes
                .insert(extension.to_string(), mimetype.to_string());
        }
    }

    /// Get content type for a URL.
    fn url_content_type(&self, url: &str) -> &str {
        url.rsplit('.')
            .next()
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
        for line in DEFAULT_EXTENSIONS_MAP {
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
    if !url.starts_with(&[b'/']) {
        bail!("url does not start with slash");
    }

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
                write!(f, "{}", std::char::from_u32(*byte as u32).unwrap())?;
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

fn parse_offset(data: &[u8]) -> (Option<i64>, &[u8]) {
    let mut digits_len = 0;
    while digits_len < data.len() && data[digits_len].is_ascii_digit() {
        digits_len += 1;
    }
    let offset = std::str::from_utf8(&data[0..digits_len])
        .unwrap()
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
    let reply_length = reply.as_bytes().len() as i64;
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
        reply_length,
        if server.auth_key.is_some() {
            "WWW-Authenticate: Basic realm=\"User Visible Realm\"\r\n"
        } else {
            ""
        }
    );
    Response {
        http_code: errcode,
        headers,
        body: Some(Body::Generated(reply)),
        reply_start: 0,
        reply_length,
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
    let reply_length = reply.as_bytes().len() as i64;
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
        reply_length,
    );
    Response {
        http_code: 301,
        headers,
        body: Some(Body::Generated(reply)),
        reply_start: 0,
        reply_length,
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
    path: &str,
    decoded_url: &str,
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

    let reply = format!(
        "<html>\n<head>\n<title>{}</title>\n\
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
        </head>\n<body>\n<h1>{}</h1>\n<tt><pre>\n\
        {}\
        </pre></tt>\n\
        <hr>\n\
        {}\
        </body>\n</html>\n",
        HtmlEscaped(decoded_url),
        HtmlEscaped(decoded_url),
        Listing(entries),
        GeneratedOn(server, now),
    );
    let reply_length = reply.as_bytes().len() as i64;
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
        reply_length,
    );
    Response {
        http_code: 200,
        headers,
        body: Some(Body::Generated(reply)),
        reply_start: 0,
        reply_length,
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
        reply_start: 0,
        reply_length: 0,
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
fn get_range(request_range: (Option<i64>, Option<i64>), file_len: i64) -> Option<(i64, i64)> {
    match request_range {
        // eg. 100-200
        (Some(from), Some(to)) => Some((from, min(to, file_len - 1))),
        // eg. 100- :: yields 100 to end
        (Some(from), None) => Some((from, file_len - 1)),
        // eg. -200 :: yields last 200
        (None, Some(to)) => Some((max(file_len - to, 0), file_len - 1)),
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

    // strip query params
    let stripped_url = request.url.splitn(2, '?').next().unwrap().to_string();

    // work out path of file being requested
    let mut decoded_url = url_decode(&stripped_url);

    // Make sure URL is safe
    if let Err(_) = make_safe_url(&mut decoded_url) {
        let reason = "You requested an invalid URL.".to_string();
        return default_reply(server, conn, now, 400, "Bad Request", &reason);
    }
    // TODO: Handle non-UTF-8 paths without panicking.
    let decoded_url = String::from_utf8(decoded_url).unwrap();

    // test the host against web forward options
    let host = request.header("host");
    if let Some(forward_to_url) = get_forward_to_url(server, host) {
        let redirect_url = format!("{}{}", forward_to_url, decoded_url);
        return redirect(server, conn, now, &redirect_url);
    }

    // Find path to target file, and possibly a fallback to an index file.
    let target;
    let dir_listing_target;
    if decoded_url.ends_with('/') {
        target = format!("{}{}{}", server.wwwroot, decoded_url, server.index_name);
        dir_listing_target = Some(format!("{}{}", server.wwwroot, decoded_url));
    } else {
        target = format!("{}{}", server.wwwroot, decoded_url);
        dir_listing_target = None;
    }

    let mimetype = server.mime_map.url_content_type(&target);

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(target)
    {
        Ok(file) => file,
        Err(e) => {
            if let Some(target) = dir_listing_target {
                // If `--no-listing` is specified, always fall back to 404 to avoid leaking
                // information.
                if e.kind() == std::io::ErrorKind::NotFound && !server.no_listing {
                    return generate_dir_listing(server, conn, now, &target, &decoded_url);
                }
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
        // TODO: Fix when URL contains query string
        let url = format!("{}/", request.url);
        return redirect(server, conn, now, &url);
    } else if !metadata.is_file() {
        // TODO: Add test coverage
        let reason = "Not a regular file.";
        return default_reply(server, conn, now, 403, "Forbidden", &reason);
    }

    let body = Some(Body::FromFile(file));
    let lastmod = metadata.modified().expect("modified not available");

    // handle If-Modified-Since
    if let Some(if_mod_since) = request.header("if-modified-since") {
        if HttpDate(lastmod).to_string() == if_mod_since {
            return not_modified(server, conn, now);
        }
    }

    // handle Range
    let request_range = request.range();
    if let Some((from, to)) = get_range(request_range, metadata.len() as i64) {
        if from >= metadata.len() as i64 {
            let errname = "Requested Range Not Satisfiable";
            let reason = "You requested a range outside of the file.".to_string();
            return default_reply(server, conn, now, 416, errname, &reason);
        }

        if to < from {
            let errname = "Requested Range Not Satisfiable";
            let reason = "You requested a backward range.".to_string();
            return default_reply(server, conn, now, 416, errname, &reason);
        }

        let reply_start = from;
        let reply_length = to - from + 1;
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
            reply_start,
            to,
            metadata.len(),
            mimetype,
            HttpDate(lastmod)
        );
        return Response {
            http_code: 206,
            headers,
            body,
            reply_start,
            reply_length,
        };
    }

    let reply_length = metadata.len().try_into().unwrap();

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
        reply_length,
        mimetype,
        HttpDate(lastmod)
    );
    Response {
        http_code: 200,
        headers,
        body,
        reply_start: 0,
        reply_length,
    }
}

/// Process a request and return corresponding response.
fn process_request(server: &mut Server, conn: &mut Connection, now: SystemTime) -> Response {
    conn.request = Request::parse(&conn.buffer);
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
    assert!(response.reply_length >= conn.reply_sent);

    conn.last_active = now;

    let offset = response.reply_start + conn.reply_sent;
    // `i64` may wider than `usize`, so saturate when casting.
    let send_len = usize::try_from(response.reply_length - conn.reply_sent).unwrap_or(usize::MAX);
    let body = response.body.as_ref().expect("reply has no body");
    let sent = match body.send(&conn.socket, offset, send_len) {
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
    conn.reply_sent += i64::try_from(sent).unwrap();
    conn.total_sent += i64::try_from(sent).unwrap();
    stats.total_out += u64::try_from(sent).unwrap();

    // check if we're done sending
    if conn.reply_sent == response.reply_length {
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

    assert!(sent > 0);
    conn.header_sent += sent;
    conn.total_sent += i64::try_from(sent).unwrap();
    stats.total_out += u64::try_from(sent).unwrap();

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

// To prevent a malformed request from eating up too much memory, die once the request exceeds this
// many bytes:
const MAX_REQUEST_LENGTH: usize = 4000;

/// Receiving request.
fn poll_recv_request(
    server: &mut Server,
    conn: &mut Connection,
    now: SystemTime,
    stats: &mut ServerStats,
) {
    assert_eq!(conn.state, ConnectionState::ReceiveRequest);
    // TODO: Write directly to the request buffer
    let mut buf = [0; 1 << 15];
    let recvd = u64::try_from(
        match socket::recv(conn.socket.as_raw_fd(), &mut buf, socket::MsgFlags::empty()) {
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
        },
    )
    .unwrap();
    conn.last_active = now;

    // append to conn.buffer
    assert!(recvd > 0);
    conn.buffer.extend(&buf[..recvd.try_into().unwrap()]);
    stats.total_in += recvd;

    // die if it's too large, or process request if we have all of it
    // TODO: Handle HTTP pipelined requests
    if conn.buffer.len() > MAX_REQUEST_LENGTH {
        let errname = "Request Entity Too Large";
        let reason = "Your request was dropped because it was too long.";
        conn.response = Some(default_reply(server, conn, now, 413, errname, reason));
        conn.buffer = Vec::new(); // request not needed anymore
        conn.state = ConnectionState::SendHeader;
    } else if (conn.buffer.len() >= 2
        && &conn.buffer[conn.buffer.len() - 2..conn.buffer.len()] == b"\n\n")
        || (conn.buffer.len() >= 4
            && &conn.buffer[conn.buffer.len() - 4..conn.buffer.len()] == b"\r\n\r\n")
    {
        stats.num_requests += 1;
        conn.response = Some(process_request(server, conn, now));
        conn.buffer = Vec::new(); // request not needed anymore
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
        LogEncoded(&request.url),
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
            ConnectionState::ReceiveRequest => {
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
            ConnectionState::ReceiveRequest => {
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
                // and go right back to recv_request without going through select() again.
                poll_recv_request(server, conn, now, stats);
                index += 1;
            }
        } else {
            index += 1;
        }
    }
}
