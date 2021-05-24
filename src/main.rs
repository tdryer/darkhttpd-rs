use std::cmp::{max, min};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{remove_file, File, OpenOptions};
use std::io::{BufRead, BufWriter, Read, Write};
use std::mem::MaybeUninit;
use std::net::{
    AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream,
};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, Context, Result};
use chrono::{Local, TimeZone, Utc};
use nix::errno::Errno;
use nix::sys::select::{select, FdSet};
use nix::sys::sendfile::sendfile;
use nix::sys::signal::{signal, SigHandler, Signal};
use nix::sys::socket;
use nix::sys::time::TimeVal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{
    chdir, chroot, close, dup2, fork, getpid, getuid, pipe, read, setgid, setgroups, setsid,
    setuid, ForkResult, Gid, Group, Pid, Uid, User,
};

const COPYRIGHT: &str = "copyright (c) 2021 Tom Dryer";
const DEFAULT_INDEX_NAME: &str = "index.html";

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn stop_running(_signal: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}

fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

fn usage(server: &Server, argv0: &str) {
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
        argv0, server.bindport, DEFAULT_INDEX_NAME, DEFAULT_MIME_TYPE, server.timeout_secs
    );
}

/// Prints message to standard error and exits with code 1.
macro_rules! abort {
    ($($arg:tt)*) => ({
        eprint!("{}: ", env!("CARGO_PKG_NAME"));
        eprintln!($($arg)*);
        std::process::exit(1);
    })
}

const INVALID_UID: libc::uid_t = libc::uid_t::MAX;
const INVALID_GID: libc::gid_t = libc::gid_t::MAX;

fn main() -> Result<()> {
    let mut server = Server::new();

    println!(
        "{}/{}, {}.",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        COPYRIGHT,
    );
    parse_commandline(&mut server)?;

    if server.want_server_id {
        server.server_hdr = format!(
            "Server: {}/{}\r\n",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
    }

    init_sockin(&mut server);

    let mut lifeline_read = -1;
    let mut lifeline_write = -1;
    let mut fd_null = -1;
    if server.want_daemon {
        daemonize_start(&mut lifeline_read, &mut lifeline_write, &mut fd_null)
            .context("failed to daemonize")?;
    }

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

    if server.drop_gid != INVALID_GID {
        let gid = Gid::from_raw(server.drop_gid);
        setgroups(&[gid])
            .with_context(|| format!("failed to set supplementary group IDs to [{}]", gid))?;
        setgid(gid).with_context(|| format!("failed to set group ID to {}", gid))?;
        println!("set gid to {}", gid);
    }

    if server.drop_uid != INVALID_UID {
        let uid = Uid::from_raw(server.drop_uid);
        setuid(uid).with_context(|| format!("failed to set user ID to {}", uid))?;
        println!("set uid to {}", uid);
    }

    let pidfile = server
        .pidfile_name
        .take()
        .map(PidFile::create)
        .transpose()?;

    if server.want_daemon {
        daemonize_finish(&mut lifeline_read, &mut lifeline_write, &mut fd_null)
            .context("failed to daemonize")?;
    }

    let mut connections = Vec::new();

    // main loop
    while is_running() {
        httpd_poll(&mut server, &mut connections);
    }

    // clean exit
    close(server.sockin).context("failed to close listening socket")?;

    pidfile.map(|pidfile| pidfile.remove()).transpose()?;

    // free connections
    for mut conn in connections.drain(..) {
        free_connection(&mut server, &mut conn);
    }

    // Original darkhttpd only prints usage stats if logfile is specified, because otherwise stdout
    // will be closed. It's not clear whether this was intentional.
    if !matches!(server.log_sink, LogSink::Stdout) {
        let rusage = getrusage().context("failed to get resource usage")?;
        println!(
            "CPU time used: {}.{:02} user, {}.{:02} system",
            rusage.ru_utime.tv_sec,
            rusage.ru_utime.tv_usec / 10000,
            rusage.ru_stime.tv_sec,
            rusage.ru_stime.tv_usec / 10000,
        );
        println!("Requests: {}", server.num_requests);
        println!("Bytes: {} in, {} out", server.total_in, server.total_out);
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

#[derive(Debug)]
struct Server {
    forward_map: ForwardMap,
    forward_all_url: Option<String>,
    timeout_secs: libc::c_int,
    bindaddr: Option<String>,
    bindport: u16,
    max_connections: libc::c_int,
    index_name: String,
    no_listing: bool,
    sockin: libc::c_int,
    now: libc::time_t,
    inet6: bool,
    wwwroot: String,
    log_sink: LogSink,
    pidfile_name: Option<String>,
    want_chroot: bool,
    want_daemon: bool,
    want_accf: bool,
    want_keepalive: bool,
    want_server_id: bool,
    server_hdr: String,
    auth_key: Option<String>,
    num_requests: u64,
    total_in: u64,
    total_out: u64,
    accepting: bool,
    mime_map: MimeMap,
    drop_uid: libc::uid_t,
    drop_gid: libc::gid_t,
}
impl Server {
    fn new() -> Self {
        Self {
            forward_map: ForwardMap::new(),
            forward_all_url: None,
            timeout_secs: 30,
            bindaddr: None,
            bindport: 8080,      /* or 80 if running as root */
            max_connections: -1, /* kern.ipc.somaxconn */
            index_name: DEFAULT_INDEX_NAME.to_string(),
            no_listing: false,
            sockin: -1,
            now: 0,
            inet6: false,
            wwwroot: String::new(),
            log_sink: LogSink::Stdout,
            pidfile_name: None,
            want_chroot: false,
            want_daemon: false,
            want_accf: false,
            want_keepalive: true,
            want_server_id: true,
            server_hdr: String::new(),
            auth_key: None,
            num_requests: 0,
            total_in: 0,
            total_out: 0,
            accepting: true,
            mime_map: MimeMap::parse_default_extension_map(),
            drop_uid: INVALID_UID,
            drop_gid: INVALID_GID,
        }
    }
    fn keep_alive_header(&self, conn_close: bool) -> String {
        // TODO: Build this string once and reuse it.
        if conn_close {
            "Connection: close\r\n".to_string()
        } else {
            format!("Keep-Alive: timeout={}\r\n", self.timeout_secs)
        }
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

fn parse_commandline(server: &mut Server) -> Result<()> {
    // TODO: use std::env::args_os to allow non-UTF-8 filenames
    let mut args = std::env::args();

    let name = args.next().expect("expected at least one argument");

    match args.next().as_deref() {
        None | Some("--help") => {
            usage(server, &name); // no wwwroot given
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

    if getuid().is_root() {
        server.bindport = 80;
    }

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
                server.max_connections = number
                    .parse()
                    .with_context(|| format!("maxconn number {} is invalid", number))?;
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
                    .parse_extension_map_file(&OsString::from(filename));
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
                server.drop_uid = user1
                    .or(user2)
                    .with_context(|| format!("no such uid: `{}'", uid))?
                    .uid
                    .as_raw();
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
                server.drop_gid = group1
                    .or(group2)
                    .with_context(|| format!("no such gid: `{}'", gid))?
                    .gid
                    .as_raw();
            }
            "--pidfile" => {
                server.pidfile_name =
                    Some(args.next().context("missing filename after --pidfile")?);
            }
            "--no-keepalive" => server.want_keepalive = false,
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
            "--no-server-id" => server.want_server_id = false,
            "--timeout" => {
                let number = args.next().context("missing number after --timeout")?;
                server.timeout_secs = number
                    .parse()
                    .with_context(|| format!("timeout number {} is invalid", number))?;
            }
            "--auth" => {
                let user_pass = args.next().context("missing user:pass after --auth")?;
                if !user_pass.contains(':') {
                    return Err(anyhow!("expected user:pass after --auth"));
                }
                server.auth_key = Some(format!("Basic {}", Base64Encoded(user_pass.as_bytes())));
            }
            "--ipv6" => server.inet6 = true,
            _ => {
                return Err(anyhow!("unknown argument `{}'", arg));
            }
        }
    }
    Ok(())
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
            .custom_flags(libc::O_CREAT | libc::O_EXCL)
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

const PATH_DEVNULL: &str = "/dev/null";

fn daemonize_start(
    lifeline_read: &mut libc::c_int,
    lifeline_write: &mut libc::c_int,
    fd_null: &mut libc::c_int,
) -> Result<()> {
    // create lifeline pipe
    let pipe_fds = pipe().context("failed to create pipe")?;
    // TODO: return these
    *lifeline_read = pipe_fds.0;
    *lifeline_write = pipe_fds.1;

    // populate fd_null
    *fd_null = OpenOptions::new()
        .read(true)
        .write(true)
        .open(PATH_DEVNULL)
        .with_context(|| format!("failed to open {}", PATH_DEVNULL))?
        .into_raw_fd();

    if let ForkResult::Parent { child } = unsafe { fork() }.context("failed to fork process")? {
        // wait for the child
        if let Err(e) = close(*lifeline_write) {
            eprintln!("warning: failed to close lifeline in parent: {}", e);
        }
        let mut buf = [0; 1];
        if let Err(e) = read(*lifeline_read, &mut buf) {
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
    Ok(())
}

fn daemonize_finish(
    lifeline_read: &mut libc::c_int,
    lifeline_write: &mut libc::c_int,
    fd_null: &mut libc::c_int,
) -> Result<()> {
    setsid().context("failed to create session")?;
    if let Err(e) = close(*lifeline_read) {
        eprintln!(
            "warning: failed to close read end of lifeline in child: {}",
            e
        );
    }
    if let Err(e) = close(*lifeline_write) {
        eprintln!("warning: failed to cut the lifeline: {}", e);
    }

    // close all our std fds
    if let Err(e) = dup2(*fd_null, libc::STDIN_FILENO) {
        eprintln!("warning: failed to close stdin: {}", e);
    }
    if let Err(e) = dup2(*fd_null, libc::STDOUT_FILENO) {
        eprintln!("warning: failed to close stdout: {}", e);
    }
    if let Err(e) = dup2(*fd_null, libc::STDERR_FILENO) {
        eprintln!("warning: failed to close stderr: {}", e);
    }
    if *fd_null > 2 {
        close(*fd_null).ok();
    }
    Ok(())
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
                write!(f, "{}", BASE64_TABLE[(triple as usize >> i * 6) & 0x3F])?;
            }
            for _ in 0..(3 - chunk.len()) {
                write!(f, "=")?;
            }
        }
        Ok(())
    }
}

// TODO: Oxidize types
struct Connection {
    socket: Option<TcpStream>,
    client: IpAddr,
    last_active: libc::time_t,
    state: ConnectionState,
    request: Vec<u8>,
    method: Option<String>,
    url: Option<String>,
    referer: Option<String>,
    user_agent: Option<String>,
    authorization: Option<String>,
    range_begin: libc::off_t,
    range_end: libc::off_t,
    range_begin_given: libc::off_t,
    range_end_given: libc::off_t,
    header: Option<String>,
    header_sent: usize,
    header_only: bool,
    http_code: u16,
    conn_close: bool,
    reply_type: ConnectionReplyType,
    reply: Option<String>,
    reply_fd: Option<File>,
    reply_start: libc::off_t,
    reply_length: libc::off_t,
    reply_sent: libc::off_t,
    total_sent: libc::off_t,
}

#[derive(Debug, PartialEq)]
enum ConnectionState {
    ReceiveRequest,
    SendHeader,
    SendReply,
    Done,
}

#[derive(Debug, PartialEq)]
enum ConnectionReplyType {
    Generated,
    FromFile,
}

type ForwardMap = HashMap<String, String>;

// TODO: Include this as a file.
const DEFAULT_EXTENSIONS_MAP: &'static [&'static str] = &[
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

const DEFAULT_MIME_TYPE: &str = "application/octet-stream";

impl MimeMap {
    /// Create MimeMap using the default extension map.
    fn parse_default_extension_map() -> MimeMap {
        let mut mime_map = MimeMap {
            mimetypes: HashMap::new(),
            default_mimetype: DEFAULT_MIME_TYPE.to_string(),
        };
        for line in DEFAULT_EXTENSIONS_MAP {
            mime_map.add_mimetype_line(line);
        }
        mime_map
    }

    /// Add extension map from a file.
    fn parse_extension_map_file(&mut self, filename: &OsStr) {
        let file = File::open(filename)
            .unwrap_or_else(|e| abort!("failed to open {}: {}", filename.to_string_lossy(), e));
        for line in std::io::BufReader::new(file).lines() {
            let line = line
                .unwrap_or_else(|e| abort!("failed to read {}: {}", filename.to_string_lossy(), e));
            self.add_mimetype_line(&line);
        }
    }

    /// Add line from an extension map.
    fn add_mimetype_line(&mut self, line: &str) {
        let mut fields = line
            .split(|c| matches!(c, ' ' | '\t'))
            .filter(|field| field.len() > 0);
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

/// RFC1123 formatted date.
struct HttpDate(libc::time_t);

impl std::fmt::Display for HttpDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let datetime = Utc.timestamp(self.0, 0);
        write!(f, "{}", datetime.format("%a, %d %b %Y %H:%M:%S GMT"))
    }
}

/// Common Log Format (CLF) formatted date in local timezone.
struct ClfDate(libc::time_t);

impl std::fmt::Display for ClfDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let datetime = Local.timestamp(self.0, 0);
        write!(f, "{}", datetime.format("[%d/%b/%Y:%H:%M:%S %z]"))
    }
}

/// "Generated by" string.
struct GeneratedOn<'a>(&'a Server);

impl<'a> std::fmt::Display for GeneratedOn<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let date = HttpDate(self.0.now);
        if self.0.want_server_id {
            write!(
                f,
                "Generated by {}/{} on {}\n",
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
/// Returns None if the URL is invalid/unsafe.
fn make_safe_url(url: &str) -> Option<String> {
    // TODO: Make this work in-place again?
    let mut url = url.as_bytes().to_vec();

    // URLs not starting with a slash are illegal.
    if !url.starts_with(&[b'/']) {
        return None;
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
                    return None;
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

    Some(String::from_utf8(url).unwrap())
}

/// Encode string to be an RFC3986-compliant URL part.
struct UrlEncoded<'a>(&'a str);

impl<'a> std::fmt::Display for UrlEncoded<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for c in self.0.chars() {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
                write!(f, "{}", c)?;
            } else {
                let mut buf = [0; 4];
                c.encode_utf8(&mut buf);
                for i in 0..c.len_utf8() {
                    write!(f, "%{:02X}", buf[i])?;
                }
            }
        }
        Ok(())
    }
}

/// Decode URL by converting %XX (where XX are hexadecimal digits) to the character it represents.
struct UrlDecoded<'a>(&'a str);

impl<'a> std::fmt::Display for UrlDecoded<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = self.0.as_bytes();
        let mut decoded = Vec::with_capacity(url.len());
        let mut i = 0;
        while i < url.len() {
            let c = url[i];
            assert!(c != 0);
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
        // TODO: Handle invalid UTF-8 sequences.
        write!(f, "{}", String::from_utf8(decoded).unwrap())
    }
}

/// Convert hex digit to integer.
fn hex_to_digit(hex: u8) -> u8 {
    if hex >= b'A' && hex <= b'F' {
        hex - b'A' + 10
    } else if hex >= b'a' && hex <= b'f' {
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

/// Parses a single HTTP request field.  Returns string from end of [field] to
/// first \r, \n or end of request string.  Returns NULL if [field] can't be
/// matched.
///
/// You need to remember to deallocate the result.
/// example: parse_field(conn, "Referer: ");
fn parse_field(conn: &Connection, field: &str) -> Option<String> {
    // TODO: Header names should be case-insensitive.
    // TODO: Parse the request instead of naively searching for the header name.
    let field_start_pod = match find(field.as_bytes(), &conn.request) {
        Some(field_start_pod) => field_start_pod,
        None => return None,
    };

    let value_start_pos = field_start_pod + field.as_bytes().len();
    let mut value_end_pos = 0;
    for i in value_start_pos..conn.request.len() {
        value_end_pos = i;
        let c = conn.request[i];
        if matches!(c, b'\r' | b'\n') {
            break;
        }
    }

    let value = &conn.request[value_start_pos..value_end_pos];
    Some(String::from_utf8(value.to_vec()).unwrap())
}

/// Return index of first occurrence of `needle` in `haystack`.
fn find(needle: &[u8], haystack: &[u8]) -> Option<usize> {
    for i in 0..haystack.len() {
        if haystack[i..].starts_with(needle) {
            return Some(i);
        }
    }
    return None;
}

/// Parse a Range: field into range_begin and range_end. Only handles the first range if a list is
/// given. Sets range_{begin,end}_given to 1 if either part of the range is given.
fn parse_range_field(conn: &mut Connection) {
    let range = match parse_field(conn, "Range: bytes=") {
        Some(range) => range,
        None => return,
    };

    // Valid because parse_field returns CString::into_raw
    let remaining = range.as_bytes();

    // parse number up to hyphen
    let (range_begin, remaining) = parse_offset(remaining);

    // there must be a hyphen here
    if remaining.len() == 0 || remaining[0] != b'-' {
        return;
    }
    let remaining = &remaining[1..];

    if let Some(range_begin) = range_begin {
        conn.range_begin_given = 1;
        conn.range_begin = range_begin;
    }

    // parse number after hyphen
    let (range_end, remaining) = parse_offset(remaining);

    // must be end of string or a list to be valid
    if remaining.len() > 0 && remaining[0] != b',' {
        return;
    }

    if let Some(range_end) = range_end {
        conn.range_end_given = 1;
        conn.range_end = range_end;
    }
}

fn parse_offset(data: &[u8]) -> (Option<libc::off_t>, &[u8]) {
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
    errcode: u16,
    errname: &str,
    reason: &str,
) {
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
        GeneratedOn(server),
    );
    conn.reply_length = reply.as_bytes().len() as libc::off_t;
    conn.reply = Some(reply);

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
        HttpDate(server.now),
        server.server_hdr,
        server.keep_alive_header(conn.conn_close),
        conn.reply_length,
        if server.auth_key.is_some() {
            "WWW-Authenticate: Basic realm=\"User Visible Realm\"\r\n"
        } else {
            ""
        }
    );
    conn.header = Some(headers);
    conn.reply_type = ConnectionReplyType::Generated;
    conn.http_code = errcode;
    conn.reply_start = 0; // Reset in case the request set a range.
}

/// A redirect reply.
fn redirect(server: &Server, conn: &mut Connection, location: &str) {
    let reply = format!(
        "<html><head><title>301 Moved Permanently</title></head><body>\n\
        <h1>Moved Permanently</h1>\n\
        Moved to: <a href=\"{}\">{}</a>\n\
        <hr>\n\
        {}\
        </body></html>\n",
        location,
        location,
        GeneratedOn(server),
    );
    conn.reply_length = reply.as_bytes().len() as libc::off_t;
    conn.reply = Some(reply);

    let headers = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
        Date: {}\r\n\
        {}\
        Location: {}\r\n\
        {}\
        Content-Length: {}\r\n\
        Content-Type: text/html; charset=UTF-8\r\n\
        \r\n",
        HttpDate(server.now),
        server.server_hdr,
        location,
        server.keep_alive_header(conn.conn_close),
        conn.reply_length,
    );
    conn.header = Some(headers);
    conn.reply_type = ConnectionReplyType::Generated;
    conn.http_code = 301;
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

        write!(f, "<a href=\"..\">..</a>/\n")?;

        for dir_entry in &self.0 {
            let metadata = match dir_entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            let name = dir_entry.file_name();
            write!(
                f,
                "<a href=\"{}\">{}</a>",
                UrlEncoded(&name.to_string_lossy()),
                name.to_string_lossy()
            )?;
            if metadata.is_dir() {
                write!(f, "/\n")?;
            } else {
                let num_spaces = max_len - name.len();
                for _ in 0..num_spaces {
                    write!(f, " ")?;
                }
                write!(f, "{:10}\n", metadata.len())?;
            }
        }
        Ok(())
    }
}

/// A directory listing reply.
fn generate_dir_listing(server: &Server, conn: &mut Connection, path: &str, decoded_url: &str) {
    let mut entries: Vec<_> = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) => {
            let reason = format!("Couldn't list directory: {}", e);
            default_reply(server, conn, 500, "Internal Server Error", &reason);
            return;
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
        GeneratedOn(server),
    );
    conn.reply_length = reply.as_bytes().len() as libc::off_t;
    conn.reply = Some(reply);

    let headers = format!(
        "HTTP/1.1 200 OK\r\n\
        Date: {}\r\n\
        {}\
        Accept-Ranges: bytes\r\n\
        {}\
        Content-Length: {}\r\n\
        Content-Type: text/html; charset=UTF-8\r\n\
        \r\n",
        HttpDate(server.now),
        server.server_hdr,
        server.keep_alive_header(conn.conn_close),
        conn.reply_length,
    );
    conn.header = Some(headers);
    conn.reply_type = ConnectionReplyType::Generated;
    conn.http_code = 200;
}

/// Return true if file exists.
fn file_exists(path: &str) -> bool {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        _ => true,
    }
}

/// A not modified reply.
fn not_modified(server: &Server, conn: &mut Connection) {
    let headers = format!(
        "HTTP/1.1 304 Not Modified\r\n\
        Date: {}\r\n\
        {}\
        Accept-Ranges: bytes\r\n\
        {}\
        \r\n",
        HttpDate(server.now),
        server.server_hdr,
        server.keep_alive_header(conn.conn_close),
    );
    conn.header = Some(headers);
    conn.http_code = 304;
    conn.header_only = true;
    conn.reply_length = 0;
}

/// Get URL to forward to based on host header, if any.
fn get_forward_to_url<'a>(server: &'a Server, conn: &mut Connection) -> Option<&'a str> {
    if !server.forward_map.is_empty() {
        let host = parse_field(conn, "Host: ");
        if let Some(target) = host.and_then(move |host| server.forward_map.get(&host)) {
            return Some(target);
        }
    }
    server.forward_all_url.as_deref()
}

/// Return range based on header values and file length.
fn get_range(conn: &Connection, file_len: i64) -> Option<(i64, i64)> {
    if conn.range_begin_given > 0 || conn.range_end_given > 0 {
        let mut to;
        let mut from;
        if conn.range_begin_given > 0 && conn.range_end_given > 0 {
            // 100-200
            from = conn.range_begin;
            to = conn.range_end;

            // clamp end to filestat.st_size-1
            if to > file_len {
                to = file_len - 1;
            }
        } else if conn.range_begin_given > 0 && conn.range_end_given == 0 {
            // 100- :: yields 100 to end
            from = conn.range_begin;
            to = file_len - 1;
        } else if conn.range_begin_given == 0 && conn.range_end_given > 0 {
            // -200 :: yields last 200
            to = file_len - 1;
            from = to - conn.range_end + 1;

            // clamp start
            if from < 0 {
                from = 0;
            }
        } else {
            abort!("internal error - from/to mismatch");
        }
        Some((to, from))
    } else {
        None
    }
}

/// Process a GET/HEAD request.
fn process_get(server: &Server, conn: &mut Connection) {
    // strip query params
    let url = conn.url.as_ref().unwrap();
    let stripped_url = url.splitn(2, '?').next().unwrap().to_string();

    // work out path of file being requested
    let decoded_url = UrlDecoded(&stripped_url).to_string();

    // Make sure URL is safe
    let decoded_url = match make_safe_url(&decoded_url) {
        Some(decoded_url) => decoded_url,
        None => {
            let reason = format!("You requested an invalid URL.");
            default_reply(server, conn, 400, "Bad Request", &reason);
            return;
        }
    };

    // test the host against web forward options
    if let Some(forward_to_url) = get_forward_to_url(server, conn) {
        let redirect_url = format!("{}{}", forward_to_url, decoded_url);
        redirect(server, conn, &redirect_url);
        return;
    }

    let target; // path to the file we're going to return
    let mimetype; // the mimetype for that file

    // does it end in a slash? serve up url/index_name
    if decoded_url.ends_with('/') {
        // does an index exist?
        target = format!("{}{}{}", server.wwwroot, decoded_url, server.index_name);
        if !file_exists(&target) {
            if server.no_listing {
                // Return 404 instead of 403 to make --no-listing indistinguishable from the
                // directory not existing. i.e.: Don't leak information.
                let reason = "The URL you requested was not found.";
                default_reply(server, conn, 404, "Not Found", &reason);
                return;
            }
            // return directory listing
            let target = format!("{}{}", server.wwwroot, decoded_url);
            generate_dir_listing(server, conn, &target, &decoded_url);
            return;
        } else {
            mimetype = server.mime_map.url_content_type(&server.index_name);
        }
    } else {
        target = format!("{}{}", server.wwwroot, decoded_url);
        mimetype = server.mime_map.url_content_type(&decoded_url);
    }

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(target)
    {
        Ok(file) => file,
        Err(e) => {
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
            default_reply(server, conn, errcode, errname, &reason);
            return;
        }
    };

    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(e) => {
            let reason = format!("fstat() failed: {}.", e);
            default_reply(server, conn, 500, "Internal Server Error", &reason);
            return;
        }
    };

    if metadata.is_dir() {
        let url = format!("{}/", conn.url.as_ref().unwrap());
        redirect(server, conn, &url);
        return;
    } else if !metadata.is_file() {
        // TODO: Add test coverage
        let reason = "Not a regular file.";
        default_reply(server, conn, 403, "Forbidden", &reason);
        return;
    }

    conn.reply_fd = Some(file);
    conn.reply_type = ConnectionReplyType::FromFile;
    let lastmod = metadata
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // handle If-Modified-Since
    if let Some(if_mod_since) = parse_field(conn, "If-Modified-Since: ") {
        if HttpDate(lastmod.try_into().unwrap()).to_string() == if_mod_since {
            not_modified(server, conn);
            return;
        }
    }

    // handle Range
    if let Some((to, from)) = get_range(&conn, metadata.len() as i64) {
        if from >= metadata.len() as i64 {
            let errname = "Requested Range Not Satisfiable";
            let reason = format!("You requested a range outside of the file.");
            default_reply(server, conn, 416, errname, &reason);
            return;
        }

        if to < from {
            let errname = "Requested Range Not Satisfiable";
            let reason = format!("You requested a backward range.");
            default_reply(server, conn, 416, errname, &reason);
            return;
        }

        conn.reply_start = from;
        conn.reply_length = to - from + 1;
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
            HttpDate(server.now),
            server.server_hdr,
            server.keep_alive_header(conn.conn_close),
            conn.reply_length,
            from,
            to,
            metadata.len(),
            mimetype,
            HttpDate(lastmod.try_into().unwrap())
        );
        conn.header = Some(headers);
        conn.http_code = 206;
        return;
    }

    conn.reply_length = metadata.len().try_into().unwrap();

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
        HttpDate(server.now),
        server.server_hdr,
        server.keep_alive_header(conn.conn_close),
        conn.reply_length,
        mimetype,
        HttpDate(lastmod.try_into().unwrap())
    );
    conn.header = Some(headers);
    conn.http_code = 200;
}

/// Parse an HTTP request like "GET / HTTP/1.1" to get the method (GET), the url (/), the referer
/// (if given) and the user-agent (if given). Remember to deallocate all these buffers. The method
/// will be returned in uppercase.
fn parse_request(server: &Server, conn: &mut Connection) -> bool {
    let request = std::str::from_utf8(&conn.request).unwrap();
    let mut lines = request.split(|c| matches!(c, '\r' | '\n'));
    let mut request_line = lines.next().unwrap().split(' ');

    // parse method
    if let Some(method) = request_line.next() {
        conn.method = Some(method.to_uppercase())
    } else {
        return false;
    }

    // parse URL
    if let Some(url) = request_line.next() {
        conn.url = Some(url.to_string());
    } else {
        return false;
    }

    // parse protocol to determine conn.close
    if let Some(protocol) = request_line.next() {
        if protocol.to_uppercase() == "HTTP/1.1" {
            conn.conn_close = false;
        }
    }

    // parse connection header
    if let Some(connection) = parse_field(conn, "Connection: ") {
        let connection = connection.to_lowercase();
        if connection == "close" {
            conn.conn_close = true;
        } else if connection == "keep-alive" {
            conn.conn_close = false;
        }
    }

    // cmdline flag can be used to deny keep-alive
    if !server.want_keepalive {
        conn.conn_close = true;
    }

    // parse important fields
    conn.referer = parse_field(conn, "Referer: ");
    conn.user_agent = parse_field(conn, "User-Agent: ");
    conn.authorization = parse_field(conn, "Authorization: ");
    parse_range_field(conn);

    true
}

/// Process a request: build the header and reply, advance state.
fn process_request(server: &mut Server, conn: &mut Connection) {
    server.num_requests += 1;

    let result = parse_request(server, conn);

    if !result {
        let reason = "You sent a request that the server couldn't understand.";
        default_reply(server, conn, 400, "Bad Request", reason);
    } else if server.auth_key.is_some()
        && (conn.authorization.is_none()
            || conn.authorization.as_deref() != server.auth_key.as_deref())
    {
        let reason = "Access denied due to invalid credentials.";
        default_reply(server, conn, 401, "Unauthorized", reason);
    } else if conn.method.as_deref().unwrap() == "GET" {
        process_get(server, conn);
    } else if conn.method.as_deref().unwrap() == "HEAD" {
        process_get(server, conn);
        conn.header_only = true;
    } else {
        let reason = "The method you specified is not implemented.";
        default_reply(server, conn, 501, "Not Implemented", reason);
    }

    // advance state
    conn.state = ConnectionState::SendHeader;

    // request not needed anymore
    conn.request = Vec::new();
}

/// Send chunk on socket <s> from FILE *fp, starting at <ofs> and of size <size>.  Use sendfile()
/// if possible since it's zero-copy on some platforms. Returns the number of bytes sent, 0 on
/// closure, -1 if send() failed, -2 if read error.
fn send_from_file(
    s: libc::c_int,
    fd: libc::c_int,
    mut ofs: libc::off_t,
    size: libc::size_t,
) -> nix::Result<usize> {
    // Limit truly ridiculous (LARGEFILE) requests.
    let size = min(size, 1 << 20);
    // TODO: Implement fallback for platforms without sendfile.
    sendfile(s, fd, Some(&mut ofs), size)
}

/// Sending reply.
fn poll_send_reply(server: &mut Server, conn: &mut Connection) {
    assert!(conn.state == ConnectionState::SendReply);
    assert!(!conn.header_only);
    assert!(conn.reply_length >= conn.reply_sent);

    // TODO: off_t can be wider than size_t?
    let send_len: libc::off_t = conn.reply_length - conn.reply_sent;

    let sent;
    if conn.reply_type == ConnectionReplyType::Generated {
        assert!(conn.reply.is_some());
        let start = usize::try_from(conn.reply_start + conn.reply_sent).unwrap();
        let buf = &conn.reply.as_ref().unwrap().as_bytes()
            [start..start + usize::try_from(send_len).unwrap()];
        sent = socket::send(
            conn.socket.as_ref().unwrap().as_raw_fd(),
            buf,
            socket::MsgFlags::empty(),
        );
    } else {
        sent = send_from_file(
            conn.socket.as_ref().unwrap().as_raw_fd(),
            conn.reply_fd.as_ref().unwrap().as_raw_fd(),
            conn.reply_start + conn.reply_sent,
            send_len.try_into().unwrap(),
        );
    }
    conn.last_active = server.now;
    let sent = match sent {
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
    conn.reply_sent += libc::off_t::try_from(sent).unwrap();
    conn.total_sent += libc::off_t::try_from(sent).unwrap();
    server.total_out += u64::try_from(sent).unwrap();

    // check if we're done sending
    if conn.reply_sent == conn.reply_length {
        conn.state = ConnectionState::Done;
    }
}

/// Sending header. Assumes conn->header is not NULL.
fn poll_send_header(server: &mut Server, conn: &mut Connection) {
    assert_eq!(conn.state, ConnectionState::SendHeader);

    let header = conn.header.as_ref().unwrap().as_bytes();

    conn.last_active = server.now;

    let sent = match socket::send(
        conn.socket.as_ref().unwrap().as_raw_fd(),
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
    conn.total_sent += libc::off_t::try_from(sent).unwrap();
    server.total_out += u64::try_from(sent).unwrap();

    // check if we're done sending header
    if conn.header_sent == header.len() {
        if conn.header_only {
            conn.state = ConnectionState::Done;
        } else {
            conn.state = ConnectionState::SendReply;
            // go straight on to body, don't go through another iteration of the select() loop
            poll_send_reply(server, conn);
        }
    }
}

// To prevent a malformed request from eating up too much memory, die once the request exceeds this
// many bytes:
const MAX_REQUEST_LENGTH: usize = 4000;

/// Receiving request.
fn poll_recv_request(server: &mut Server, conn: &mut Connection) {
    assert_eq!(conn.state, ConnectionState::ReceiveRequest);
    // TODO: Write directly to the request buffer
    let mut buf = [0; 1 << 15];
    let recvd = u64::try_from(
        match socket::recv(
            conn.socket.as_ref().unwrap().as_raw_fd(),
            &mut buf,
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
        },
    )
    .unwrap();
    conn.last_active = server.now;

    // append to conn.request
    assert!(recvd > 0);
    conn.request.extend(&buf[..recvd.try_into().unwrap()]);
    server.total_in += recvd;

    // die if it's too large, or process request if we have all of it
    // TODO: Handle HTTP pipelined requests
    if conn.request.len() > MAX_REQUEST_LENGTH {
        let reason = "Your request was dropped because it was too long.";
        default_reply(server, conn, 413, "Request Entity Too Large", reason);
        conn.state = ConnectionState::SendHeader;
    } else if conn.request.len() >= 2
        && &conn.request[conn.request.len() - 2..conn.request.len()] == b"\n\n"
    {
        process_request(server, conn);
    } else if conn.request.len() >= 4
        && &conn.request[conn.request.len() - 4..conn.request.len()] == b"\r\n\r\n"
    {
        process_request(server, conn);
    }

    // if we've moved on to the next state, try to send right away, instead of going through
    // another iteration of the select() loop.
    if conn.state == ConnectionState::SendHeader {
        poll_send_header(server, conn);
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
                for i in 0..c.len_utf8() {
                    write!(f, "%{:02X}", buf[i])?;
                }
            } else {
                write!(f, "{}", c)?;
            }
        }
        Ok(())
    }
}

/// Add a connection's details to the logfile.
fn log_connection(server: &mut Server, conn: &Connection) {
    if conn.http_code == 0 {
        return; // invalid - died in request
    }
    let method = match &conn.method {
        Some(method) => method,
        // invalid - didn't parse - maybe too long
        None => return,
    };
    let message = format!(
        "{} - - {} \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\"\n",
        conn.client,
        ClfDate(server.now),
        LogEncoded(method),
        LogEncoded(conn.url.as_ref().unwrap()),
        conn.http_code,
        conn.total_sent,
        LogEncoded(conn.referer.as_deref().unwrap_or("")),
        LogEncoded(conn.user_agent.as_deref().unwrap_or(""))
    );
    server
        .log_sink
        .log(&message)
        .expect("failed to write log message");
}

/// Log a connection, then cleanly deallocate its internals.
fn free_connection(server: &mut Server, conn: &mut Connection) {
    log_connection(server, conn);

    server.accepting = true; // Try to resume accepting if we ran out of sockets.
}

/// Recycle a finished connection for HTTP/1.1 Keep-Alive.
fn recycle_connection(server: &mut Server, conn: &mut Connection) {
    free_connection(server, conn);

    // don't reset conn.socket or conn.client
    conn.request = Vec::new();
    conn.method = None;
    conn.url = None;
    conn.referer = None;
    conn.user_agent = None;
    conn.authorization = None;
    conn.range_begin = 0;
    conn.range_end = 0;
    conn.range_begin_given = 0;
    conn.range_end_given = 0;
    conn.header = None;
    conn.header_sent = 0;
    conn.header_only = false;
    conn.http_code = 0;
    conn.conn_close = true;
    conn.reply = None;
    conn.reply_fd = None;
    conn.reply_start = 0;
    conn.reply_length = 0;
    conn.reply_sent = 0;
    conn.total_sent = 0;

    conn.state = ConnectionState::ReceiveRequest; // ready for another
}

/// Allocate and initialize an empty connection.
fn new_connection(server: &Server, stream: TcpStream, client: IpAddr) -> Connection {
    Connection {
        socket: Some(stream),
        client,
        last_active: server.now,
        state: ConnectionState::ReceiveRequest,
        request: Vec::new(),
        method: None,
        url: None,
        referer: None,
        user_agent: None,
        authorization: None,
        range_begin: 0,
        range_end: 0,
        range_begin_given: 0,
        range_end_given: 0,
        header: None,
        header_sent: 0,
        header_only: false,
        http_code: 0,
        conn_close: true,
        reply_type: ConnectionReplyType::Generated,
        reply: None,
        reply_fd: None,
        reply_start: 0,
        reply_length: 0,
        reply_sent: 0,
        total_sent: 0,
    }
}

/// If a connection has been idle for more than timeout_secs, it will be marked as DONE and killed
/// off in httpd_poll().
fn poll_check_timeout(server: &Server, conn: &mut Connection) {
    if server.timeout_secs > 0 {
        if server.now - conn.last_active >= server.timeout_secs as i64 {
            conn.conn_close = true;
            conn.state = ConnectionState::Done;
        }
    }
}

/// Accept a connection from sockin and add it to the connection queue.
fn accept_connection(server: &mut Server, connections: &mut Vec<Connection>) {
    let fd = match socket::accept(server.sockin) {
        Ok(fd) => fd,
        Err(e) => {
            // Failed to accept, but try to keep serving existing connections.
            if e.as_errno() == Some(Errno::EMFILE) || e.as_errno() == Some(Errno::ENFILE) {
                server.accepting = false;
            }
            eprintln!("warning: accept() failed: {}", e);
            return;
        }
    };

    // `socket::accept` doesn't expose the peer address, so request it separately.
    let addr = match socket::getpeername(fd) {
        Ok(socket::SockAddr::Inet(addr)) => addr,
        Ok(_) => panic!("getpeername returned unexpected address type"),
        Err(e) => {
            eprintln!("warning: getpeername() failed: {}", e);
            return;
        }
    };

    let stream = unsafe { TcpStream::from_raw_fd(fd) };

    stream
        .set_nonblocking(true)
        .expect("set_nonblocking failed");

    // Allocate and initialize struct connection.
    let conn = new_connection(server, stream, addr.ip().to_std());

    connections.push(conn);
    let num_connections = connections.len();

    // Try to read straight away rather than going through another iteration of the select() loop.
    poll_recv_request(server, &mut connections[num_connections - 1]);
}

/// Main loop of the httpd - a select() and then delegation to accept connections, handle receiving
/// of requests, and sending of replies.
fn httpd_poll(server: &mut Server, connections: &mut Vec<Connection>) {
    let mut recv_set = FdSet::new();
    let mut send_set = FdSet::new();
    let mut timeout_required = false;

    if server.accepting {
        recv_set.insert(server.sockin);
    }

    for conn in connections.iter() {
        match conn.state {
            ConnectionState::Done => {}
            ConnectionState::ReceiveRequest => {
                recv_set.insert(conn.socket.as_ref().unwrap().as_raw_fd());
                timeout_required = true;
            }
            ConnectionState::SendHeader | ConnectionState::SendReply => {
                send_set.insert(conn.socket.as_ref().unwrap().as_raw_fd());
                timeout_required = true;
            }
        }
    }

    let mut timeout = Some(TimeVal::from(libc::timeval {
        tv_sec: server.timeout_secs as libc::time_t,
        tv_usec: 0,
    }))
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
    server.now = Utc::now().timestamp();

    // poll connections that select() says need attention
    if recv_set.contains(server.sockin) {
        accept_connection(server, connections);
    }
    let mut index = 0;
    while index < connections.len() {
        let conn = &mut connections[index];

        poll_check_timeout(server, conn);

        match conn.state {
            ConnectionState::ReceiveRequest => {
                if recv_set.contains(conn.socket.as_ref().unwrap().as_raw_fd()) {
                    poll_recv_request(server, conn);
                }
            }
            ConnectionState::SendHeader => {
                if send_set.contains(conn.socket.as_ref().unwrap().as_raw_fd()) {
                    poll_send_header(server, conn);
                }
            }
            ConnectionState::SendReply => {
                if send_set.contains(conn.socket.as_ref().unwrap().as_raw_fd()) {
                    poll_send_reply(server, conn);
                }
            }
            ConnectionState::Done => {
                // (handled later; ignore for now as it's a valid state)
            }
        };

        // Handling SEND_REPLY could have set the state to done.
        if conn.state == ConnectionState::Done {
            // clean out finished connection
            if conn.conn_close {
                free_connection(server, conn);
                connections.remove(index);
            } else {
                recycle_connection(server, conn);
                // and go right back to recv_request without going through select() again.
                poll_recv_request(server, conn);
                index += 1;
            }
        } else {
            index += 1;
        }
    }
}

fn listening_socket_addr(server: &Server) -> Result<SocketAddr, AddrParseError> {
    Ok(if server.inet6 {
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from_str(server.bindaddr.as_deref().unwrap_or("::"))?,
            server.bindport,
            0,
            0,
        ))
    } else {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str(server.bindaddr.as_deref().unwrap_or("0.0.0.0"))?,
            server.bindport,
        ))
    })
}

/// Initialize the sockin global. This is the socket that we accept connections from.
fn init_sockin(server: &mut Server) {
    let domain = match server.inet6 {
        false => socket::AddressFamily::Inet,
        true => socket::AddressFamily::Inet6,
    };

    server.sockin = match socket::socket(
        domain,
        socket::SockType::Stream,
        socket::SockFlag::empty(),
        socket::SockProtocol::Tcp,
    ) {
        Ok(sockin) => sockin,
        Err(e) => abort!(
            "failed to create listening socket: {}",
            e.as_errno().unwrap().desc()
        ),
    };

    // reuse address
    if let Err(e) = socket::setsockopt(server.sockin, socket::sockopt::ReuseAddr, &true) {
        abort!(
            "failed to set SO_REUSEADDR: {}",
            e.as_errno().unwrap().desc()
        );
    }

    let socket_addr = match listening_socket_addr(server) {
        Ok(socket_addr) => socket_addr,
        Err(_) => abort!("malformed --addr argument"),
    };

    if let Err(e) = socket::bind(
        server.sockin,
        &socket::SockAddr::Inet(socket::InetAddr::from_std(&socket_addr)),
    ) {
        abort!(
            "failed to bind port {}: {}",
            server.bindport,
            e.as_errno().unwrap().desc()
        );
    }

    println!("listening on: http://{}/", socket_addr);

    // listen on socket
    if let Err(e) = socket::listen(server.sockin, server.max_connections as usize) {
        abort!("failed to listen socket: {}", e.as_errno().unwrap().desc());
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use test_case::test_case;

    #[test_case(b"", "" ; "zero bytes")]
    #[test_case(b"M", "TQ==" ; "one byte")]
    #[test_case(b"Ma", "TWE=" ; "two bytes")]
    #[test_case(b"Man", "TWFu" ; "three bytes")]
    #[test_case(b"hello world", "aGVsbG8gd29ybGQ=" ; "many bytes")]
    fn base_64_encoded_works(data: &[u8], output: &str) {
        assert_eq!(Base64Encoded(data).to_string(), output);
    }

    #[test]
    fn url_encoded_works() {
        assert_eq!(
            UrlEncoded("escape(this)name\tcrab\u{1F980}").to_string(),
            "escape%28this%29name%09crab%F0%9F%A6%80"
        );
    }

    #[test]
    fn url_decoded_works() {
        assert_eq!(
            UrlDecoded("escape%28this%29name%09").to_string(),
            "escape(this)name\t"
        );
        assert_eq!(UrlDecoded("%F0%9F%A6%80").to_string(), "\u{1F980}");
    }

    #[test]
    fn html_escaped_works() {
        assert_eq!(
            HtmlEscaped("foo<>&'\"").to_string(),
            "foo&lt;&gt;&amp;&apos;&quot;"
        );
    }

    #[test]
    fn log_encoded_works() {
        assert_eq!(
            LogEncoded("some\"log\tcrab\u{1F980}").to_string(),
            "some%22log%09crab%F0%9F%A6%80"
        );
    }

    #[test]
    fn clf_date_works() {
        // contains system's local timezone
        assert!(ClfDate(1620965123).to_string().contains("May/2021"));
    }

    #[test]
    fn make_safe_url_works() {
        let test_cases = &[
            ("", None),
            ("/", Some("/")),
            ("/.", Some("/")),
            ("/./", Some("/")),
            ("/.d", Some("/.d")),
            ("//.d", Some("/.d")),
            ("/../", None),
            ("/abc", Some("/abc")),
            ("/abc/", Some("/abc/")),
            ("/abc/.", Some("/abc")),
            ("/abc/./", Some("/abc/")),
            ("/abc/..", Some("/")),
            ("/abc/../", Some("/")),
            ("/abc/../def", Some("/def")),
            ("/abc/../def/", Some("/def/")),
            ("/abc/../def/..", Some("/")),
            ("/abc/../def/../", Some("/")),
            ("/abc/../def/../../", None),
            ("/abc/../def/.././", Some("/")),
            ("/abc/../def/.././../", None),
            ("/a/b/c/../../d/", Some("/a/d/")),
            ("/a/b/../../../c", None),
            ("//a///b////c/////", Some("/a/b/c/")),
        ];
        for (url, expected) in test_cases {
            assert_eq!(make_safe_url(url), expected.map(|s| s.to_string()));
        }
    }
}
