use std::cmp::{max, min};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::BufRead;
use std::net::{IpAddr, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::ptr::null_mut;
use std::slice;

use chrono::{Local, TimeZone, Utc};
use nix::errno::Errno;
use nix::sys::select::{select, FdSet};
use nix::sys::sendfile::sendfile;
use nix::sys::socket;
use nix::sys::time::TimeVal;
use nix::unistd::close;

mod bindings;

use bindings::server as Server;

/// Prints message to standard error and exits with code 1.
macro_rules! abort {
    ($($arg:tt)*) => ({
        eprint!("{}: ", env!("CARGO_PKG_NAME"));
        eprintln!($($arg)*);
        std::process::exit(1);
    })
}

// TODO: Oxidize types
struct Connection {
    socket: RawFd,
    client: IpAddr,
    last_active: libc::time_t,
    state: ConnectionState,
    request: *mut ::std::os::raw::c_char,
    request_length: bindings::size_t,
    method: Option<String>,
    url: *mut ::std::os::raw::c_char,
    referer: Option<String>,
    user_agent: Option<String>,
    authorization: Option<String>,
    range_begin: libc::off_t,
    range_end: libc::off_t,
    range_begin_given: libc::off_t,
    range_end_given: libc::off_t,
    header: *mut ::std::os::raw::c_char,
    header_length: bindings::size_t,
    header_sent: bindings::size_t,
    header_only: bool,
    http_code: ::std::os::raw::c_int,
    conn_close: bool,
    reply_type: ConnectionReplyType,
    reply: *mut ::std::os::raw::c_char,
    reply_fd: ::std::os::raw::c_int,
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

struct MimeMap {
    mimetypes: HashMap<String, String>,
    default_mimetype: String,
}

impl MimeMap {
    /// Create MimeMap using the default extension map.
    fn parse_default_extension_map() -> MimeMap {
        let mut mime_map = MimeMap {
            mimetypes: HashMap::new(),
            default_mimetype: "application/octet-stream".to_string(),
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

#[no_mangle]
pub extern "C" fn set_default_mimetype(server: *mut Server, mimetype: *const libc::c_char) {
    let server = unsafe { server.as_mut().unwrap() };
    let mime_map = unsafe { (server.mime_map as *mut MimeMap).as_mut() }.unwrap();
    assert!(!mimetype.is_null());
    mime_map.default_mimetype = unsafe { CStr::from_ptr(mimetype) }
        .to_str()
        .unwrap()
        .to_string();
}

#[no_mangle]
pub extern "C" fn parse_default_extension_map(server: *mut Server) {
    let server = unsafe { server.as_mut().unwrap() };
    let mime_map = MimeMap::parse_default_extension_map();
    assert!(server.mime_map.is_null());
    // freed by `free_mime_map`
    server.mime_map = Box::into_raw(Box::new(mime_map)) as *mut libc::c_void;
}

#[no_mangle]
pub extern "C" fn free_mime_map(server: *mut Server) {
    let server = unsafe { server.as_mut().unwrap() };
    assert!(!server.mime_map.is_null());
    unsafe { Box::from_raw(server.mime_map as *mut MimeMap) };
}

#[no_mangle]
pub extern "C" fn parse_extension_map_file(server: *mut Server, filename: *const libc::c_char) {
    let server = unsafe { server.as_mut().unwrap() };
    assert!(!filename.is_null());
    let filename = OsStr::from_bytes(unsafe { CStr::from_ptr(filename) }.to_bytes());
    let mime_map = unsafe { (server.mime_map as *mut MimeMap).as_mut() }.unwrap();
    mime_map.parse_extension_map_file(filename);
}

/// Set the keep alive field.
#[no_mangle]
pub extern "C" fn set_keep_alive_field(server: *mut Server) {
    let server = unsafe { server.as_mut().unwrap() };
    assert!(server.keep_alive_field.is_null());
    let keep_alive = format!("Keep-Alive: timeout={}\r\n", server.timeout_secs);
    // freed by `free_keep_alive_field`
    server.keep_alive_field = Box::into_raw(Box::new(keep_alive)) as *mut libc::c_void;
}

/// Frees the keep alive field.
#[no_mangle]
pub extern "C" fn free_keep_alive_field(server: *mut Server) {
    let server = unsafe { server.as_mut().unwrap() };
    assert!(!server.keep_alive_field.is_null());
    unsafe { Box::from_raw(server.keep_alive_field as *mut String) };
}

/// Returns Connection or Keep-Alive header, depending on conn_close.
fn keep_alive(server: &Server, conn: &Connection) -> String {
    // TODO: We've made the keep alive field caching pretty useless by cloning the string each
    // time. Return a reference once this can be a method?
    if conn.conn_close {
        "Connection: close\r\n".to_string()
    } else {
        unsafe { (server.keep_alive_field as *const String).as_ref() }
            .expect("keep_alive_field is null")
            .clone()
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
        let pkgname = unsafe { CStr::from_ptr(self.0.pkgname).to_str().unwrap() };
        let date = HttpDate(self.0.now);
        if self.0.want_server_id == 1 {
            write!(f, "Generated by {} on {}\n", pkgname, date)?;
        }
        Ok(())
    }
}

/// malloc that dies if it can't allocate.
#[no_mangle]
pub unsafe extern "C" fn xmalloc(size: libc::size_t) -> *mut libc::c_void {
    let ptr = libc::malloc(size);
    if ptr.is_null() {
        abort!("can't allocate {} bytes", size)
    }
    ptr
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
#[no_mangle]
fn parse_field(conn: &Connection, field: &str) -> Option<String> {
    assert!(!conn.request.is_null());
    let request = unsafe { CStr::from_ptr(conn.request) };

    // TODO: Header names should be case-insensitive.
    // TODO: Parse the request instead of naively searching for the header name.
    let field_start_pod = match find(field.as_bytes(), request.to_bytes()) {
        Some(field_start_pod) => field_start_pod,
        None => return None,
    };

    let value_start_pos = field_start_pod + field.as_bytes().len();
    let mut value_end_pos = 0;
    for i in value_start_pos..request.to_bytes().len() {
        value_end_pos = i;
        let c = request.to_bytes()[i];
        if matches!(c, b'\r' | b'\n') {
            break;
        }
    }

    let value = &request.to_bytes()[value_start_pos..value_end_pos];
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
    errcode: i32,
    errname: &str,
    reason: &str,
) {
    assert!(!server.server_hdr.is_null());
    let server_hdr = unsafe { CStr::from_ptr(server.server_hdr).to_str().unwrap() };

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
    let reply = CString::new(reply).unwrap();
    conn.reply_length = reply.as_bytes().len() as libc::off_t;
    conn.reply = reply.into_raw();

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
        server_hdr,
        keep_alive(server, conn),
        conn.reply_length,
        if !server.auth_key.is_null() {
            "WWW-Authenticate: Basic realm=\"User Visible Realm\"\r\n"
        } else {
            ""
        }
    );
    let headers = CString::new(headers).unwrap();
    conn.header_length = headers.as_bytes().len() as bindings::size_t;
    conn.header = headers.into_raw();
    conn.reply_type = ConnectionReplyType::Generated;
    conn.http_code = errcode;
    conn.reply_start = 0; // Reset in case the request set a range.
}

/// A redirect reply.
fn redirect(server: &Server, conn: &mut Connection, location: &str) {
    assert!(!server.server_hdr.is_null());
    let server_hdr = unsafe { CStr::from_ptr(server.server_hdr).to_str().unwrap() };

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
    let reply = CString::new(reply).unwrap();
    conn.reply_length = reply.as_bytes().len() as libc::off_t;
    conn.reply = reply.into_raw();

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
        server_hdr,
        location,
        keep_alive(server, conn),
        conn.reply_length,
    );
    let headers = CString::new(headers).unwrap();
    conn.header_length = headers.as_bytes().len() as bindings::size_t;
    conn.header = headers.into_raw();
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
    assert!(!server.server_hdr.is_null());
    let server_hdr = unsafe { CStr::from_ptr(server.server_hdr).to_str().unwrap() };

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
    let reply = CString::new(reply).unwrap();
    conn.reply_length = reply.as_bytes().len() as libc::off_t;
    conn.reply = reply.into_raw();

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
        server_hdr,
        keep_alive(server, conn),
        conn.reply_length,
    );
    let headers = CString::new(headers).unwrap();
    conn.header_length = headers.as_bytes().len() as bindings::size_t;
    conn.header = headers.into_raw();
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
    let server_hdr = unsafe { CStr::from_ptr(server.server_hdr).to_str().unwrap() };

    let headers = format!(
        "HTTP/1.1 304 Not Modified\r\n\
        Date: {}\r\n\
        {}\
        Accept-Ranges: bytes\r\n\
        {}\
        \r\n",
        HttpDate(server.now),
        server_hdr,
        keep_alive(server, conn),
    );
    let headers = CString::new(headers).unwrap();
    conn.header_length = headers.as_bytes().len() as bindings::size_t;
    conn.header = headers.into_raw();
    conn.http_code = 304;
    conn.header_only = true;
    conn.reply_length = 0;
}

/// Get URL to forward to based on host header, if any.
fn get_forward_to_url(server: &Server, conn: &mut Connection) -> Option<&'static str> {
    let mut forward_to_url = None;
    if !server.forward_map.is_null() {
        if let Some(host) = parse_field(conn, "Host: ") {
            let forward_mappings = unsafe {
                slice::from_raw_parts(server.forward_map, server.forward_map_size as usize)
            };
            for forward_mapping in forward_mappings {
                let mapping_host = unsafe { CStr::from_ptr(forward_mapping.host) }
                    .to_str()
                    .unwrap();
                let mapping_target = unsafe { CStr::from_ptr(forward_mapping.target_url) }
                    .to_str()
                    .unwrap();
                if host == mapping_host {
                    forward_to_url = Some(mapping_target);
                    break;
                }
            }
        }
    }
    if forward_to_url.is_none() && !server.forward_all_url.is_null() {
        forward_to_url = Some(
            unsafe { CStr::from_ptr(server.forward_all_url) }
                .to_str()
                .unwrap(),
        );
    }
    forward_to_url
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
    let wwwroot = unsafe { CStr::from_ptr(server.wwwroot) }.to_str().unwrap();
    let index_name = unsafe { CStr::from_ptr(server.index_name) }
        .to_str()
        .unwrap();
    let server_hdr = unsafe { CStr::from_ptr(server.server_hdr).to_str().unwrap() };
    let url = unsafe { CStr::from_ptr(conn.url) }.to_str().unwrap();

    // strip query params
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

    let mime_map =
        unsafe { (server.mime_map as *const MimeMap).as_ref() }.expect("mime_map is null");

    let target; // path to the file we're going to return
    let mimetype; // the mimetype for that file

    // does it end in a slash? serve up url/index_name
    if decoded_url.ends_with('/') {
        // does an index exist?
        target = format!("{}{}{}", wwwroot, decoded_url, index_name);
        if !file_exists(&target) {
            if server.no_listing > 0 {
                // Return 404 instead of 403 to make --no-listing indistinguishable from the
                // directory not existing. i.e.: Don't leak information.
                let reason = "The URL you requested was not found.";
                default_reply(server, conn, 404, "Not Found", &reason);
                return;
            }
            // return directory listing
            let target = format!("{}{}", wwwroot, decoded_url);
            generate_dir_listing(server, conn, &target, &decoded_url);
            return;
        } else {
            let index_name = unsafe { CStr::from_ptr(server.index_name).to_str().unwrap() };
            mimetype = mime_map.url_content_type(index_name);
        }
    } else {
        target = format!("{}{}", wwwroot, decoded_url);
        mimetype = mime_map.url_content_type(&decoded_url);
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
        let url = format!("{}/", unsafe { CStr::from_ptr(conn.url) }.to_str().unwrap());
        redirect(server, conn, &url);
        return;
    } else if !metadata.is_file() {
        // TODO: Add test coverage
        let reason = "Not a regular file.";
        default_reply(server, conn, 403, "Forbidden", &reason);
        return;
    }

    conn.reply_fd = file.into_raw_fd();
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
            server_hdr,
            keep_alive(server, conn),
            conn.reply_length,
            from,
            to,
            metadata.len(),
            mimetype,
            HttpDate(lastmod.try_into().unwrap())
        );
        let headers = CString::new(headers).unwrap();
        conn.header_length = headers.as_bytes().len() as bindings::size_t;
        conn.header = headers.into_raw();
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
        server_hdr,
        keep_alive(server, conn),
        conn.reply_length,
        mimetype,
        HttpDate(lastmod.try_into().unwrap())
    );
    let headers = CString::new(headers).unwrap();
    conn.header_length = headers.as_bytes().len() as bindings::size_t;
    conn.header = headers.into_raw();
    conn.http_code = 200;
}

/// Parse an HTTP request like "GET / HTTP/1.1" to get the method (GET), the url (/), the referer
/// (if given) and the user-agent (if given). Remember to deallocate all these buffers. The method
/// will be returned in uppercase.
fn parse_request(server: &Server, conn: &mut Connection) -> bool {
    let request: &str = unsafe { CStr::from_ptr(conn.request) }.to_str().unwrap();
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
        let url = CString::new(url).unwrap();
        conn.url = url.into_raw();
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
    if server.want_keepalive == 0 {
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

    let auth_key = if server.auth_key.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(server.auth_key) }.to_str().unwrap())
    };

    if !result {
        let reason = "You sent a request that the server couldn't understand.";
        default_reply(server, conn, 400, "Bad Request", reason);
    } else if auth_key.is_some()
        && (conn.authorization.is_none() || conn.authorization.as_deref() != auth_key)
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

    /* request not needed anymore */
    unsafe { libc::free(conn.request as *mut libc::c_void) };
    conn.request = null_mut(); // important: don't free it again later
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
        assert!(!conn.reply.is_null());
        // TODO: Clean up type casts
        let reply = unsafe {
            std::slice::from_raw_parts(
                conn.reply as *const u8,
                conn.reply_length.try_into().unwrap(),
            )
        };
        let start = usize::try_from(conn.reply_start + conn.reply_sent).unwrap();
        let buf = &reply[start..start + usize::try_from(send_len).unwrap()];
        sent = socket::send(conn.socket, buf, socket::MsgFlags::empty());
    } else {
        sent = send_from_file(
            conn.socket,
            conn.reply_fd,
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

    assert!(!conn.header.is_null());
    let header = unsafe { CStr::from_ptr(conn.header) };
    assert_eq!(conn.header_length, header.to_bytes().len() as u64);

    conn.last_active = server.now;

    let sent = match socket::send(
        conn.socket,
        &header.to_bytes()
            [conn.header_sent as usize..conn.header_length as usize - conn.header_sent as usize],
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
    conn.header_sent += bindings::size_t::try_from(sent).unwrap();
    conn.total_sent += libc::off_t::try_from(sent).unwrap();
    server.total_out += u64::try_from(sent).unwrap();

    // check if we're done sending header
    if conn.header_sent == conn.header_length {
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
const MAX_REQUEST_LENGTH: u64 = 4000;

/// Receiving request.
fn poll_recv_request(server: &mut Server, conn: &mut Connection) {
    assert_eq!(conn.state, ConnectionState::ReceiveRequest);
    // TODO: Write directly to the request buffer
    let mut buf = [0; 1 << 15];
    let recvd = bindings::size_t::try_from(
        match socket::recv(conn.socket, &mut buf, socket::MsgFlags::empty()) {
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
    let new_request_length = usize::try_from(conn.request_length + recvd + 1).unwrap();
    conn.request =
        unsafe { libc::realloc(conn.request as *mut libc::c_void, new_request_length) as *mut i8 };
    if conn.request.is_null() {
        panic!("realloc failed");
    }
    let request =
        unsafe { std::slice::from_raw_parts_mut(conn.request as *mut u8, new_request_length) };
    request[conn.request_length.try_into().unwrap()
        ..usize::try_from(conn.request_length + recvd).unwrap()]
        .copy_from_slice(&buf[..recvd.try_into().unwrap()]);
    conn.request_length += recvd;
    request[usize::try_from(conn.request_length).unwrap()] = 0;
    server.total_in += recvd;

    // process request if we have all of it
    // TODO: Handle HTTP pipelined requests
    if request.len() > 2 && &request[request.len() - 1 - 2..request.len() - 1] == b"\n\n" {
        process_request(server, conn);
    } else if request.len() > 4 && &request[request.len() - 1 - 4..request.len() - 1] == b"\r\n\r\n"
    {
        process_request(server, conn);
    }

    // die if it's too large
    if conn.request_length > MAX_REQUEST_LENGTH {
        let reason = "Your request was dropped because it was too long.";
        default_reply(server, conn, 413, "Request Entity Too Large", reason);
        conn.state = ConnectionState::SendHeader;
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

fn str_from_ptr<'a>(ptr: *const libc::c_char) -> Option<&'a str> {
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(ptr) }.to_str().unwrap())
    }
}

/// Add a connection's details to the logfile.
fn log_connection(server: &Server, conn: &Connection) {
    if server.logfile.is_null() {
        return;
    }
    if conn.http_code == 0 {
        return; // invalid - died in request
    }
    let method = match &conn.method {
        Some(method) => method,
        // invalid - didn't parse - maybe too long
        None => return,
    };

    let url = str_from_ptr(conn.url).unwrap();

    let message = CString::new(format!(
        "{} - - {} \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\"\n",
        conn.client,
        ClfDate(server.now),
        LogEncoded(method),
        LogEncoded(url),
        conn.http_code,
        conn.total_sent,
        LogEncoded(conn.referer.as_deref().unwrap_or("")),
        LogEncoded(conn.user_agent.as_deref().unwrap_or(""))
    ))
    .unwrap();

    if server.syslog_enabled == 1 {
        unsafe {
            libc::syslog(libc::LOG_INFO, message.as_c_str().as_ptr());
        }
    } else {
        unsafe {
            libc::fprintf(
                server.logfile as *mut libc::FILE,
                message.as_c_str().as_ptr(),
            );
            libc::fflush(server.logfile as *mut libc::FILE);
        }
    }
}

/// Log a connection, then cleanly deallocate its internals.
fn free_connection(server: &mut Server, conn: &mut Connection) {
    log_connection(server, conn);

    if conn.socket != -1 {
        close(conn.socket).expect("close failed");
    }
    if !conn.request.is_null() {
        unsafe { libc::free(conn.request as *mut libc::c_void) };
    }
    if !conn.url.is_null() {
        unsafe { CString::from_raw(conn.url) };
    }
    if !conn.header.is_null() {
        unsafe { CString::from_raw(conn.header) };
    }
    if !conn.reply.is_null() {
        unsafe { CString::from_raw(conn.reply) };
    }
    if conn.reply_fd != -1 {
        close(conn.reply_fd).expect("close failed");
    }
    // If we ran out of sockets, try to resume accepting.
    server.accepting = 1;
}

/// Recycle a finished connection for HTTP/1.1 Keep-Alive.
fn recycle_connection(server: &mut Server, conn: &mut Connection) {
    let socket_tmp = conn.socket;
    conn.socket = -1; // so free_connection() doesn't close it
    free_connection(server, conn);
    conn.socket = socket_tmp;

    // don't reset conn->client
    conn.request = null_mut();
    conn.request_length = 0;
    conn.method = None;
    conn.url = null_mut();
    conn.referer = None;
    conn.user_agent = None;
    conn.authorization = None;
    conn.range_begin = 0;
    conn.range_end = 0;
    conn.range_begin_given = 0;
    conn.range_end_given = 0;
    conn.header = null_mut();
    conn.header_length = 0;
    conn.header_sent = 0;
    conn.header_only = false;
    conn.http_code = 0;
    conn.conn_close = true;
    conn.reply = null_mut();
    conn.reply_fd = -1;
    conn.reply_start = 0;
    conn.reply_length = 0;
    conn.reply_sent = 0;
    conn.total_sent = 0;

    conn.state = ConnectionState::ReceiveRequest; // ready for another
}

/// Allocate and initialize an empty connection.
fn new_connection(server: &Server, socket: RawFd, client: IpAddr) -> Connection {
    Connection {
        socket,
        client,
        last_active: server.now,
        state: ConnectionState::ReceiveRequest,
        request: null_mut(),
        request_length: 0,
        method: None,
        url: null_mut(),
        referer: None,
        user_agent: None,
        authorization: None,
        range_begin: 0,
        range_end: 0,
        range_begin_given: 0,
        range_end_given: 0,
        header: null_mut(),
        header_length: 0,
        header_sent: 0,
        header_only: false,
        http_code: 0,
        conn_close: true,
        reply_type: ConnectionReplyType::Generated,
        reply: null_mut(),
        reply_fd: -1,
        reply_start: 0,
        reply_length: 0,
        reply_sent: 0,
        total_sent: 0,
    }
}

/// Initialize connections list.
#[no_mangle]
pub extern "C" fn init_connections_list(server: *mut Server) {
    let server = unsafe { server.as_mut().expect("server pointer is null") };
    assert!(server.connections.is_null());
    let connections: Vec<Connection> = Vec::new();
    // freed by `free_connections_list`
    server.connections = Box::into_raw(Box::new(connections)) as *mut libc::c_void;
}

/// Free connections list.
#[no_mangle]
pub extern "C" fn free_connections_list(server: *mut Server) {
    let server = unsafe { server.as_mut().expect("server pointer is null") };
    assert!(!server.connections.is_null());
    let mut connections = unsafe { Box::from_raw(server.connections as *mut Vec<Connection>) };
    for mut conn in connections.drain(..) {
        free_connection(server, &mut conn); // logs connection and drops fields
    }
    server.connections = null_mut();
}

/// Remove connection by index.
fn remove_connection(server: &mut Server, index: libc::c_int) {
    let connections = unsafe {
        (server.connections as *mut Vec<Connection>)
            .as_mut()
            .expect("connections pointer is null")
    };
    assert!(
        (index as usize) < connections.len(),
        "invalid connection index"
    );
    connections.remove(index as usize);
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

/// Make the specified socket non-blocking.
fn nonblock_socket(sock: RawFd) {
    let stream = unsafe { TcpStream::from_raw_fd(sock) };
    stream
        .set_nonblocking(true)
        .expect("set_nonblocking failed");
    stream.into_raw_fd();
}

/// Accept a connection from sockin and add it to the connection queue.
fn accept_connection(server: &mut Server) {
    let fd = match socket::accept(server.sockin) {
        Ok(fd) => fd,
        Err(e) => {
            // Failed to accept, but try to keep serving existing connections.
            if e.as_errno() == Some(Errno::EMFILE) || e.as_errno() == Some(Errno::ENFILE) {
                server.accepting = 0;
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

    nonblock_socket(fd);

    // Allocate and initialize struct connection.
    let conn = new_connection(server, fd, addr.ip().to_std());

    let connections = unsafe {
        (server.connections as *mut Vec<Connection>)
            .as_mut()
            .expect("connections pointer is null")
    };
    connections.push(conn);
    let num_connections = connections.len();

    // Try to read straight away rather than going through another iteration of the select() loop.
    poll_recv_request(server, &mut connections[num_connections - 1]);
}

/// Main loop of the httpd - a select() and then delegation to accept connections, handle receiving
/// of requests, and sending of replies.
#[no_mangle]
pub extern "C" fn httpd_poll(server: *mut Server) {
    let server = unsafe { server.as_mut().expect("server pointer is null") };

    let mut recv_set = FdSet::new();
    let mut send_set = FdSet::new();
    let mut timeout_required = false;

    if server.accepting == 1 {
        recv_set.insert(server.sockin);
    }

    let connections = unsafe {
        (server.connections as *mut Vec<Connection>)
            .as_mut()
            .expect("connections pointer is null")
    };
    for conn in connections.iter() {
        match conn.state {
            ConnectionState::Done => {}
            ConnectionState::ReceiveRequest => {
                recv_set.insert(conn.socket);
                timeout_required = true;
            }
            ConnectionState::SendHeader | ConnectionState::SendReply => {
                send_set.insert(conn.socket);
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
        accept_connection(server);
    }
    let mut index = 0;
    while index < connections.len() {
        let conn = &mut connections[index];

        poll_check_timeout(server, conn);

        match conn.state {
            ConnectionState::ReceiveRequest => {
                if recv_set.contains(conn.socket) {
                    poll_recv_request(server, conn);
                }
            }
            ConnectionState::SendHeader => {
                if send_set.contains(conn.socket) {
                    poll_send_header(server, conn);
                }
            }
            ConnectionState::SendReply => {
                if send_set.contains(conn.socket) {
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
                free_connection(server, conn); // logs connection and drops fields
                remove_connection(server, index as libc::c_int); // drops connection
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

#[cfg(test)]
mod test {
    use super::*;

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
