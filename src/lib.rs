use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::OsStr;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::BufRead;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::IntoRawFd;
use std::slice;
use std::sync::Mutex;

use chrono::{TimeZone, Utc};
use once_cell::sync::Lazy;

mod bindings;

/// Prints message to standard error and exits with code 1.
macro_rules! abort {
    ($($arg:tt)*) => ({
        eprint!("{}: ", env!("CARGO_PKG_NAME"));
        eprintln!($($arg)*);
        std::process::exit(1);
    })
}

// TODO: Use String instead of CString
// TODO: Remove these statics when we can propagate them instead.
static MIME_MAP: Lazy<Mutex<HashMap<CString, CString>>> = Lazy::new(|| {
    let mime_map = HashMap::new();
    Mutex::new(mime_map)
});
static KEEP_ALIVE_FIELD: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));

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

/// Adds contents of DEFAULT_EXTENSIONS_MAP to mime_map.
#[no_mangle]
pub extern "C" fn parse_default_extension_map() {
    for line in DEFAULT_EXTENSIONS_MAP {
        let line = unsafe { CString::from_vec_unchecked(line.as_bytes().to_vec()) };
        add_mimetype_line(&line);
    }
}

/// Adds contents of specified file to mime_map list.
#[no_mangle]
pub extern "C" fn parse_extension_map_file(filename: *const libc::c_char) {
    assert!(!filename.is_null());
    let filename = unsafe { CStr::from_ptr(filename) };
    let file = File::open(OsStr::from_bytes(filename.to_bytes()))
        .unwrap_or_else(|e| abort!("failed to open {}: {}", filename.to_string_lossy(), e));
    for line in std::io::BufReader::new(file).lines() {
        let line =
            line.unwrap_or_else(|e| abort!("failed to read {}: {}", filename.to_string_lossy(), e));
        let line = unsafe { CString::from_vec_unchecked(line.into_bytes()) };
        add_mimetype_line(&line);
    }
}

/// Retrieves a mimetype for a URL.
fn url_content_type(server: &bindings::server, url: &str) -> String {
    let default_mimetype = unsafe { CStr::from_ptr(server.default_mimetype) }
        .to_str()
        .unwrap();
    let extension = match url.rsplit('.').next() {
        Some(extension) => extension,
        None => return default_mimetype.to_string(),
    };
    match MIME_MAP
        .lock()
        .expect("failed to lock MIME_MAP")
        .get(&CString::new(extension).unwrap())
    {
        Some(mimetype) => mimetype.as_c_str().to_str().unwrap().to_string(),
        None => default_mimetype.to_string(),
    }
}

/// Parses a mimetype line and adds the parsed data to MIME_MAP.
fn add_mimetype_line(line: &CStr) {
    let mut fields = line
        .to_bytes()
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|slice| slice.len() > 0)
        .map(|field| unsafe { CString::from_vec_unchecked(field.to_vec()) });
    let mimetype = match fields.next() {
        Some(mimetype) => mimetype,
        None => return, // empty line
    };
    if mimetype.as_bytes()[0] == b'#' {
        return; // comment
    }
    for extension in fields {
        assert!(mimetype.as_bytes().len() > 1);
        assert!(extension.as_bytes().len() > 1);
        // TODO: Cases valgrind false-positives as "possibly lost" and "still reachable".
        MIME_MAP
            .lock()
            .expect("failed to lock MIME_MAP")
            .insert(extension, mimetype.clone());
    }
}

/// Set the keep alive field.
#[no_mangle]
pub extern "C" fn set_keep_alive_field(timeout_secs: libc::c_int) {
    let mut field = KEEP_ALIVE_FIELD
        .lock()
        .expect("failed to lock KEEP_ALIVE_FIELD");
    field.clear();
    field.push_str(&format!("Keep-Alive: timeout={}\r\n", timeout_secs));
}

/// Returns Connection or Keep-Alive header, depending on conn_close.
fn keep_alive(conn: &bindings::connection) -> String {
    // TODO: We've made the keep alive field caching pretty useless by cloning the string each
    // time. Return a reference once this can be a method?
    if conn.conn_close == 1 {
        "Connection: close\r\n".to_string()
    } else {
        KEEP_ALIVE_FIELD
            .lock()
            .expect("failed to lock KEEP_ALIVE_FIELD")
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

/// "Generated by" string.
struct GeneratedOn<'a>(&'a bindings::server);

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

/// Split string out of src with range [left:right-1].
#[no_mangle]
pub unsafe extern "C" fn split_string(
    src: *const libc::c_char,
    left: libc::size_t,
    right: libc::size_t,
) -> *mut libc::c_char {
    assert!(left <= right);
    assert!(left < libc::strlen(src)); // [left means must be smaller
    assert!(right <= libc::strlen(src)); // right) means can be equal or smaller

    let src = slice::from_raw_parts(src, right);
    let dest_len = right - left + 1;
    let dest = slice::from_raw_parts_mut(xmalloc(dest_len) as *mut libc::c_char, dest_len);
    dest[..right - left].copy_from_slice(&src[left..]);
    dest[dest_len - 1] = 0;
    dest.as_mut_ptr()
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
    dst_index = std::cmp::max(dst_index, 1);
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
                    write!(f, "%{:02x}", buf[i])?;
                }
            }
        }
        Ok(())
    }
}

// TODO: No longer called from C
/// Decode URL by converting %XX (where XX are hexadecimal digits) to the character it represents.
/// Don't forget to free the return value.
#[no_mangle]
pub extern "C" fn urldecode(url: *const libc::c_char) -> *mut libc::c_char {
    assert!(!url.is_null());
    let url = unsafe { slice::from_raw_parts(url as *const libc::c_uchar, libc::strlen(url)) };
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
    unsafe { CString::from_vec_unchecked(decoded).into_raw() }
}

struct UrlDecoded<'a>(&'a str);

impl<'a> std::fmt::Display for UrlDecoded<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: Rewrite this instead of calling urldecode.
        let s = CString::new(self.0).unwrap();
        let decoded = unsafe { CString::from_raw(urldecode(s.as_c_str().as_ptr())) };
        write!(f, "{}", decoded.to_str().unwrap())
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

/// Free a string allocated by Rust.
#[no_mangle]
pub extern "C" fn free_rust_cstring(s: *mut libc::c_char) {
    // No operation is performed if the pointer is null (like `free`).
    if !s.is_null() {
        unsafe {
            CString::from_raw(s);
        }
    }
}

/// Parses a single HTTP request field.  Returns string from end of [field] to
/// first \r, \n or end of request string.  Returns NULL if [field] can't be
/// matched.
///
/// You need to remember to deallocate the result.
/// example: parse_field(conn, "Referer: ");
#[no_mangle]
pub extern "C" fn parse_field(
    conn: *const bindings::connection,
    field: *const libc::c_char,
) -> *mut libc::c_char {
    let conn = unsafe { conn.as_ref().unwrap() };
    assert!(!conn.request.is_null());
    let request = unsafe { CStr::from_ptr(conn.request) };
    assert!(!field.is_null());
    let field = unsafe { CStr::from_ptr(field) };

    // TODO: Header names should be case-insensitive.
    // TODO: Parse the request instead of naively searching for the header name.
    let field_start_pod = match find(field.to_bytes(), request.to_bytes()) {
        Some(field_start_pod) => field_start_pod,
        None => return std::ptr::null_mut(),
    };

    let value_start_pos = field_start_pod + field.to_bytes().len();
    let mut value_end_pos = 0;
    for i in value_start_pos..request.to_bytes().len() {
        value_end_pos = i;
        let c = request.to_bytes()[i];
        if c == b'\r' || c == b'\n' {
            break;
        }
    }

    let value = &request.to_bytes()[value_start_pos..value_end_pos];
    unsafe { CString::from_vec_unchecked(value.to_vec()).into_raw() }
}

fn parse_field_2(conn: &bindings::connection, field: &str) -> Option<String> {
    // TODO: Rewrite this instead of calling parse_field.
    let field = CString::new(field).unwrap();
    let result = parse_field(conn, field.as_c_str().as_ptr());
    if result.is_null() {
        None
    } else {
        Some(unsafe { CString::from_raw(result) }.into_string().unwrap())
    }
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
#[no_mangle]
pub extern "C" fn parse_range_field(conn: *mut bindings::connection) {
    let field = CString::new("Range: bytes=").unwrap();
    let range = parse_field(conn, field.as_c_str().as_ptr());
    if range.is_null() {
        return;
    }
    // Valid because parse_field returns CString::into_raw
    let range = unsafe { CString::from_raw(range) };
    let remaining = range.as_bytes();

    // parse number up to hyphen
    let (range_begin, remaining) = parse_offset(remaining);

    // there must be a hyphen here
    if remaining.len() == 0 || remaining[0] != b'-' {
        return;
    }
    let remaining = &remaining[1..];

    let conn = unsafe { conn.as_mut().unwrap() };
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
#[no_mangle]
pub extern "C" fn default_reply_impl(
    server: *const bindings::server,
    conn: *mut bindings::connection,
    errcode: libc::c_int,
    errname: *const libc::c_char,
    reason: *const libc::c_char,
) {
    let server = unsafe { server.as_ref().expect("server pointer is null") };
    let conn = unsafe { conn.as_mut().expect("connection pointer is null") };
    assert!(!errname.is_null());
    let errname = unsafe { CStr::from_ptr(errname).to_str().unwrap() };
    assert!(!reason.is_null());
    let reason = unsafe { CStr::from_ptr(reason).to_str().unwrap() };

    default_reply(server, conn, errcode, errname, reason);
}

fn default_reply(
    server: &bindings::server,
    conn: &mut bindings::connection,
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
    conn.reply = reply.into_raw(); // TODO: freed by C

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
        keep_alive(conn),
        conn.reply_length,
        if !server.auth_key.is_null() {
            "WWW-Authenticate: Basic realm=\"User Visible Realm\"\r\n"
        } else {
            ""
        }
    );
    let headers = CString::new(headers).unwrap();
    conn.header_length = headers.as_bytes().len() as bindings::size_t;
    conn.header = headers.into_raw(); // TODO: freed by C
    conn.reply_type = bindings::connection_REPLY_GENERATED;
    conn.http_code = errcode;
    conn.reply_start = 0; // Reset in case the request set a range.
}

// TODO: No longer called from C
/// A redirect reply.
#[no_mangle]
pub extern "C" fn redirect_impl(
    server: *const bindings::server,
    conn: *mut bindings::connection,
    location: *const libc::c_char,
) {
    let server = unsafe { server.as_ref().expect("server pointer is null") };
    let conn = unsafe { conn.as_mut().expect("connection pointer is null") };
    assert!(!location.is_null());
    let location = unsafe { CStr::from_ptr(location).to_str().unwrap() };
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
    conn.reply = reply.into_raw(); // TODO: freed by C

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
        keep_alive(conn),
        conn.reply_length,
    );
    let headers = CString::new(headers).unwrap();
    conn.header_length = headers.as_bytes().len() as bindings::size_t;
    conn.header = headers.into_raw(); // TODO: freed by C

    conn.reply_type = bindings::connection_REPLY_GENERATED;
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

// TODO: No longer called from C
/// A directory listing reply.
#[no_mangle]
pub extern "C" fn generate_dir_listing(
    server: *const bindings::server,
    conn: *mut bindings::connection,
    path: *const libc::c_char,
    decoded_url: *const libc::c_char,
) {
    let server = unsafe { server.as_ref().expect("server pointer is null") };
    let conn = unsafe { conn.as_mut().expect("connection pointer is null") };
    assert!(!path.is_null());
    let path = unsafe { CStr::from_ptr(path).to_str().unwrap() };
    assert!(!decoded_url.is_null());
    let decoded_url = unsafe { CStr::from_ptr(decoded_url).to_str().unwrap() };
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
    conn.reply = reply.into_raw(); // TODO: freed by C

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
        keep_alive(conn),
        conn.reply_length,
    );
    let headers = CString::new(headers).unwrap();
    conn.header_length = headers.as_bytes().len() as bindings::size_t;
    conn.header = headers.into_raw(); // TODO: freed by C

    conn.reply_type = bindings::connection_REPLY_GENERATED;
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
fn not_modified(server: &bindings::server, conn: &mut bindings::connection) {
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
        keep_alive(conn),
    );
    let headers = CString::new(headers).unwrap();
    conn.header_length = headers.as_bytes().len() as bindings::size_t;
    conn.header = headers.into_raw(); // TODO: freed by C
    conn.http_code = 304;
    conn.header_only = 1;
    conn.reply_length = 0;
}

/// Get URL to forward to based on host header, if any.
fn get_forward_to_url(
    server: &bindings::server,
    conn: &mut bindings::connection,
) -> Option<&'static str> {
    let mut forward_to_url = None;
    if !server.forward_map.is_null() {
        if let Some(host) = parse_field_2(conn, "Host: ") {
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
fn get_range(conn: &bindings::connection, file_len: i64) -> Option<(i64, i64)> {
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
#[no_mangle]
pub extern "C" fn process_get(server: *const bindings::server, conn: *mut bindings::connection) {
    let server = unsafe { server.as_ref().expect("server pointer is null") };
    let conn = unsafe { conn.as_mut().expect("connection pointer is null") };
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
        let redirect_url = CString::new(format!("{}{}", forward_to_url, decoded_url)).unwrap();
        redirect_impl(server, conn, redirect_url.as_ptr());
        return;
    }

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
                // TODO: free decoded_url?
                return;
            }
            // return directory listing
            let target = CString::new(format!("{}{}", wwwroot, decoded_url)).unwrap();
            let decoded_url = CString::new(decoded_url).unwrap();
            generate_dir_listing(server, conn, target.as_ptr(), decoded_url.as_ptr());
            return;
        } else {
            let index_name = unsafe { CStr::from_ptr(server.index_name).to_str().unwrap() };
            mimetype = url_content_type(server, index_name);
        }
    } else {
        target = format!("{}{}", wwwroot, decoded_url);
        mimetype = url_content_type(server, &decoded_url);
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
        let url = CString::new(format!(
            "{}/",
            unsafe { CStr::from_ptr(conn.url) }.to_str().unwrap()
        ))
        .unwrap();
        redirect_impl(server, conn, url.as_ptr());
        return;
    } else if !metadata.is_file() {
        // TODO: Add test coverage
        let reason = "Not a regular file.";
        default_reply(server, conn, 403, "Forbidden", &reason);
        return;
    }

    conn.reply_fd = file.into_raw_fd();
    conn.reply_type = bindings::connection_REPLY_FROMFILE;
    let lastmod = metadata
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // handle If-Modified-Since
    if let Some(if_mod_since) = parse_field_2(conn, "If-Modified-Since: ") {
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
            keep_alive(conn),
            conn.reply_length,
            from,
            to,
            metadata.len(),
            mimetype,
            HttpDate(lastmod.try_into().unwrap())
        );
        let headers = CString::new(headers).unwrap();
        conn.header_length = headers.as_bytes().len() as bindings::size_t;
        conn.header = headers.into_raw(); // TODO: freed by C
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
        keep_alive(conn),
        conn.reply_length,
        mimetype,
        HttpDate(lastmod.try_into().unwrap())
    );
    let headers = CString::new(headers).unwrap();
    conn.header_length = headers.as_bytes().len() as bindings::size_t;
    conn.header = headers.into_raw(); // TODO: freed by C
    conn.http_code = 200;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn url_encoded_works() {
        assert_eq!(
            UrlEncoded("escape(this)name\t").to_string(),
            "escape%28this%29name%09"
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
