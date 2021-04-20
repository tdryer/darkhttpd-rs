use std::collections::HashMap;
use std::ffi::OsStr;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::BufRead;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::slice;
use std::sync::Mutex;

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

// TODO: Remove this global when we can propagate it instead.
static MIME_MAP: Lazy<Mutex<HashMap<CString, CString>>> = Lazy::new(|| {
    let mime_map = HashMap::new();
    Mutex::new(mime_map)
});

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

/// Retrieves a mimetype from the mime_map.
#[no_mangle]
pub extern "C" fn get_mimetype(extension: *const libc::c_char) -> *const libc::c_char {
    assert!(!extension.is_null());
    let extension = unsafe { CStr::from_ptr(extension) };
    match MIME_MAP
        .lock()
        .expect("failed to lock MIME_MAP")
        .get(extension)
    {
        Some(mimetype) => mimetype.as_ptr(),
        None => std::ptr::null(),
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

/// Resolve //, /./, and /../ in a URL, in-place.
///
/// Returns NULL if the URL is invalid/unsafe, or the original buffer if successful.
#[no_mangle]
pub extern "C" fn make_safe_url(url: *mut libc::c_char) -> *mut libc::c_char {
    assert!(!url.is_null());

    let url = unsafe { slice::from_raw_parts_mut(url, libc::strlen(url) + 1) };

    // URLs not starting with a slash are illegal.
    if !url.starts_with(&[b'/' as libc::c_char]) {
        return std::ptr::null_mut();
    }

    const SLASH: libc::c_char = b'/' as libc::c_char;
    const DOT: libc::c_char = b'.' as libc::c_char;

    let mut src_index = 0;
    let mut dst_index = 0;
    while src_index < url.len() {
        if url[src_index] == SLASH && url[src_index + 1] == SLASH {
            // skip slash
            src_index += 1;
        } else if url[src_index] == SLASH
            && url[src_index + 1] == DOT
            && (url[src_index + 2] == SLASH || url[src_index + 2] == 0)
        {
            // skip slash dot slash
            src_index += 2;
        } else if url[src_index] == SLASH
            && url[src_index + 1] == DOT
            && url[src_index + 2] == DOT
            && (url[src_index + 3] == SLASH || url[src_index + 3] == 0)
        {
            // skip slash dot dot slash
            src_index += 3;
            // overwrite previous component
            loop {
                if dst_index == 0 {
                    return std::ptr::null_mut();
                }
                dst_index -= 1;
                if url[dst_index] == SLASH {
                    break;
                }
            }
        } else {
            url[dst_index] = url[src_index];
            src_index += 1;
            dst_index += 1;
        }
    }

    // fix up null result
    if dst_index == 1 {
        url[0] = SLASH;
        url[1] = 0;
    }

    url.as_mut_ptr()
}

/// Is this an RFC3986 "unreserved character"?
fn is_unreserved(c: libc::c_uchar) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

/// Encode string to be an RFC3986-compliant URL part.
/// Don't forget to free the return value.
#[no_mangle]
pub extern "C" fn urlencode(src: *const libc::c_char) -> *mut libc::c_char {
    assert!(!src.is_null());
    let src_len = unsafe { libc::strlen(src) };
    let src = unsafe { slice::from_raw_parts(src as *const libc::c_uchar, src_len) };
    let mut dest = Vec::with_capacity(src.len());

    let hex = b"0123456789ABCDEF";
    for &c in src {
        if !is_unreserved(c) {
            dest.write_all(&[
                b'%',
                hex[((c >> 4) & 0xF) as usize],
                hex[(c & 0xF) as usize],
            ])
            .unwrap();
        } else {
            dest.write_all(&[c]).unwrap();
        }
    }
    dest.write_all(&[0]).unwrap();
    unsafe { CString::from_vec_unchecked(dest).into_raw() }
}

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
    // TODO: as_ref instead
    assert!(!conn.is_null());
    let conn = unsafe { *conn };
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
    let data = range.as_bytes();

    // parse number up to hyphen
    let range_begin_len = parse_digits(data);
    let range_begin: Option<libc::off_t> = std::str::from_utf8(&data[0..range_begin_len])
        .unwrap()
        .parse()
        .ok();
    let data = &data[range_begin_len..];

    // there must be a hyphen here
    if data.len() == 0 || data[0] != b'-' {
        return;
    }
    let data = &data[1..];

    let conn = unsafe { conn.as_mut().unwrap() };
    if let Some(range_begin) = range_begin {
        conn.range_begin_given = 1;
        conn.range_begin = range_begin;
    }

    // parse number after hyphen
    let range_end_len = parse_digits(data);
    let range_end: Option<libc::off_t> = std::str::from_utf8(&data[0..range_end_len])
        .unwrap()
        .parse()
        .ok();
    let data = &data[range_end_len..];

    // must be end of string or a list to be valid
    if data.len() > 0 && data[0] != b',' {
        return;
    }

    if let Some(range_end) = range_end {
        conn.range_end_given = 1;
        conn.range_end = range_end;
    }
}

fn parse_digits(data: &[u8]) -> usize {
    let mut digits_len = 0;
    while digits_len < data.len() && data[digits_len].is_ascii_digit() {
        digits_len += 1;
    }
    digits_len
}
