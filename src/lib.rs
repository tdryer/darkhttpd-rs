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
/// dest string must be three times longer than src string.
#[no_mangle]
pub extern "C" fn urlencode(src: *const libc::c_char, dest: *mut libc::c_char) {
    assert!(!src.is_null());
    let src_len = unsafe { libc::strlen(src) };
    let src = unsafe { slice::from_raw_parts(src as *const libc::c_uchar, src_len) };
    assert!(!dest.is_null());
    let mut dest =
        unsafe { slice::from_raw_parts_mut(dest as *mut libc::c_uchar, src_len * 3 + 1) };

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
    assert!(!s.is_null());
    unsafe { CString::from_raw(s) };
}
