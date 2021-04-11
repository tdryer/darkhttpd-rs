use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::slice;
use std::sync::Mutex;

use once_cell::sync::Lazy;

// TODO: Remove this global when we can propagate it instead.
static MIME_MAP: Lazy<Mutex<HashMap<CString, CString>>> = Lazy::new(|| {
    let mime_map = HashMap::new();
    Mutex::new(mime_map)
});

/// Associates an extension with a mimetype in the mime_map. Entries are in unsorted order. Makes
/// copies of extension and mimetype strings.
#[no_mangle]
pub extern "C" fn add_mime_mapping(extension: *const libc::c_char, mimetype: *const libc::c_char) {
    assert!(!extension.is_null());
    let extension =
        unsafe { CString::from_vec_unchecked(CStr::from_ptr(extension).to_bytes().to_vec()) };
    assert!(extension.to_bytes().len() > 0);
    assert!(!mimetype.is_null());
    let mimetype =
        unsafe { CString::from_vec_unchecked(CStr::from_ptr(mimetype).to_bytes().to_vec()) };
    assert!(mimetype.to_bytes().len() > 0);
    MIME_MAP
        .lock()
        .expect("failed to lock MIME_MAP")
        .insert(extension, mimetype);
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

/// Prints message to standard error and exits with code 1.
macro_rules! abort {
    ($($arg:tt)*) => ({
        eprint!("{}: ", env!("CARGO_PKG_NAME"));
        eprintln!($($arg)*);
        std::process::exit(1);
    })
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
