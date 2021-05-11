use std::fs::File;
use std::fs::{set_permissions, Permissions};
use std::io;
use std::io::{Read, Write};
use std::io::{Seek, SeekFrom};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tempfile::NamedTempFile;
use test_case::test_case;

mod util;

use util::{Request, Server};

fn test_forward(args: &[&str], url: &str, host: &str, location: &str) {
    let server = Server::with_args(args);
    let response = server.send(Request::new(url).with_header("Host", host));
    assert_eq!(response.status(), "301 Moved Permanently");
    assert_eq!(response.header("Location"), Some(location));
    assert!(response.text().unwrap().contains(location));
}

const FORWARD_ARGS: &[&str] = &[
    "--forward",
    "example.com",
    "http://www.example.com",
    "--forward",
    "secure.example.com",
    "https://www.example.com/secure",
];

#[test]
fn forward_root() {
    test_forward(FORWARD_ARGS, "/", "example.com", "http://www.example.com/");
}

#[test]
fn forward_relative() {
    test_forward(
        FORWARD_ARGS,
        "/foo/bar",
        "secure.example.com",
        "https://www.example.com/secure/foo/bar",
    );
}

const FORWARD_ALL_ARGS: &[&str] = &[
    "--forward",
    "example.com",
    "http://www.example.com",
    "--forward-all",
    "http://catchall.example.com",
];

#[test]
fn forward_all_root() {
    test_forward(
        FORWARD_ALL_ARGS,
        "/",
        "not-example.com",
        "http://catchall.example.com/",
    );
}

#[test]
fn forward_all_relative() {
    test_forward(
        FORWARD_ALL_ARGS,
        "/foo/bar",
        "still-not.example.com",
        "http://catchall.example.com/foo/bar",
    );
}

fn test_server_id(args: &[&str], server_id: bool) {
    let server = Server::with_args(args);
    let response = server.send(Request::new("/"));
    assert_eq!(response.status(), "200 OK");
    assert_eq!(response.header("Server").is_some(), server_id);
    assert!(response.text().unwrap().contains("Generated by") == server_id);
}

#[test]
fn no_server_id() {
    test_server_id(&["--no-server-id"], false);
}

#[test]
fn server_id() {
    test_server_id(&[], true);
}

fn test_listing(args: &[&str], listing: bool) {
    let server = Server::with_args(args);
    let response = server.send(Request::new("/"));
    if listing {
        assert_eq!(response.status(), "200 OK");
    } else {
        assert_eq!(response.status(), "404 Not Found");
    }
}

#[test]
fn no_listing() {
    test_listing(&["--no-listing"], false);
}

#[test]
fn listing() {
    test_listing(&[], true);
}

fn test_auth(auth: Option<&str>, authorized: bool) {
    let args = &["--auth", "myuser:mypass"];
    let server = Server::with_args(args);
    let response = server.send(match auth {
        Some(auth) => Request::new("/").with_header("Authorization", auth),
        None => Request::new("/"),
    });
    if authorized {
        assert_eq!(response.status(), "200 OK");
    } else {
        assert_eq!(response.status(), "401 Unauthorized");
        assert_eq!(
            response.header("WWW-Authenticate"),
            Some("Basic realm=\"User Visible Realm\"")
        );
    }
}

#[test]
fn no_auth() {
    test_auth(None, false);
}

#[test]
fn with_auth() {
    test_auth(Some("Basic bXl1c2VyOm15cGFzcw=="), true);
}

#[test]
fn wrong_auth() {
    test_auth(Some("Basic bXl1c2VyOndyb25ncGFzcw=="), false);
}

#[test]
fn mimemap() {
    let mimemap_lines = &[
        "test/type1 a1",
        "test/this-gets-replaced  ap2",
        "# this is a comment",
        "test/type3\tapp3\r",
        "test/type2  ap2",
        "  test/foo foo",
        "",
    ];
    let mut mimemap = NamedTempFile::new().unwrap();
    for line in mimemap_lines {
        writeln!(mimemap, "{}", line).unwrap();
    }
    let args = &[
        "--mimetypes",
        &mimemap.path().to_str().unwrap(),
        "--default-mimetype",
        "test/default",
    ];
    let server = Server::with_args(args);
    let files = &[
        ("test-file.a1", "test/type1"),
        ("test-file.ap2", "test/type2"),
        ("test-file.app3", "test/type3"),
        ("test-file.appp4", "test/default"),
        ("test-file.foo", "test/foo"),
    ];
    for (filename, content_type) in files {
        server.create_file(filename);
        let response = server.send(Request::new(&format!("/{}", filename)));
        assert_eq!(response.status(), "200 OK");
        assert_eq!(response.header("Content-Type"), Some(*content_type));
    }
}

#[test]
fn timeout() {
    let args = &["--timeout", "1"];
    let server = Server::with_args(args);
    let mut stream = server.stream();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut buf = String::new();
    // expect EOF before read timeout expires
    assert_eq!(stream.read_to_string(&mut buf).unwrap(), 0);
}

#[test]
fn dirlist_escape() {
    let server = Server::with_args(&[]);
    let mut file = server.create_file("escape(this)name");
    let mut buf = Vec::new();
    buf.resize(123456, 0);
    file.write_all(&buf).unwrap();
    let response = server.send(Request::new("/"));
    assert!(response.text().unwrap().contains("escape%28this%29name"));
    assert!(response.text().unwrap().contains("12345"));
}

#[test]
fn dir_redirect() {
    let server = Server::with_args(&[]);
    server.create_dir("mydir");
    let response = server.send(Request::new("/mydir"));
    assert_eq!(response.status(), "301 Moved Permanently");
    assert_eq!(response.header("Location"), Some("/mydir/"));
}

fn get_random_data(len: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.resize(len, 0);
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut buf)
        .unwrap();
    buf
}

fn test_file_get(path: &str) {
    let server = Server::with_args(&[]);
    let data = get_random_data(2345);
    server.create_file("data.jpeg").write_all(&data).unwrap();
    server.create_file("what?.jpg").write_all(&data).unwrap();
    let response = server.send(Request::new(path));
    assert_eq!(response.status(), "200 OK");
    assert_eq!(response.header("Accept-Ranges"), Some("bytes"));
    assert_eq!(
        response.header("Content-Length"),
        Some(data.len().to_string().as_str())
    );
    assert_eq!(response.header("Content-Type"), Some("image/jpeg"));
    assert!(response.header("Server").unwrap().contains("darkhttpd/"));
    assert_eq!(response.body, Some(data));
}

#[test]
fn file_get() {
    test_file_get("/data.jpeg");
}

fn percent_encode(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|b| format!("%{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

#[test]
fn file_get_urldecode() {
    test_file_get(&percent_encode("/data.jpeg"));
}

#[test]
fn file_get_redundant_dots() {
    test_file_get("/./././data.jpeg");
}

#[test]
fn file_get_with_empty_query() {
    test_file_get("/data.jpeg?");
}

#[test]
fn file_get_with_query() {
    test_file_get("/data.jpeg?action=Submit");
}

#[test]
fn file_get_escaped_question() {
    test_file_get("/what%3f.jpg");
}

#[test]
fn file_get_escaped_question_with_query() {
    test_file_get("/what%3f.jpg?hello=world");
}

#[test]
fn file_head() {
    let server = Server::with_args(&[]);
    let data = get_random_data(2345);
    server.create_file("data.jpeg").write_all(&data).unwrap();
    let response = server.send(Request::new("/data.jpeg").with_method("HEAD"));
    assert_eq!(response.status(), "200 OK");
    assert_eq!(response.header("Accept-Ranges"), Some("bytes"));
    assert_eq!(
        response.header("Content-Length"),
        Some(data.len().to_string().as_str())
    );
    assert_eq!(response.header("Content-Type"), Some("image/jpeg"));
}

#[test]
fn if_modified_since() {
    let server = Server::with_args(&[]);
    let data = get_random_data(2345);
    server.create_file("data.jpeg").write_all(&data).unwrap();
    let response = server.send(Request::new("/data.jpeg").with_method("HEAD"));
    let last_mod = response.header("Last-Modified").unwrap();
    let response =
        server.send(Request::new("/data.jpeg").with_header("If-Modified-Since", last_mod));
    assert_eq!(response.status(), "304 Not Modified");
    assert_eq!(response.header("Last-Modified"), None);
    assert_eq!(response.header("Accept-Ranges"), Some("bytes"));
    assert_eq!(response.header("Content-Length"), None);
    assert_eq!(response.header("Content-Type"), None);
}

const RANGE_DATA_LEN: usize = 2345;

macro_rules! range {
    ($start:expr => $end:expr) => {
        format!("bytes={}-{}", $start, $end)
    };
    (=> $end:expr) => {
        format!("bytes=-{}", $end)
    };
    ($start:expr =>) => {
        format!("bytes={}-", $start)
    };
}

fn test_range(range_in: String, range_out: (usize, usize), range_data: (usize, usize)) {
    let server = Server::with_args(&[]);
    let data = get_random_data(RANGE_DATA_LEN);
    server.create_file("data.jpeg").write_all(&data).unwrap();
    let response = server.send(Request::new("/data.jpeg").with_header("Range", &range_in));
    assert_eq!(response.status(), "206 Partial Content");
    assert_eq!(response.header("Accept-Ranges"), Some("bytes"));
    assert_eq!(
        response.header("Content-Range"),
        Some(format!("bytes {}-{}/{}", range_out.0, range_out.1, RANGE_DATA_LEN).as_str())
    );
    assert_eq!(
        response.header("Content-Length"),
        Some((range_data.1 - range_data.0).to_string().as_str())
    );
    assert_eq!(&response.body.unwrap(), &data[range_data.0..range_data.1]);
}

#[test]
fn range_single() {
    test_range(range! { 5 => 5 }, (5, 5), (5, 6));
}

#[test]
fn range_single_first() {
    test_range(range! { 0 => 0 }, (0, 0), (0, 1))
}

#[test]
fn range_single_last() {
    let last = RANGE_DATA_LEN - 1;
    test_range(
        range! { last => last },
        (last, last),
        (last, RANGE_DATA_LEN),
    )
}

#[test]
fn range_reasonable() {
    test_range(range! { 10 => 20 }, (10, 20), (10, 21))
}

#[test]
fn range_start_given() {
    test_range(
        range! { 10 => },
        (10, RANGE_DATA_LEN - 1),
        (10, RANGE_DATA_LEN),
    )
}

#[test]
fn range_end_given() {
    test_range(
        range! { => 25 },
        (RANGE_DATA_LEN - 25, RANGE_DATA_LEN - 1),
        (RANGE_DATA_LEN - 25, RANGE_DATA_LEN),
    )
}

#[test]
fn range_beyond_end() {
    // expecting same result as range_end_given
    test_range(
        range! { RANGE_DATA_LEN - 25 => RANGE_DATA_LEN * 2 },
        (RANGE_DATA_LEN - 25, RANGE_DATA_LEN - 1),
        (RANGE_DATA_LEN - 25, RANGE_DATA_LEN),
    )
}

#[test]
fn range_end_given_oversize() {
    // expecting full file
    test_range(
        range! { => RANGE_DATA_LEN * 3 },
        (0, RANGE_DATA_LEN - 1),
        (0, RANGE_DATA_LEN),
    )
}

macro_rules! test_bad_range {
    ($name:ident, $range:expr) => {
        #[test]
        fn $name() {
            let server = Server::with_args(&[]);
            let data = get_random_data(RANGE_DATA_LEN);
            server.create_file("data.jpeg").write_all(&data).unwrap();
            let response = server.send(Request::new("/data.jpeg").with_header("Range", &$range));
            assert_eq!(response.status(), "416 Requested Range Not Satisfiable");
        }
    };
}

test_bad_range! { range_single_bad, range! { RANGE_DATA_LEN => RANGE_DATA_LEN } }
test_bad_range! { range_bad_start, range! { RANGE_DATA_LEN * 2 => } }
test_bad_range! { range_backwards, range! { 20 => 10} }

/// Create a file containing 4 KB of random data aligned at the center of the given boundary length
/// (eg. 2 GB). Send a RANGE request for the 1 KB of data starting at the boundary length plus a
/// small offset.
///
/// To avoid actually writing such a large file to disk, create a sparse file by seeking past the
/// end of the file before writing. This relies on implementation-defined behaviour of the `seek`
/// method and may only work on Linux.
#[test_case(1 << 31 ; "2 GB")]
#[test_case(1 << 32 ; "4 GB")]
fn large_file(boundary: usize) {
    let server = Server::with_args(&[]);
    let data = get_random_data(4096);
    let mut file = server.create_file("big.jpeg");
    let pos = (boundary - (data.len() / 2)) as u64;
    file.seek(SeekFrom::Start(pos)).unwrap();
    assert_eq!(file.stream_position().unwrap(), pos);
    file.write_all(&data).unwrap();
    let file_size = file.metadata().unwrap().len();
    assert_eq!(file_size, pos + data.len() as u64);

    for offset in -3..=3 {
        let req_start = (boundary as i64 + offset) as usize;
        let req_end = req_start + data.len() / 4 - 1;
        let range_in = format!("{}-{}", req_start, req_end);
        let range_out = format!("bytes {}/{}", range_in, file_size);
        let data_start = req_start - pos as usize;
        let data_end = data_start + data.len() / 4;
        let response = server
            .send(Request::new("/big.jpeg").with_header("Range", &format!("bytes={}", range_in)));
        assert_eq!(response.status(), "206 Partial Content");
        assert_eq!(response.header("Accept-Ranges"), Some("bytes"));
        assert_eq!(response.header("Content-Range"), Some(range_out.as_str()));
        assert_eq!(
            response.header("Content-Length"),
            Some((data.len() / 4).to_string().as_str())
        );
        assert_eq!(&response.body.unwrap(), &data[data_start..data_end]);
    }
}

const HTTP_CLIENT_CASES: &[(&str, &str)] = &[
    ("", "\n"),
    ("1.0", "\n"),
    ("1.1", "\n"),
    ("", "\r\n"),
    ("1.0", "\r\n"),
    ("1.1", "\r\n"),
];

#[test_case("/" ; "root")]
#[test_case("/dir/../" ; "up dir")]
#[test_case("/dir/.." ; "no trailing slash")]
#[test_case("//dir///..////" ; "extra slashes")]
fn is_index(url: &str) {
    let server = Server::with_args(&[]);
    for (version, line_ending) in HTTP_CLIENT_CASES {
        let response = server.send(
            Request::new(url)
                .with_version(version)
                .with_line_ending(line_ending),
        );
        assert_eq!(response.status(), "200 OK");
        let text = response.text().unwrap();
        assert!(text.contains("<a href=\"..\">..</a>/"));
        assert!(text.contains("Generated by darkhttpd"));
    }
}

#[test_case("dir/../" ; "no leading slash")]
#[test_case("/../" ; "invalid up dir")]
#[test_case("/./dir/./../../" ; "fancy invalid up dir")]
fn is_invalid(url: &str) {
    let server = Server::with_args(&[]);
    for (version, line_ending) in HTTP_CLIENT_CASES {
        let response = server.send(
            Request::new(url)
                .with_version(version)
                .with_line_ending(line_ending),
        );
        assert_eq!(response.status(), "400 Bad Request");
        let text = response.text().unwrap();
        assert!(text.contains("You requested an invalid URL.\n"));
        assert!(text.contains("Generated by darkhttpd"));
    }
}

#[test_case("//.d" ; "extra slashes 2")]
#[test_case("/not_found.txt" ; "not found")]
fn is_not_found(url: &str) {
    let server = Server::with_args(&[]);
    for (version, line_ending) in HTTP_CLIENT_CASES {
        let response = server.send(
            Request::new(url)
                .with_version(version)
                .with_line_ending(line_ending),
        );
        assert_eq!(response.status(), "404 Not Found");
        let text = response.text().unwrap();
        assert!(text.contains("The URL you requested was not found.\n"));
        assert!(text.contains("Generated by darkhttpd"));
    }
}

#[test]
fn forbidden() {
    let server = Server::with_args(&[]);
    set_permissions(
        server.create_dir("forbidden"),
        Permissions::from_mode(0o666), // -x
    )
    .unwrap();
    for (version, line_ending) in HTTP_CLIENT_CASES {
        let response = server.send(
            Request::new("/forbidden/x")
                .with_version(version)
                .with_line_ending(line_ending),
        );
        assert_eq!(response.status(), "403 Forbidden");
        let text = response.text().unwrap();
        assert!(text.contains("You don't have permission to access this URL.\n"));
        assert!(text.contains("Generated by darkhttpd"));
    }
}

#[test]
fn unreadable() {
    let server = Server::with_args(&[]);
    set_permissions(
        server.create_dir("unreadable"),
        Permissions::from_mode(0o333), // -r
    )
    .unwrap();
    for (version, line_ending) in HTTP_CLIENT_CASES {
        let response = server.send(
            Request::new("/unreadable/")
                .with_version(version)
                .with_line_ending(line_ending),
        );
        assert_eq!(response.status(), "500 Internal Server Error");
        let text = response.text().unwrap();
        assert!(text.contains("Couldn't list directory: Permission denied (os error 13)\n"));
        assert!(text.contains("Generated by darkhttpd"));
    }
}

#[test]
fn keepalive() {
    let server = Server::with_args(&[]);
    let mut stream = server.stream();
    for _ in 0..2 {
        let response = server.send_stream(&mut stream, Request::new("/").with_version("1.1"));
        assert_eq!(response.status(), "200 OK");
    }
}

fn was_closed(stream: &mut TcpStream) -> bool {
    let mut buf = [0; 1];
    match stream.read_exact(&mut buf) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => true,
        _ => false,
    }
}

#[test]
fn keepalive_disabled() {
    let server = Server::with_args(&["--no-keepalive"]);
    let mut stream = server.stream();
    let response = server.send_stream(&mut stream, Request::new("/").with_version("1.1"));
    assert_eq!(response.status(), "200 OK");
    assert!(was_closed(&mut stream));
}

#[test_case("1.0" ; "one point zero")]
#[test_case("" ; "undefined" )]
fn keepalive_bad_version(version: &'static str) {
    let server = Server::with_args(&["--no-keepalive"]);
    let mut stream = server.stream();
    let response = server.send_stream(&mut stream, Request::new("/").with_version(version));
    assert_eq!(response.status(), "200 OK");
    assert!(was_closed(&mut stream));
}
