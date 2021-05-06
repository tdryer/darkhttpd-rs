use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;
use tempfile::tempdir;

macro_rules! map {
    ($($k:expr => $v:expr),* $(,)?) => {
        std::iter::Iterator::collect(std::array::IntoIter::new([$(($k, $v),)*]))
    };
}

fn get_unused_port() -> Option<u16> {
    TcpListener::bind(("localhost", 0))
        .ok()
        .map(|listener| listener.local_addr().unwrap().port())
}

fn wait_for_port(port: u16) -> bool {
    for _ in 0..1000 {
        if let Ok(_) = TcpStream::connect(("localhost", port)) {
            return true;
        }
        sleep(Duration::from_millis(1));
    }
    false
}

fn is_built() -> bool {
    Command::new("make")
        .args(&["--question"])
        .output()
        .expect("failed to run make")
        .status
        .success()
}

struct Server {
    child: Child,
    port: u16,
}
impl Server {
    fn with_args(dir: &Path, args: &[&str]) -> Self {
        // Check that the darkhttpd binary is up to date. We don't actually build it here because
        // test threads could race each other.
        assert!(is_built(), "need to run `make` before running tests");

        // Get an unused port. Assumes the port won't be reused before we start darkhttpd.
        let port = get_unused_port().expect("failed to get unused port");

        let child = Command::new("./darkhttpd")
            .args(&[
                dir.to_str().expect("path is not valid UTF-8"),
                "--port",
                &format!("{}", port),
                "--addr",
                "127.0.0.1",
            ])
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn darkhttpd");

        // Create server early so it will be dropped if it fails to start.
        let server = Self { child, port };

        // Wait until the socket is open.
        assert!(wait_for_port(port), "failed to connect to darkhttpd");

        server
    }
    fn stream(&self) -> TcpStream {
        TcpStream::connect(("localhost", self.port)).expect("failed to connect to darkhttpd")
    }
    fn get(&self, path: &str, headers: HashMap<&str, &str>) -> String {
        let mut stream = self.stream();
        // Set timeouts to prevent tests from hanging
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        // Write request
        write!(stream, "GET {}", path).unwrap();
        write!(stream, "\n").unwrap();
        for (header_name, header_value) in headers {
            write!(stream, "{}: {}\n", header_name, header_value).unwrap();
        }
        write!(stream, "\n").unwrap();
        // Read response
        let mut buf = String::new();
        stream
            .read_to_string(&mut buf)
            .expect("failed to read response");
        buf
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.child.kill().ok();
    }
}

fn parse(response: &str) -> (&str, HashMap<&str, &str>, &str) {
    let mut parts = response.splitn(2, "\r\n\r\n");
    let headers = parts.next().unwrap();
    let body = parts.next().unwrap();

    let mut header_lines = headers.split("\r\n");
    let request_line = header_lines.next().unwrap();
    let mut headers = HashMap::new();
    for header_line in header_lines {
        let mut header = header_line.splitn(2, ": ");
        let key = header.next().unwrap();
        let value = header.next().unwrap();
        headers.insert(key, value);
    }
    (request_line, headers, body)
}

fn test_forward(args: &[&str], url: &str, host: &str, location: &str) {
    let root = tempdir().expect("failed to create tempdir");
    let server = Server::with_args(root.path(), args);
    let request_headers = map! { "Host" => host };
    let response = server.get(url, request_headers);
    let (status, headers, body) = parse(&response);

    assert!(status.contains("301 Moved Permanently"));
    assert_eq!(headers.get("Location"), Some(&location));
    assert!(body.contains(location));

    root.close().expect("failed to close tempdir");
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
    let root = tempdir().expect("failed to create tempdir");
    let server = Server::with_args(root.path(), args);
    let response = server.get("/", HashMap::new());
    let (status, headers, body) = parse(&response);

    assert!(status.contains("200 OK"));
    assert!(headers.contains_key("Server") == server_id);
    assert!(body.contains("Generated by") == server_id);

    root.close().expect("failed to close tempdir");
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
    let root = tempdir().expect("failed to create tempdir");
    let server = Server::with_args(root.path(), args);
    let response = server.get("/", HashMap::new());
    let (status, _headers, _body) = parse(&response);

    if listing {
        assert!(status.contains("200 OK"));
    } else {
        assert!(status.contains("404 Not Found"));
    }

    root.close().expect("failed to close tempdir");
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
    let root = tempdir().expect("failed to create tempdir");
    let args = &["--auth", "myuser:mypass"];
    let server = Server::with_args(root.path(), args);
    let mut request_headers = HashMap::new();
    if let Some(auth) = auth {
        request_headers.insert("Authorization", auth);
    }
    let response = server.get("/", request_headers);
    let (status, headers, _body) = parse(&response);

    if authorized {
        assert!(status.contains("200 OK"));
    } else {
        assert!(status.contains("401 Unauthorized"));
        assert_eq!(
            headers.get("WWW-Authenticate"),
            Some(&"Basic realm=\"User Visible Realm\"")
        );
    }

    root.close().expect("failed to close tempdir");
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
    let root = tempdir().expect("failed to create tempdir");
    let mut mimemap_path = root.path().to_path_buf();
    mimemap_path.push("mimemap");
    let mut mimemap = File::create(&mimemap_path).unwrap();
    let mimemap_lines = &[
        "test/type1 a1",
        "test/this-gets-replaced  ap2",
        "# this is a comment",
        "test/type3\tapp3\r",
        "test/type2  ap2",
        "  test/foo foo",
        "",
    ];
    for line in mimemap_lines {
        writeln!(mimemap, "{}", line).unwrap();
    }
    let args = &[
        "--mimetypes",
        &mimemap_path.to_str().unwrap(),
        "--default-mimetype",
        "test/default",
    ];
    let server = Server::with_args(root.path(), args);
    let files = &[
        ("test-file.a1", "test/type1"),
        ("test-file.ap2", "test/type2"),
        ("test-file.app3", "test/type3"),
        ("test-file.appp4", "test/default"),
        ("test-file.foo", "test/foo"),
    ];
    for (filename, content_type) in files {
        let mut file_path = root.path().to_path_buf();
        file_path.push(filename);
        File::create(file_path).unwrap();
        let response = server.get(&format!("/{}", filename), HashMap::new());
        let (status, headers, _body) = parse(&response);
        assert!(status.contains("200 OK"));
        assert_eq!(headers.get("Content-Type"), Some(content_type));
    }
    root.close().expect("failed to close tempdir");
}

#[test]
fn timeout() {
    let root = tempdir().expect("failed to create tempdir");
    let args = &["--timeout", "1"];
    let server = Server::with_args(root.path(), args);
    let mut stream = server.stream();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut buf = String::new();
    // expect EOF before read timeout expires
    assert_eq!(stream.read_to_string(&mut buf).unwrap(), 0);
}
