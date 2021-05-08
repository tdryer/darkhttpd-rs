use std::collections::HashMap;
use std::fs::{create_dir, File};
use std::io;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;
use tempfile::{tempdir, TempDir};

#[macro_export]
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

struct ScopedChild(Child);

impl Drop for ScopedChild {
    fn drop(&mut self) {
        self.0.kill().ok();
    }
}

impl From<Child> for ScopedChild {
    fn from(child: Child) -> Self {
        ScopedChild(child)
    }
}

pub struct Server {
    _child: ScopedChild,
    port: u16,
    root: TempDir,
}
impl Server {
    pub fn with_args(args: &[&str]) -> Self {
        // Check that the darkhttpd binary is up to date. We don't actually build it here because
        // test threads could race each other.
        assert!(is_built(), "need to run `make` before running tests");

        let root = tempdir().expect("failed to create tempdir");

        // Get an unused port. Assumes the port won't be reused before we start darkhttpd.
        let port = get_unused_port().expect("failed to get unused port");

        let child = Command::new("./darkhttpd")
            .args(&[
                root.path().to_str().expect("path is not valid UTF-8"),
                "--port",
                &format!("{}", port),
                "--addr",
                "127.0.0.1",
            ])
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn darkhttpd")
            .into();

        // Wait until the socket is open.
        assert!(wait_for_port(port), "failed to connect to darkhttpd");

        Self {
            _child: child,
            port,
            root,
        }
    }
    pub fn root(&self) -> &Path {
        self.root.path()
    }
    pub fn create_dir(&self, name: &str) {
        let mut path = self.root().to_path_buf();
        path.push(name);
        create_dir(path).expect("failed to create directory");
    }
    pub fn create_file(&self, name: &str) -> File {
        let mut path = self.root().to_path_buf();
        path.push(name);
        File::create(path).expect("failed to create file")
    }
    pub fn stream(&self) -> TcpStream {
        TcpStream::connect(("localhost", self.port)).expect("failed to connect to darkhttpd")
    }
    pub fn get(&self, path: &str, headers: HashMap<&str, &str>) -> Response {
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
        Response::from_reader(&mut stream).expect("failed to read response")
    }
}

/// HTTP Response from darkhttpd.
pub struct Response {
    response_line: String,
    headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}
impl Response {
    pub fn from_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let response_line = Self::read_header(reader)?;
        let headers = Self::read_headers(reader)?;
        let body = headers
            .get("Content-Length")
            .map(|length| length.parse::<usize>().expect("invalid content length"))
            .map(|length| Self::read_body(reader, length))
            .transpose()?;
        Ok(Self {
            response_line,
            headers,
            body,
        })
    }
    fn read_headers<R: Read>(reader: &mut R) -> io::Result<HashMap<String, String>> {
        let mut headers = HashMap::new();
        loop {
            let header_line = Self::read_header(reader)?;
            if header_line.is_empty() {
                break;
            }
            let mut header = header_line.splitn(2, ": ");
            let key = header.next().expect("invalid header").to_string();
            let value = header.next().expect("invalid header").to_string();
            headers.insert(key, value);
        }
        Ok(headers)
    }
    fn read_header<R: Read>(reader: &mut R) -> io::Result<String> {
        read_until_slice(reader, b"\r\n")
            .map(|vec| String::from_utf8(vec).expect("response header is not valid UTF-8"))
    }
    fn read_body<R: Read>(reader: &mut R, content_length: usize) -> io::Result<Vec<u8>> {
        let mut body = Vec::new();
        body.resize(content_length, 0);
        reader.read_exact(&mut body)?;
        Ok(body)
    }
    pub fn status(&self) -> &str {
        self.response_line
            .splitn(2, " ")
            .nth(1)
            .expect("invalid response line")
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|name| name.as_str())
    }
    pub fn text(&self) -> Option<&str> {
        self.body
            .as_ref()
            .map(|body| std::str::from_utf8(body).expect("body is not valid UTF-8"))
    }
}

fn read_until_slice<R: Read>(reader: &mut R, separator: &[u8]) -> io::Result<Vec<u8>> {
    let mut byte = [0; 1];
    let mut buf = Vec::new();
    loop {
        reader.read_exact(&mut byte)?;
        buf.push(byte[0]);
        if buf.as_slice().ends_with(separator) {
            buf.truncate(buf.len() - separator.len());
            return Ok(buf);
        }
    }
}
