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
    assert_eq!(url_decode("escape%28this%29name%09"), b"escape(this)name\t");
    assert_eq!(url_decode("edge%"), b"edge%");
    assert_eq!(url_decode("edge%2"), b"edge%2");
    assert_eq!(url_decode("edge%20"), b"edge ");
    assert_eq!(url_decode("invalid%C3%28"), b"invalid\xc3\x28");
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
    assert!(
        ClfDate(SystemTime::UNIX_EPOCH + Duration::from_secs(1620965123))
            .to_string()
            .contains("May/2021")
    );
}

#[test]
fn http_date_works() {
    assert_eq!(
        HttpDate(SystemTime::UNIX_EPOCH + Duration::from_secs(1622040683)).to_string(),
        "Wed, 26 May 2021 14:51:23 GMT"
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
