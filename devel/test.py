#!/usr/bin/env python3
# This is run by the "run-tests" script.
import unittest
import socket
import signal
import re
import os
import random

WWWROOT = "tmp.httpd.tests"

def random_bytes(n):
    return bytes([random.randint(0,255) for _ in range(n)])

def between(s, start, end):
    assert start in s, s
    p = s.index(start) + len(start)
    s = s[p:]
    assert end in s, s
    p = s.index(end)
    return s[:p]

assert between("hello world", "hell", "world") == "o "

class Conn:
    def __init__(self):
        self.port = 12346
        self.s = socket.socket()
        self.s.connect(("0.0.0.0", self.port))
        # connect throws socket.error on connection refused

    def close(self):
        self.s.close()

    def get(self, url, http_ver="1.0", endl="\n", req_hdrs={}, method="GET"):
        req = method+" "+url
        if http_ver is not None:
            req += " HTTP/"+http_ver
        req += endl
        if http_ver is not None:
            req_hdrs["User-Agent"] = "test.py"
            req_hdrs["Connection"] = "close"
            for k,v in req_hdrs.items():
                req += k+": "+v+endl
        req += endl # end of request
        self.s.send(req.encode('utf_8'))
        ret = b''
        while True:
            signal.alarm(1) # don't wait forever
            r = self.s.recv(65536)
            signal.alarm(0)
            if r == b'':
                break
            else:
                ret += r
        return ret

    def get_keepalive(self, url, endl="\n", req_hdrs={}, method="GET"):
        req = method+" "+url+" HTTP/1.1"+endl
        req_hdrs["User-Agent"] = "test.py"
        req_hdrs["Connection"] = "keep-alive"
        for k,v in req_hdrs.items():
            req += k+": "+v+endl
        req += endl # end of request
        self.s.send(req.encode('utf-8'))
        signal.alarm(1) # don't wait forever
        ret = b''
        while True:
            ret += self.s.recv(65536)
            if b'\r\n\r\n' not in ret:
                # Don't have headers yet.
                continue
            if method == "HEAD":
                # We're done.
                break
            if b'Content-Length: ' in ret:
                cl = between(ret, b'Content-Length: ', b'\r\n')
                cl = int(cl)
            else:
                cl = 0
            p = ret.index(b'\r\n\r\n') + 4
            assert len(ret) - p <= cl, [ret, p, cl]
            if len(ret) == p + cl:
                # Complete response.
                break
        signal.alarm(0)
        return ret

def parse(resp):
    """
    Parse response into status line, headers and body.
    """
    pos = resp.find(b'\r\n\r\n')
    assert pos != -1, 'response is %s' % repr(resp)
    head = resp[:pos]
    body = resp[pos+4:]
    status,head = head.split(b'\r\n', 1)
    hdrs = {}
    for line in head.split(b'\r\n'):
        k, v = line.split(b': ', 1)
        k = k.decode('utf-8')
        v = v.decode('utf-8')
        hdrs[k] = v
    return (status, hdrs, body)

class TestHelper(unittest.TestCase):
    def get(self, url, http_ver="1.0", endl="\n", req_hdrs={}, method="GET"):
        c = Conn()
        r = c.get(url, http_ver, endl, req_hdrs, method)
        c.close()
        return r

    def assertContains(self, body, *strings):
        if type(body) is not bytes:
            body = body.encode('utf-8')
        for s in strings:
            self.assertTrue(s.encode('utf-8') in body,
                    msg="\nExpected: %s\nIn response: %s" % (
                        repr(s), repr(body)))

    def assertIsIndex(self, body, path):
        self.assertContains(body,
            '<a href="..">..</a>/',
            'Generated by darkhttpd')

    def assertIsInvalid(self, body, path):
        self.assertContains(body,
            "<title>400 Bad Request</title>",
            "<h1>Bad Request</h1>\n",
            "You requested an invalid URL.\n",
            'Generated by darkhttpd')

    def assertNotFound(self, body, path):
        self.assertContains(body,
            "<title>404 Not Found</title>",
            "<h1>Not Found</h1>\n",
            "The URL you requested was not found.\n",
            'Generated by darkhttpd')

    def assertForbidden(self, body, path):
        self.assertContains(body,
            "<title>403 Forbidden</title>",
            "<h1>Forbidden</h1>\n",
            "You don't have permission to access this URL.\n",
            'Generated by darkhttpd')

    def assertUnreadable(self, body, path):
        self.assertContains(body,
            "Couldn't list directory: Permission denied (os error 13)\n",
            'Generated by darkhttpd')

    def drive_range(self, range_in, range_out, len_out, data_out,
            status_out = "206 Partial Content"):
        resp = self.get(self.url, req_hdrs = {"Range": "bytes="+range_in})
        status, hdrs, body = parse(resp)
        self.assertContains(status, status_out)
        self.assertEqual(hdrs["Accept-Ranges"], "bytes")
        self.assertEqual(hdrs["Content-Range"], "bytes "+range_out)
        self.assertEqual(hdrs["Content-Length"], str(len_out))
        self.assertEqual(body, data_out)

class TestCases(TestHelper):
    pass # these get autogenerated in setUpModule()

def nerf(s):
    return re.sub("[^a-zA-Z0-9]", "_", s)

def makeCase(name, url, hdr_checker=None, body_checker=None,
             req_hdrs={"User-Agent": "test.py"},
             http_ver=None, endl="\n"):
    def do_test(self):
        resp = self.get(url, http_ver, endl, req_hdrs)
        if http_ver is None:
            status = ""
            hdrs = {}
            body = resp
        else:
            status, hdrs, body = parse(resp)

        if hdr_checker is not None and http_ver is not None:
            hdr_checker(self, hdrs)

        if body_checker is not None:
            body_checker(self, body)

        # FIXME: check status
        if http_ver is not None:
            prefix = b'HTTP/1.1 ' # should 1.0 stay 1.0?
            self.assertTrue(status.startswith(prefix),
                msg="%s at start of %s"%(repr(prefix), repr(status)))

    v = http_ver
    if v is None:
        v = "0.9"
    test_name = "_".join([
        "test",
        nerf(name),
        nerf("HTTP"+v),
        {"\n":"LF", "\r\n":"CRLF"}[endl],
    ])
    do_test.__name__ = test_name # hax
    setattr(TestCases, test_name, do_test)

def makeCases(name, url, hdr_checker=None, body_checker=None,
              req_hdrs={"User-Agent": "test.py"}):
    for http_ver in [None, "1.0", "1.1"]:
        for endl in ["\n", "\r\n"]:
            makeCase(name, url, hdr_checker, body_checker,
                     req_hdrs, http_ver, endl)

def makeSimpleCases(name, url, assert_name):
    makeCases(name, url, None,
        lambda self,body: getattr(self, assert_name)(body, url))

def setUpModule():
    for args in [
        ["index",                "/",               "assertIsIndex"],
        ["up dir",               "/dir/../",        "assertIsIndex"],
        ["extra slashes",        "//dir///..////",  "assertIsIndex"],
        ["no trailing slash",    "/dir/..",         "assertIsIndex"],
        ["no leading slash",     "dir/../",         "assertIsInvalid"],
        ["invalid up dir",       "/../",            "assertIsInvalid"],
        ["fancy invalid up dir", "/./dir/./../../", "assertIsInvalid"],
        ["extra slashes 2",      "//.d",            "assertNotFound"],
        ["not found",            "/not_found.txt",  "assertNotFound"],
        ["forbidden",            "/forbidden/x",    "assertForbidden"],
        ["unreadable",           "/unreadable/",    "assertUnreadable"],
        ]:
        makeSimpleCases(*args)

class TestFileGet(TestHelper):
    def setUp(self):
        self.datalen = 2345
        self.data = random_bytes(self.datalen)
        self.url = '/data.jpeg'
        self.fn = WWWROOT + self.url
        with open(self.fn, 'wb') as f:
            f.write(self.data)
        self.qurl = '/what%3f.jpg'
        self.qfn = WWWROOT + '/what?.jpg'
        if os.path.exists(self.qfn):
            os.unlink(self.qfn)
        os.link(self.fn, self.qfn)

    def tearDown(self):
        os.unlink(self.fn)
        os.unlink(self.qfn)

class TestKeepAlive(TestFileGet):
    """
    Run all of TestFileGet but with a single long-lived connection.
    """
    def setUp(self):
        TestFileGet.setUp(self)
        self.conn = Conn()

    def tearDown(self):
        self.conn.close()

    def get(self, url, endl="\n", req_hdrs={}, method="GET"):
        return self.conn.get_keepalive(url, endl, req_hdrs, method)

def make_large_file(fn, boundary, data):
    with open(fn, 'wb') as f:
        pos = boundary - (len(data) // 2)
        f.seek(pos)
        assert f.tell() == pos
        assert f.tell() < boundary
        f.write(data)
        filesize = f.tell()
        assert filesize == pos + len(data), (filesize, pos, len(data))
        assert filesize > boundary
    return (pos, filesize)

class TestLargeFile2G(TestHelper):
    BOUNDARY = 1<<31

    def setUp(self):
        self.datalen = 4096
        self.data = random_bytes(self.datalen)
        self.url = "/big.jpeg"
        self.fn = WWWROOT + self.url
        self.filepos, self.filesize = make_large_file(
            self.fn, self.BOUNDARY, self.data)

    def tearDown(self):
        os.unlink(self.fn)

    def drive_start(self, ofs):
        req_start = self.BOUNDARY + ofs
        req_end = req_start + self.datalen//4 - 1
        range_in = "%d-%d"%(req_start, req_end)
        range_out = "%s/%d"%(range_in, self.filesize)

        data_start = req_start - self.filepos
        data_end = data_start + self.datalen//4

        self.drive_range(range_in, range_out, self.datalen//4,
            self.data[data_start:data_end])

    def test_largefile_head(self):
        resp = self.get(self.url, method="HEAD")
        status, hdrs, body = parse(resp)
        self.assertContains(status, "200 OK")
        self.assertEqual(hdrs["Accept-Ranges"], "bytes")
        self.assertEqual(hdrs["Content-Length"], str(self.filesize))
        self.assertEqual(hdrs["Content-Type"], "image/jpeg")

    def test_largefile__3(self): self.drive_start(-3)
    def test_largefile__2(self): self.drive_start(-2)
    def test_largefile__1(self): self.drive_start(-1)
    def test_largefile_0(self): self.drive_start(0)
    def test_largefile_1(self): self.drive_start(1)
    def test_largefile_2(self): self.drive_start(2)
    def test_largefile_3(self): self.drive_start(3)

class TestLargeFile4G(TestLargeFile2G):
    BOUNDARY = 1<<32

if __name__ == '__main__':
    setUpModule()
    unittest.main()

# vim:set ts=4 sw=4 et:
