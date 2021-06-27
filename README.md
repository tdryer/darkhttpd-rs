# darkhttpd-rs

Rust port of [darkhttpd], a simple and fast web server for static content.

Like the original, darkhttpd-rs constrains itself to a single source file and
minimal dependencies. Porting was done incrementally, by replacing individual C
functions, until the entire program was translated.

darkhttpd-rs is experimental. You probably want to use [darkhttpd] instead.

[darkhttpd]: https://unix4lyfe.org/darkhttpd/

## Changes from darkhttpd

* `sendfile` support required.
* FreeBSD `acceptfilter` support (`--accf`) removed.
* Only tested on Linux.

## Features

* Simple to set up:
  * Single binary, no other files, no installation needed.
  * Standalone, doesn't need `inetd` or `ucspi-tcp`.
  * No messing around with config files - all you have to specify is the `www`
    root.
* Small memory footprint.
* Event loop, single threaded - no `fork()` or `pthreads`.
* Generates directory listings.
* Supports HTTP GET and HEAD requests.
* Supports `Range` / partial content. (try streaming music files or resuming a
  download)
* Supports `If-Modified-Since`.
* Supports Keep-Alive connections.
* Supports IPv6.
* Can serve 301 redirects based on `Host` header.
* Uses `sendfile()`.
* ISC license.

## Security

* Can log accesses, including `Referer` and `User-Agent`.
* Can chroot.
* Can drop privileges.
* Impervious to `/../` sniffing.
* Times out idle connections.
* Drops overly long requests.

## Limitations

* Only serves static content - no CGI.

## How to build

Install [the Rust toolchain](https://rustup.rs/).

Build `./target/release/darkhttpd-rs` with cargo:

```
cargo build --release
```

## How to run

Serve `/var/www/htdocs` on the default port (80 if running as root, else 8080):

```
darkhttpd-rs /var/www/htdocs
```

Serve `~/public_html` on port 8081:

```
darkhttpd-rs ~/public_html --port 8081
```

Only bind to one IP address (useful on multi-homed systems):

```
darkhttpd-rs ~/public_html --addr 192.168.0.1
```

Serve at most 4 simultaneous connections:

```
darkhttpd-rs ~/public_html --maxconn 4
```

Log accesses to a file:

```
darkhttpd-rs ~/public_html --log access.log
```

Chroot for extra security (you need root privs for chroot):

```
darkhttpd-rs /var/www/htdocs --chroot
```

Use `default.htm` instead of `index.html`:

```
darkhttpd-rs /var/www/htdocs --index default.htm
```

Add mimetypes - in this case, serve `.dat` files as `text/plain`:

```
$ cat extramime
text/plain  dat
$ darkhttpd-rs /var/www/htdocs --mimetypes extramime
```

Drop privileges:

```
darkhttpd-rs /var/www/htdocs --uid www --gid www
```

Run in the background and create a pidfile:

```
darkhttpd-rs /var/www/htdocs --pidfile /var/run/httpd.pid --daemon
```

Web forward (301) requests for some hosts:

```
darkhttpd-rs /var/www/htdocs \
  --forward example.com http://www.example.com \
  --forward secure.example.com https://www.example.com/secure
```

Web forward (301) requests for all hosts:

```
darkhttpd-rs /var/www/htdocs \
  --forward example.com http://www.example.com \
  --forward-all http://catchall.example.com
```

Command line options can be combined:

```
darkhttpd-rs ~/public_html --port 8080 --addr 127.0.0.1
```

To see a full list of command line options, run darkhttpd-rs without any
arguments:

```
darkhttpd-rs
```
