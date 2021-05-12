CC?=cc
CFLAGS?=-O
LIBS=`[ \`uname\` = "SunOS" ] && echo -lsocket -lnsl`

all: darkhttpd

# The `pthread` and `dl` libraries are required for Rust's standard library.
# `rt` is required for the nix crate.
# Order is significant, so they must be placed after the Rust library.
darkhttpd: darkhttpd.c target/debug/libdarkhttpd.a
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) $^ -lpthread -ldl -lrt -o $@

darkhttpd-static: darkhttpd.c
	$(CC) -static $(CFLAGS) $(LDFLAGS) $(LIBS) darkhttpd.c -o $@

target/debug/libdarkhttpd.a: src/lib.rs
	cargo build

clean:
	rm -f darkhttpd core darkhttpd.core darkhttpd-static darkhttpd-static.core

.PHONY: all clean
