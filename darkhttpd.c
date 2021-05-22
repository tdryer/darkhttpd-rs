/* darkhttpd - a simple, single-threaded, static content webserver.
 * https://unix4lyfe.org/darkhttpd/
 * Copyright (c) 2003-2021 Emil Mikulic <emikulic@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

static const char
    pkgname[]   = "darkhttpd/1.13.from.git",
    copyright[] = "copyright (c) 2003-2021 Emil Mikulic";

/* Possible build options: -DDEBUG -DNO_IPV6 */

#ifndef NO_IPV6
# define HAVE_INET6
#endif

#ifdef __linux
# define _GNU_SOURCE /* for strsignal() and vasprintf() */
# define _FILE_OFFSET_BITS 64 /* stat() files bigger than 2GB */
# include <sys/sendfile.h>
#endif

#ifdef __sun__
# include <sys/sendfile.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#if defined(__has_feature)
# if __has_feature(memory_sanitizer)
#  include <sanitizer/msan_interface.h>
# endif
#endif

#ifdef __sun__
# ifndef INADDR_NONE
#  define INADDR_NONE -1
# endif
#endif

#ifndef MAXNAMLEN
# ifdef NAME_MAX
#  define MAXNAMLEN NAME_MAX
# else
#  define MAXNAMLEN   255
# endif
#endif

#if defined(O_EXCL) && !defined(O_EXLOCK)
# define O_EXLOCK O_EXCL
#endif

#ifndef __printflike
# ifdef __GNUC__
/* [->] borrowed from FreeBSD's src/sys/sys/cdefs.h,v 1.102.2.2.2.1 */
#  define __printflike(fmtarg, firstvararg) \
             __attribute__((__format__(__printf__, fmtarg, firstvararg)))
/* [<-] */
# else
#  define __printflike(fmtarg, firstvararg)
# endif
#endif

#if defined(__GNUC__) || defined(__INTEL_COMPILER)
# define unused __attribute__((__unused__))
#else
# define unused
#endif

/* [->] borrowed from FreeBSD's src/sys/sys/systm.h,v 1.276.2.7.4.1 */
#ifndef CTASSERT                /* Allow lint to override */
# define CTASSERT(x)             _CTASSERT(x, __LINE__)
# define _CTASSERT(x, y)         __CTASSERT(x, y)
# define __CTASSERT(x, y)        typedef char __assert ## y[(x) ? 1 : -1]
#endif
/* [<-] */

CTASSERT(sizeof(unsigned long long) >= sizeof(off_t));
#define llu(x) ((unsigned long long)(x))

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__linux)
# include <err.h>
#else
/* err - prints "error: format: strerror(errno)" to stderr and exit()s with
 * the given code.
 */
static void err(const int code, const char *format, ...) __printflike(2, 3);
static void err(const int code, const char *format, ...) {
    va_list va;

    va_start(va, format);
    fprintf(stderr, "error: ");
    vfprintf(stderr, format, va);
    fprintf(stderr, ": %s\n", strerror(errno));
    va_end(va);
    exit(code);
}

/* errx - err() without the strerror */
static void errx(const int code, const char *format, ...) __printflike(2, 3);
static void errx(const int code, const char *format, ...) {
    va_list va;

    va_start(va, format);
    fprintf(stderr, "error: ");
    vfprintf(stderr, format, va);
    fprintf(stderr, "\n");
    va_end(va);
    exit(code);
}

/* warn - err() without the exit */
static void warn(const char *format, ...) __printflike(1, 2);
static void warn(const char *format, ...) {
    va_list va;

    va_start(va, format);
    fprintf(stderr, "warning: ");
    vfprintf(stderr, format, va);
    fprintf(stderr, ": %s\n", strerror(errno));
    va_end(va);
}
#endif

#define INVALID_UID ((uid_t) -1)
#define INVALID_GID ((gid_t) -1)

struct connection; /* defined by Rust */

/* Container for mutable static variables. */
struct server {
    const char *pkgname;
    const char *copyright;
    void *connections;          /* used by Rust */
    void *forward_map;          /* used by Rust */
    const char *forward_all_url;
    /* If a connection is idle for timeout_secs or more, it gets closed and
     * removed from the connlist.
     */
    int timeout_secs;
    char *bindaddr;
    uint16_t bindport;
    int max_connections;
    char *index_name;
    int no_listing;
    int sockin; /* socket to accept connections from */
    /* Time is cached in the event loop to avoid making an excessive number of
     * gettimeofday() calls.
     */
    time_t now;
#ifdef HAVE_INET6
    int inet6;                  /* whether the socket uses inet6 */
#endif
    char *wwwroot;              /* a path name */
    char *logfile_name;         /* NULL = no logging */
    FILE *logfile;
    char *pidfile_name;         /* NULL = no pidfile */
    int pidfile_fd;
    int want_chroot;
    int want_daemon;
    int want_accf;
    int want_keepalive;
    int want_server_id;
    char *server_hdr;
    char *auth_key;
    uint64_t num_requests;
    uint64_t total_in;
    uint64_t total_out;
    int accepting;              /* set to 0 to stop accept()ing */
    int syslog_enabled;
    void *keep_alive_field;     /* used by Rust */
    void *mime_map;             /* used by Rust */
    uid_t drop_uid;
    gid_t drop_gid;
};

static struct server srv = {
    .pkgname = pkgname,
    .copyright = copyright,
    .forward_map = NULL,
    .forward_all_url = NULL,
    .timeout_secs = 30,
    .bindaddr = NULL,
    .bindport = 8080,           /* or 80 if running as root */
    .max_connections = -1,      /* kern.ipc.somaxconn */
    .index_name = NULL,
    .no_listing = 0,
    .sockin = -1,
    .now = 0,
#ifdef HAVE_INET6
    .inet6 = 0,
#endif
    .wwwroot = NULL,
    .logfile_name = NULL,
    .logfile = NULL,
    .pidfile_name = NULL,
    .pidfile_fd = -1,
    .want_chroot = 0,
    .want_daemon = 0,
    .want_accf = 0,
    .want_keepalive = 1,
    .want_server_id = 1,
    .server_hdr = NULL,
    .auth_key = NULL,
    .num_requests = 0,
    .total_in = 0,
    .total_out = 0,
    .accepting = 1,
    .syslog_enabled = 0,
    .keep_alive_field = NULL,
    .mime_map = NULL,
    .drop_uid = INVALID_UID,
    .drop_gid = INVALID_GID,
};

extern void main_rust(struct server *srv);

/* Execution starts here. */
int main(int argc, char **argv) {
    main_rust(&srv);

    /* usage stats */
    {
        struct rusage r;

        getrusage(RUSAGE_SELF, &r);
        printf("CPU time used: %u.%02u user, %u.%02u system\n",
            (unsigned int)r.ru_utime.tv_sec,
                (unsigned int)(r.ru_utime.tv_usec/10000),
            (unsigned int)r.ru_stime.tv_sec,
                (unsigned int)(r.ru_stime.tv_usec/10000)
        );
        printf("Requests: %llu\n", llu(srv.num_requests));
        printf("Bytes: %llu in, %llu out\n", llu(srv.total_in), llu(srv.total_out));
    }

    return 0;
}

/* vim:set ts=4 sw=4 sts=4 expandtab tw=78: */
