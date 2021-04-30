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

#ifndef DEBUG
# define NDEBUG
static const int debug = 0;
#else
static const int debug = 1;
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

/* [->] LIST_* macros taken from FreeBSD's src/sys/sys/queue.h,v 1.56
 * Copyright (c) 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Under a BSD license.
 */
#define LIST_HEAD(name, type)                                           \
struct name {                                                           \
        struct type *lh_first;  /* first element */                     \
}

#define LIST_HEAD_INITIALIZER(head)                                     \
        { NULL }

#define LIST_ENTRY(type)                                                \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}

#define LIST_FIRST(head)        ((head)->lh_first)

#define LIST_FOREACH_SAFE(var, head, field, tvar)                       \
    for ((var) = LIST_FIRST((head));                                    \
        (var) && ((tvar) = LIST_NEXT((var), field), 1);                 \
        (var) = (tvar))

#define LIST_INSERT_HEAD(head, elm, field) do {                         \
        if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL)     \
                LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field);\
        LIST_FIRST((head)) = (elm);                                     \
        (elm)->field.le_prev = &LIST_FIRST((head));                     \
} while (0)

#define LIST_NEXT(elm, field)   ((elm)->field.le_next)

#define LIST_REMOVE(elm, field) do {                                    \
        if (LIST_NEXT((elm), field) != NULL)                            \
                LIST_NEXT((elm), field)->field.le_prev =                \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = LIST_NEXT((elm), field);                \
} while (0)
/* [<-] */

static LIST_HEAD(conn_list_head, connection) connlist =
    LIST_HEAD_INITIALIZER(conn_list_head);

struct connection {
    LIST_ENTRY(connection) entries;

    int socket;
#ifdef HAVE_INET6
    struct in6_addr client;
#else
    in_addr_t client;
#endif
    time_t last_active;
    enum {
        RECV_REQUEST,   /* receiving request */
        SEND_HEADER,    /* sending generated header */
        SEND_REPLY,     /* sending reply */
        DONE            /* connection closed, need to remove from queue */
    } state;

    /* char request[request_length+1] is null-terminated */
    char *request;
    size_t request_length;

    /* request fields */
    char *method, *url, *referer, *user_agent, *authorization;
    off_t range_begin, range_end;
    off_t range_begin_given, range_end_given;

    char *header;
    size_t header_length, header_sent;
    int header_dont_free, header_only, http_code, conn_close;

    enum { REPLY_GENERATED, REPLY_FROMFILE } reply_type;
    char *reply;
    int reply_dont_free;
    int reply_fd;
    off_t reply_start, reply_length, reply_sent,
          total_sent; /* header + body = total, for logging */
};

struct forward_mapping {
    const char *host, *target_url; /* These point at argv. */
};

static const char octet_stream[] = "application/octet-stream";

/* Container for mutable static variables. */
struct server {
    const char *pkgname;
    const char *copyright;
    struct forward_mapping *forward_map;
    size_t forward_map_size;
    const char *forward_all_url;
    /* If a connection is idle for timeout_secs or more, it gets closed and
     * removed from the connlist.
     */
    int timeout_secs;
    const char *bindaddr;
    uint16_t bindport;
    int max_connections;
    const char *index_name;
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
    volatile int running;       /* signal handler sets this to false */
    void *keep_alive_field;     /* used by Rust */
    void *mime_map;             /* used by Rust */
};

static struct server srv = {
    .pkgname = pkgname,
    .copyright = copyright,
    .forward_map = NULL,
    .forward_map_size = 0,
    .forward_all_url = NULL,
    .timeout_secs = 30,
    .bindaddr = NULL,
    .bindport = 8080,           /* or 80 if running as root */
    .max_connections = -1,      /* kern.ipc.somaxconn */
    .index_name = "index.html",
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
    .running = 1,
    .keep_alive_field = NULL,
    .mime_map = NULL,
};

/* To prevent a malformed request from eating up too much memory, die once the
 * request exceeds this many bytes:
 */
#define MAX_REQUEST_LENGTH 4000

#define INVALID_UID ((uid_t) -1)
#define INVALID_GID ((gid_t) -1)

static uid_t drop_uid = INVALID_UID;
static gid_t drop_gid = INVALID_GID;

/* Prototypes. */
static void poll_recv_request(struct connection *conn);
static void poll_send_header(struct connection *conn);
static void poll_send_reply(struct connection *conn);

/* close() that dies on error.  */
static void xclose(const int fd) {
    if (close(fd) == -1)
        err(1, "close()");
}

/* malloc that dies if it can't allocate. */
extern void *xmalloc(const size_t size);

/* realloc() that dies if it can't reallocate. */
static void *xrealloc(void *original, const size_t size) {
    void *ptr = realloc(original, size);
    if (ptr == NULL)
        errx(1, "can't reallocate %zu bytes", size);
    return ptr;
}

/* strdup() that dies if it can't allocate.
 * Implement this ourselves since regular strdup() isn't C89.
 */
static char *xstrdup(const char *src) {
    size_t len = strlen(src) + 1;
    char *dest = xmalloc(len);
    memcpy(dest, src, len);
    return dest;
}

#ifdef __sun /* unimpressed by Solaris */
static int vasprintf(char **strp, const char *fmt, va_list ap) {
    char tmp;
    int result = vsnprintf(&tmp, 1, fmt, ap);
    *strp = xmalloc(result+1);
    result = vsnprintf(*strp, result+1, fmt, ap);
    return result;
}
#endif

/* vasprintf() that dies if it fails. */
static unsigned int xvasprintf(char **ret, const char *format, va_list ap)
    __printflike(2,0);
static unsigned int xvasprintf(char **ret, const char *format, va_list ap) {
    int len = vasprintf(ret, format, ap);
    if (ret == NULL || len == -1)
        errx(1, "out of memory in vasprintf()");
    return (unsigned int)len;
}

/* asprintf() that dies if it fails. */
static unsigned int xasprintf(char **ret, const char *format, ...)
    __printflike(2,3);
static unsigned int xasprintf(char **ret, const char *format, ...) {
    va_list va;
    unsigned int len;

    va_start(va, format);
    len = xvasprintf(ret, format, va);
    va_end(va);
    return len;
}

/* Free a string allocated by Rust. */
extern void free_rust_cstring(char *s);

/* Make the specified socket non-blocking. */
static void nonblock_socket(const int sock) {
    int flags = fcntl(sock, F_GETFL);

    if (flags == -1)
        err(1, "fcntl(F_GETFL)");
    flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) == -1)
        err(1, "fcntl() to set O_NONBLOCK");
}

/* Split string out of src with range [left:right-1] */
extern char *split_string(const char *src, const size_t left, const size_t right);

/* Resolve /./ and /../ in a URL, in-place.
 * Returns NULL if the URL is invalid/unsafe, or the original buffer if
 * successful.
 */
extern char *make_safe_url(char *const url);

static void add_forward_mapping(const char * const host,
                                const char * const target_url) {
    srv.forward_map_size++;
    srv.forward_map = xrealloc(srv.forward_map,
                           sizeof(*srv.forward_map) * srv.forward_map_size);
    srv.forward_map[srv.forward_map_size - 1].host = host;
    srv.forward_map[srv.forward_map_size - 1].target_url = target_url;
}

/* Adds contents of default_extension_map[] to mime_map list.  The array must
 * be NULL terminated.
 */
extern void parse_default_extension_map(struct server *srv);

extern void set_default_mimetype(struct server *srv, const char *mimetype);

/* ---------------------------------------------------------------------------
 * Adds contents of specified file to mime_map list.
 */
extern void parse_extension_map_file(struct server *srv, const char *filename);

static const char *get_address_text(const void *addr) {
#ifdef HAVE_INET6
    if (srv.inet6) {
        static char text_addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, (const struct in6_addr *)addr, text_addr,
                  INET6_ADDRSTRLEN);
        return text_addr;
    } else
#endif
    {
        return inet_ntoa(*(const struct in_addr *)addr);
    }
}

/* Initialize the sockin global.  This is the socket that we accept
 * connections from.
 */
static void init_sockin(void) {
    struct sockaddr_in addrin;
#ifdef HAVE_INET6
    struct sockaddr_in6 addrin6;
#endif
    socklen_t addrin_len;
    int sockopt;

#ifdef HAVE_INET6
    if (srv.inet6) {
        memset(&addrin6, 0, sizeof(addrin6));
        if (inet_pton(AF_INET6, srv.bindaddr ? srv.bindaddr : "::",
                      &addrin6.sin6_addr) == -1) {
            errx(1, "malformed --addr argument");
        }
        srv.sockin = socket(PF_INET6, SOCK_STREAM, 0);
    } else
#endif
    {
        memset(&addrin, 0, sizeof(addrin));
        addrin.sin_addr.s_addr = srv.bindaddr ? inet_addr(srv.bindaddr) : INADDR_ANY;
        if (addrin.sin_addr.s_addr == (in_addr_t)INADDR_NONE)
            errx(1, "malformed --addr argument");
        srv.sockin = socket(PF_INET, SOCK_STREAM, 0);
    }

    if (srv.sockin == -1)
        err(1, "socket()");

    /* reuse address */
    sockopt = 1;
    if (setsockopt(srv.sockin, SOL_SOCKET, SO_REUSEADDR,
                   &sockopt, sizeof(sockopt)) == -1)
        err(1, "setsockopt(SO_REUSEADDR)");

#if 0
    /* disable Nagle since we buffer everything ourselves */
    sockopt = 1;
    if (setsockopt(srv.sockin, IPPROTO_TCP, TCP_NODELAY,
            &sockopt, sizeof(sockopt)) == -1)
        err(1, "setsockopt(TCP_NODELAY)");
#endif

#ifdef TORTURE
    /* torture: cripple the kernel-side send buffer so we can only squeeze out
     * one byte at a time (this is for debugging)
     */
    sockopt = 1;
    if (setsockopt(srv.sockin, SOL_SOCKET, SO_SNDBUF,
            &sockopt, sizeof(sockopt)) == -1)
        err(1, "setsockopt(SO_SNDBUF)");
#endif

    /* bind socket */
#ifdef HAVE_INET6
    if (srv.inet6) {
        addrin6.sin6_family = AF_INET6;
        addrin6.sin6_port = htons(srv.bindport);
        if (bind(srv.sockin, (struct sockaddr *)&addrin6,
                 sizeof(struct sockaddr_in6)) == -1)
            err(1, "bind(port %u)", srv.bindport);

        addrin_len = sizeof(addrin6);
        if (getsockname(srv.sockin, (struct sockaddr *)&addrin6, &addrin_len) == -1)
            err(1, "getsockname()");
        printf("listening on: http://[%s]:%u/\n",
            get_address_text(&addrin6.sin6_addr), srv.bindport);
    } else
#endif
    {
        addrin.sin_family = (u_char)PF_INET;
        addrin.sin_port = htons(srv.bindport);
        if (bind(srv.sockin, (struct sockaddr *)&addrin,
                 sizeof(struct sockaddr_in)) == -1)
            err(1, "bind(port %u)", srv.bindport);
        addrin_len = sizeof(addrin);
        if (getsockname(srv.sockin, (struct sockaddr *)&addrin, &addrin_len) == -1)
            err(1, "getsockname()");
        printf("listening on: http://%s:%u/\n",
            get_address_text(&addrin.sin_addr), srv.bindport);
    }

    /* listen on socket */
    if (listen(srv.sockin, srv.max_connections) == -1)
        err(1, "listen()");

    /* enable acceptfilter (this is only available on FreeBSD) */
    if (srv.want_accf) {
#if defined(__FreeBSD__)
        struct accept_filter_arg filt = {"httpready", ""};
        if (setsockopt(srv.sockin, SOL_SOCKET, SO_ACCEPTFILTER,
                       &filt, sizeof(filt)) == -1)
            fprintf(stderr, "cannot enable acceptfilter: %s\n",
                strerror(errno));
        else
            printf("enabled acceptfilter\n");
#else
        printf("this platform doesn't support acceptfilter\n");
#endif
    }
}

static void usage(const char *argv0) {
    printf("usage:\t%s /path/to/wwwroot [flags]\n\n", argv0);
    printf("flags:\t--port number (default: %u, or 80 if running as root)\n"
    "\t\tSpecifies which port to listen on for connections.\n"
    "\t\tPass 0 to let the system choose any free port for you.\n\n", srv.bindport);
    printf("\t--addr ip (default: all)\n"
    "\t\tIf multiple interfaces are present, specifies\n"
    "\t\twhich one to bind the listening port to.\n\n");
    printf("\t--maxconn number (default: system maximum)\n"
    "\t\tSpecifies how many concurrent connections to accept.\n\n");
    printf("\t--log filename (default: stdout)\n"
    "\t\tSpecifies which file to append the request log to.\n\n");
    printf("\t--syslog\n"
    "\t\tUse syslog for request log.\n\n");
    printf("\t--chroot (default: don't chroot)\n"
    "\t\tLocks server into wwwroot directory for added security.\n\n");
    printf("\t--daemon (default: don't daemonize)\n"
    "\t\tDetach from the controlling terminal and run in the background.\n\n");
    printf("\t--index filename (default: %s)\n"
    "\t\tDefault file to serve when a directory is requested.\n\n",
        srv.index_name);
    printf("\t--no-listing\n"
    "\t\tDo not serve listing if directory is requested.\n\n");
    printf("\t--mimetypes filename (optional)\n"
    "\t\tParses specified file for extension-MIME associations.\n\n");
    printf("\t--default-mimetype string (optional, default: %s)\n"
    "\t\tFiles with unknown extensions are served as this mimetype.\n\n",
        octet_stream);
    printf("\t--uid uid/uname, --gid gid/gname (default: don't privdrop)\n"
    "\t\tDrops privileges to given uid:gid after initialization.\n\n");
    printf("\t--pidfile filename (default: no pidfile)\n"
    "\t\tWrite PID to the specified file.  Note that if you are\n"
    "\t\tusing --chroot, then the pidfile must be relative to,\n"
    "\t\tand inside the wwwroot.\n\n");
    printf("\t--no-keepalive\n"
    "\t\tDisables HTTP Keep-Alive functionality.\n\n");
#ifdef __FreeBSD__
    printf("\t--accf (default: don't use acceptfilter)\n"
    "\t\tUse acceptfilter.  Needs the accf_http module loaded.\n\n");
#endif
    printf("\t--forward host url (default: don't forward)\n"
    "\t\tWeb forward (301 redirect).\n"
    "\t\tRequests to the host are redirected to the corresponding url.\n"
    "\t\tThe option may be specified multiple times, in which case\n"
    "\t\tthe host is matched in order of appearance.\n\n");
    printf("\t--forward-all url (default: don't forward)\n"
    "\t\tWeb forward (301 redirect).\n"
    "\t\tAll requests are redirected to the corresponding url.\n\n");
    printf("\t--no-server-id\n"
    "\t\tDon't identify the server type in headers\n"
    "\t\tor directory listings.\n\n");
    printf("\t--timeout secs (default: %d)\n"
    "\t\tIf a connection is idle for more than this many seconds,\n"
    "\t\tit will be closed. Set to zero to disable timeouts.\n\n",
    srv.timeout_secs);
    printf("\t--auth username:password\n"
    "\t\tEnable basic authentication.\n\n");
#ifdef HAVE_INET6
    printf("\t--ipv6\n"
    "\t\tListen on IPv6 address.\n\n");
#else
    printf("\t(This binary was built without IPv6 support: -DNO_IPV6)\n\n");
#endif
}

static char *base64_encode(char *str) {
    const char base64_table[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/'};

    int input_length = strlen(str);
    int output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(output_length+1);
    if (encoded_data == NULL) return NULL;

    int i;
    int j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)str[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)str[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)str[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 0 * 6) & 0x3F];
    }

    const int mod_table[] = {0, 2, 1};
    for (i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';
    encoded_data[output_length] = '\0';

    return encoded_data;
}

/* Returns 1 if string is a number, 0 otherwise.  Set num to NULL if
 * disinterested in value.
 */
static int str_to_num(const char *str, long long *num) {
    char *endptr;
    long long n;

    errno = 0;
    n = strtoll(str, &endptr, 10);
    if (*endptr != '\0')
        return 0;
    if (n == LLONG_MIN && errno == ERANGE)
        return 0;
    if (n == LLONG_MAX && errno == ERANGE)
        return 0;
    if (num != NULL)
        *num = n;
    return 1;
}

/* Returns a valid number or dies. */
static long long xstr_to_num(const char *str) {
    long long ret;

    if (!str_to_num(str, &ret)) {
        errx(1, "number \"%s\" is invalid", str);
    }
    return ret;
}

static void parse_commandline(const int argc, char *argv[]) {
    int i;
    size_t len;

    if ((argc < 2) || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]); /* no wwwroot given */
        exit(EXIT_SUCCESS);
    }

    if (getuid() == 0)
        srv.bindport = 80;

    srv.wwwroot = xstrdup(argv[1]);
    /* Strip ending slash. */
    len = strlen(srv.wwwroot);
    if (len > 0)
        if (srv.wwwroot[len - 1] == '/')
            srv.wwwroot[len - 1] = '\0';

    /* walk through the remainder of the arguments (if any) */
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0) {
            if (++i >= argc)
                errx(1, "missing number after --port");
            srv.bindport = (uint16_t)xstr_to_num(argv[i]);
        }
        else if (strcmp(argv[i], "--addr") == 0) {
            if (++i >= argc)
                errx(1, "missing ip after --addr");
            srv.bindaddr = argv[i];
        }
        else if (strcmp(argv[i], "--maxconn") == 0) {
            if (++i >= argc)
                errx(1, "missing number after --maxconn");
            srv.max_connections = (int)xstr_to_num(argv[i]);
        }
        else if (strcmp(argv[i], "--log") == 0) {
            if (++i >= argc)
                errx(1, "missing filename after --log");
            srv.logfile_name = argv[i];
        }
        else if (strcmp(argv[i], "--chroot") == 0) {
            srv.want_chroot = 1;
        }
        else if (strcmp(argv[i], "--daemon") == 0) {
            srv.want_daemon = 1;
        }
        else if (strcmp(argv[i], "--index") == 0) {
            if (++i >= argc)
                errx(1, "missing filename after --index");
            srv.index_name = argv[i];
        }
        else if (strcmp(argv[i], "--no-listing") == 0) {
            srv.no_listing = 1;
        }
        else if (strcmp(argv[i], "--mimetypes") == 0) {
            if (++i >= argc)
                errx(1, "missing filename after --mimetypes");
            parse_extension_map_file(&srv, argv[i]);
        }
        else if (strcmp(argv[i], "--default-mimetype") == 0) {
            if (++i >= argc)
                errx(1, "missing string after --default-mimetype");
            set_default_mimetype(&srv, argv[i]);
        }
        else if (strcmp(argv[i], "--uid") == 0) {
            struct passwd *p;
            if (++i >= argc)
                errx(1, "missing uid after --uid");
            p = getpwnam(argv[i]);
            if (!p) {
                p = getpwuid((uid_t)xstr_to_num(argv[i]));
            }
            if (!p)
                errx(1, "no such uid: `%s'", argv[i]);
            drop_uid = p->pw_uid;
        }
        else if (strcmp(argv[i], "--gid") == 0) {
            struct group *g;
            if (++i >= argc)
                errx(1, "missing gid after --gid");
            g = getgrnam(argv[i]);
            if (!g) {
                g = getgrgid((gid_t)xstr_to_num(argv[i]));
            }
            if (!g) {
                errx(1, "no such gid: `%s'", argv[i]);
            }
            drop_gid = g->gr_gid;
        }
        else if (strcmp(argv[i], "--pidfile") == 0) {
            if (++i >= argc)
                errx(1, "missing filename after --pidfile");
            srv.pidfile_name = argv[i];
        }
        else if (strcmp(argv[i], "--no-keepalive") == 0) {
            srv.want_keepalive = 0;
        }
        else if (strcmp(argv[i], "--accf") == 0) {
            srv.want_accf = 1;
        }
        else if (strcmp(argv[i], "--syslog") == 0) {
            srv.syslog_enabled = 1;
        }
        else if (strcmp(argv[i], "--forward") == 0) {
            const char *host, *url;
            if (++i >= argc)
                errx(1, "missing host after --forward");
            host = argv[i];
            if (++i >= argc)
                errx(1, "missing url after --forward");
            url = argv[i];
            add_forward_mapping(host, url);
        }
        else if (strcmp(argv[i], "--forward-all") == 0) {
            if (++i >= argc)
                errx(1, "missing url after --forward-all");
            srv.forward_all_url = argv[i];
        }
        else if (strcmp(argv[i], "--no-server-id") == 0) {
            srv.want_server_id = 0;
        }
        else if (strcmp(argv[i], "--timeout") == 0) {
            if (++i >= argc)
                errx(1, "missing number after --timeout");
            srv.timeout_secs = (int)xstr_to_num(argv[i]);
        }
        else if (strcmp(argv[i], "--auth") == 0) {
            if (++i >= argc || strchr(argv[i], ':') == NULL)
                errx(1, "missing 'user:pass' after --auth");

            char *key = base64_encode(argv[i]);
            xasprintf(&srv.auth_key, "Basic %s", key);
            free(key);
        }
#ifdef HAVE_INET6
        else if (strcmp(argv[i], "--ipv6") == 0) {
            srv.inet6 = 1;
        }
#endif
        else
            errx(1, "unknown argument `%s'", argv[i]);
    }
}

/* Allocate and initialize an empty connection. */
static struct connection *new_connection(void) {
    struct connection *conn = xmalloc(sizeof(struct connection));

    conn->socket = -1;
    memset(&conn->client, 0, sizeof(conn->client));
    conn->last_active = srv.now;
    conn->request = NULL;
    conn->request_length = 0;
    conn->method = NULL;
    conn->url = NULL;
    conn->referer = NULL;
    conn->user_agent = NULL;
    conn->authorization = NULL;
    conn->range_begin = 0;
    conn->range_end = 0;
    conn->range_begin_given = 0;
    conn->range_end_given = 0;
    conn->header = NULL;
    conn->header_length = 0;
    conn->header_sent = 0;
    conn->header_dont_free = 0;
    conn->header_only = 0;
    conn->http_code = 0;
    conn->conn_close = 1;
    conn->reply = NULL;
    conn->reply_dont_free = 0;
    conn->reply_fd = -1;
    conn->reply_start = 0;
    conn->reply_length = 0;
    conn->reply_sent = 0;
    conn->total_sent = 0;

    /* Make it harmless so it gets garbage-collected if it should, for some
     * reason, fail to be correctly filled out.
     */
    conn->state = DONE;

    return conn;
}

/* Accept a connection from sockin and add it to the connection queue. */
static void accept_connection(void) {
    struct sockaddr_in addrin;
#ifdef HAVE_INET6
    struct sockaddr_in6 addrin6;
#endif
    socklen_t sin_size;
    struct connection *conn;
    int fd;

#ifdef HAVE_INET6
    if (srv.inet6) {
        sin_size = sizeof(addrin6);
        memset(&addrin6, 0, sin_size);
        fd = accept(srv.sockin, (struct sockaddr *)&addrin6, &sin_size);
    } else
#endif
    {
        sin_size = sizeof(addrin);
        memset(&addrin, 0, sin_size);
        fd = accept(srv.sockin, (struct sockaddr *)&addrin, &sin_size);
    }

    if (fd == -1) {
        /* Failed to accept, but try to keep serving existing connections. */
        if (errno == EMFILE || errno == ENFILE) srv.accepting = 0;
        warn("accept()");
        return;
    }

    /* Allocate and initialize struct connection. */
    conn = new_connection();
    conn->socket = fd;
    nonblock_socket(conn->socket);
    conn->state = RECV_REQUEST;

#ifdef HAVE_INET6
    if (srv.inet6) {
        conn->client = addrin6.sin6_addr;
    } else
#endif
    {
        *(in_addr_t *)&conn->client = addrin.sin_addr.s_addr;
    }
    LIST_INSERT_HEAD(&connlist, conn, entries);

    if (debug)
        printf("accepted connection from %s:%u (fd %d)\n",
               inet_ntoa(addrin.sin_addr),
               ntohs(addrin.sin_port),
               conn->socket);

    /* Try to read straight away rather than going through another iteration
     * of the select() loop.
     */
    poll_recv_request(conn);
}

/* Should this character be logencoded?
 */
static int needs_logencoding(const unsigned char c) {
    return ((c <= 0x1F) || (c >= 0x7F) || (c == '"'));
}

/* Encode string for logging.
 */
static void logencode(const char *src, char *dest) {
    static const char hex[] = "0123456789ABCDEF";
    int i, j;

    for (i = j = 0; src[i] != '\0'; i++) {
        if (needs_logencoding((unsigned char)src[i])) {
            dest[j++] = '%';
            dest[j++] = hex[(src[i] >> 4) & 0xF];
            dest[j++] = hex[ src[i]       & 0xF];
        }
        else
            dest[j++] = src[i];
    }
    dest[j] = '\0';
}

/* Format [when] as a CLF date format, stored in the specified buffer.  The same
 * buffer is returned for convenience.
 */
#define CLF_DATE_LEN 29 /* strlen("[10/Oct/2000:13:55:36 -0700]")+1 */
static char *clf_date(char *dest, const time_t when) {
    time_t when_copy = when;
    if (strftime(dest, CLF_DATE_LEN,
                 "[%d/%b/%Y:%H:%M:%S %z]", localtime(&when_copy)) == 0)
        errx(1, "strftime() failed [%s]", dest);
    return dest;
}

/* Add a connection's details to the logfile. */
static void log_connection(const struct connection *conn) {
    char *safe_method, *safe_url, *safe_referer, *safe_user_agent,
    dest[CLF_DATE_LEN];

    if (srv.logfile == NULL)
        return;
    if (conn->http_code == 0)
        return; /* invalid - died in request */
    if (conn->method == NULL)
        return; /* invalid - didn't parse - maybe too long */

#define make_safe(x) do { \
    if (conn->x) { \
        safe_##x = xmalloc(strlen(conn->x)*3 + 1); \
        logencode(conn->x, safe_##x); \
    } else { \
        safe_##x = NULL; \
    } \
} while(0)

    make_safe(method);
    make_safe(url);
    make_safe(referer);
    make_safe(user_agent);

#define use_safe(x) safe_##x ? safe_##x : ""
  if (srv.syslog_enabled) {
    syslog(LOG_INFO, "%s - - %s \"%s %s HTTP/1.1\" %d %llu \"%s\" \"%s\"\n",
        get_address_text(&conn->client),
        clf_date(dest, srv.now),
        use_safe(method),
        use_safe(url),
        conn->http_code,
        llu(conn->total_sent),
        use_safe(referer),
        use_safe(user_agent)
        );
  } else {
    fprintf(srv.logfile, "%s - - %s \"%s %s HTTP/1.1\" %d %llu \"%s\" \"%s\"\n",
        get_address_text(&conn->client),
        clf_date(dest, srv.now),
        use_safe(method),
        use_safe(url),
        conn->http_code,
        llu(conn->total_sent),
        use_safe(referer),
        use_safe(user_agent)
        );
    fflush(srv.logfile);
  }    
#define free_safe(x) if (safe_##x) free(safe_##x)

    free_safe(method);
    free_safe(url);
    free_safe(referer);
    free_safe(user_agent);

#undef make_safe
#undef use_safe
#undef free_safe
}

/* Log a connection, then cleanly deallocate its internals. */
static void free_connection(struct connection *conn) {
    if (debug) printf("free_connection(%d)\n", conn->socket);
    log_connection(conn);
    if (conn->socket != -1) xclose(conn->socket);
    if (conn->request != NULL) free(conn->request);
    if (conn->method != NULL) free_rust_cstring(conn->method);
    if (conn->url != NULL) free_rust_cstring(conn->url);
    if (conn->referer != NULL) free_rust_cstring(conn->referer);
    if (conn->user_agent != NULL) free_rust_cstring(conn->user_agent);
    if (conn->authorization != NULL) free_rust_cstring(conn->authorization);
    if (conn->header != NULL && !conn->header_dont_free) free_rust_cstring(conn->header);
    if (conn->reply != NULL && !conn->reply_dont_free) free_rust_cstring(conn->reply);
    if (conn->reply_fd != -1) xclose(conn->reply_fd);
    /* If we ran out of sockets, try to resume accepting. */
    srv.accepting = 1;
}

/* Recycle a finished connection for HTTP/1.1 Keep-Alive. */
static void recycle_connection(struct connection *conn) {
    int socket_tmp = conn->socket;
    if (debug)
        printf("recycle_connection(%d)\n", socket_tmp);
    conn->socket = -1; /* so free_connection() doesn't close it */
    free_connection(conn);
    conn->socket = socket_tmp;

    /* don't reset conn->client */
    conn->request = NULL;
    conn->request_length = 0;
    conn->method = NULL;
    conn->url = NULL;
    conn->referer = NULL;
    conn->user_agent = NULL;
    conn->authorization = NULL;
    conn->range_begin = 0;
    conn->range_end = 0;
    conn->range_begin_given = 0;
    conn->range_end_given = 0;
    conn->header = NULL;
    conn->header_length = 0;
    conn->header_sent = 0;
    conn->header_dont_free = 0;
    conn->header_only = 0;
    conn->http_code = 0;
    conn->conn_close = 1;
    conn->reply = NULL;
    conn->reply_dont_free = 0;
    conn->reply_fd = -1;
    conn->reply_start = 0;
    conn->reply_length = 0;
    conn->reply_sent = 0;
    conn->total_sent = 0;

    conn->state = RECV_REQUEST; /* ready for another */
}

/* If a connection has been idle for more than timeout_secs, it will be
 * marked as DONE and killed off in httpd_poll().
 */
static void poll_check_timeout(struct connection *conn) {
    if (srv.timeout_secs > 0) {
        if (srv.now - conn->last_active >= srv.timeout_secs) {
            if (debug)
                printf("poll_check_timeout(%d) closing connection\n",
                       conn->socket);
            conn->conn_close = 1;
            conn->state = DONE;
        }
    }
}

extern void default_reply_impl(const struct server *srv,
        struct connection *conn, const int errcode, const char *errname,
        const char *reason);

/* A default reply for any (erroneous) occasion. */
static void default_reply(struct connection *conn,
        const int errcode, const char *errname, const char *format, ...)
        __printflike(4, 5);
static void default_reply(struct connection *conn,
        const int errcode, const char *errname, const char *format, ...) {
    char *reason;
    va_list va;

    va_start(va, format);
    xvasprintf(&reason, format, va);
    va_end(va);

    /* C wrapper just deals with formatting. */
    default_reply_impl(&srv, conn, errcode, errname, reason);

    free(reason);
}

/* Parse an HTTP request like "GET / HTTP/1.1" to get the method (GET), the
 * url (/), the referer (if given) and the user-agent (if given).  Remember to
 * deallocate all these buffers.  The method will be returned in uppercase.
 */
extern int parse_request(const struct server *srv, struct connection *conn);

/* Process a GET/HEAD request. */
extern void process_get(const struct server *srv, struct connection *conn);

/* Process a request: build the header and reply, advance state. */
static void process_request(struct connection *conn) {
    srv.num_requests++;

    if (!parse_request(&srv, conn)) {
        default_reply(conn, 400, "Bad Request",
            "You sent a request that the server couldn't understand.");
    }
    /* fail if: (auth_enabled) AND (client supplied invalid credentials) */
    else if (srv.auth_key != NULL &&
            (conn->authorization == NULL ||
             strcmp(conn->authorization, srv.auth_key)))
    {
        default_reply(conn, 401, "Unauthorized",
            "Access denied due to invalid credentials.");
    }
    else if (strcmp(conn->method, "GET") == 0) {
        process_get(&srv, conn);
    }
    else if (strcmp(conn->method, "HEAD") == 0) {
        process_get(&srv, conn);
        conn->header_only = 1;
    }
    else {
        default_reply(conn, 501, "Not Implemented",
                      "The method you specified is not implemented.");
    }

    /* advance state */
    conn->state = SEND_HEADER;

    /* request not needed anymore */
    free(conn->request);
    conn->request = NULL; /* important: don't free it again later */
}

/* Receiving request. */
static void poll_recv_request(struct connection *conn) {
    char buf[1<<15];
    ssize_t recvd;

    assert(conn->state == RECV_REQUEST);
    recvd = recv(conn->socket, buf, sizeof(buf), 0);
    if (debug)
        printf("poll_recv_request(%d) got %d bytes\n",
               conn->socket, (int)recvd);
    if (recvd < 1) {
        if (recvd == -1) {
            if (errno == EAGAIN) {
                if (debug) printf("poll_recv_request would have blocked\n");
                return;
            }
            if (debug) printf("recv(%d) error: %s\n",
                conn->socket, strerror(errno));
        }
        conn->conn_close = 1;
        conn->state = DONE;
        return;
    }
    conn->last_active = srv.now;

    /* append to conn->request */
    assert(recvd > 0);
    conn->request = xrealloc(
        conn->request, conn->request_length + (size_t)recvd + 1);
    memcpy(conn->request+conn->request_length, buf, (size_t)recvd);
    conn->request_length += (size_t)recvd;
    conn->request[conn->request_length] = 0;
    srv.total_in += (size_t)recvd;

    /* process request if we have all of it */
    if ((conn->request_length > 2) &&
        (memcmp(conn->request+conn->request_length-2, "\n\n", 2) == 0))
            process_request(conn);
    else if ((conn->request_length > 4) &&
        (memcmp(conn->request+conn->request_length-4, "\r\n\r\n", 4) == 0))
            process_request(conn);

    /* die if it's too large */
    if (conn->request_length > MAX_REQUEST_LENGTH) {
        default_reply(conn, 413, "Request Entity Too Large",
                      "Your request was dropped because it was too long.");
        conn->state = SEND_HEADER;
    }

    /* if we've moved on to the next state, try to send right away, instead of
     * going through another iteration of the select() loop.
     */
    if (conn->state == SEND_HEADER)
        poll_send_header(conn);
}

/* Sending header.  Assumes conn->header is not NULL. */
static void poll_send_header(struct connection *conn) {
    ssize_t sent;

    assert(conn->state == SEND_HEADER);
    assert(conn->header_length == strlen(conn->header));

    sent = send(conn->socket,
                conn->header + conn->header_sent,
                conn->header_length - conn->header_sent,
                0);
    conn->last_active = srv.now;
    if (debug)
        printf("poll_send_header(%d) sent %d bytes\n",
               conn->socket, (int)sent);

    /* handle any errors (-1) or closure (0) in send() */
    if (sent < 1) {
        if ((sent == -1) && (errno == EAGAIN)) {
            if (debug) printf("poll_send_header would have blocked\n");
            return;
        }
        if (debug && (sent == -1))
            printf("send(%d) error: %s\n", conn->socket, strerror(errno));
        conn->conn_close = 1;
        conn->state = DONE;
        return;
    }
    assert(sent > 0);
    conn->header_sent += (size_t)sent;
    conn->total_sent += (size_t)sent;
    srv.total_out += (size_t)sent;

    /* check if we're done sending header */
    if (conn->header_sent == conn->header_length) {
        if (conn->header_only)
            conn->state = DONE;
        else {
            conn->state = SEND_REPLY;
            /* go straight on to body, don't go through another iteration of
             * the select() loop.
             */
            poll_send_reply(conn);
        }
    }
}

/* Send chunk on socket <s> from FILE *fp, starting at <ofs> and of size
 * <size>.  Use sendfile() if possible since it's zero-copy on some platforms.
 * Returns the number of bytes sent, 0 on closure, -1 if send() failed, -2 if
 * read error.
 */
static ssize_t send_from_file(const int s, const int fd,
        off_t ofs, size_t size) {
#ifdef __FreeBSD__
    off_t sent;
    int ret = sendfile(fd, s, ofs, size, NULL, &sent, 0);

    /* It is possible for sendfile to send zero bytes due to a blocking
     * condition.  Handle this correctly.
     */
    if (ret == -1)
        if (errno == EAGAIN)
            if (sent == 0)
                return -1;
            else
                return sent;
        else
            return -1;
    else
        return size;
#else
#if defined(__linux) || defined(__sun__)
    /* Limit truly ridiculous (LARGEFILE) requests. */
    if (size > 1<<20)
        size = 1<<20;
    return sendfile(s, fd, &ofs, size);
#else
    /* Fake sendfile() with read(). */
# ifndef min
#  define min(a,b) ( ((a)<(b)) ? (a) : (b) )
# endif
    char buf[1<<15];
    size_t amount = min(sizeof(buf), size);
    ssize_t numread;

    if (lseek(fd, ofs, SEEK_SET) == -1)
        err(1, "fseek(%d)", (int)ofs);
    numread = read(fd, buf, amount);
    if (numread == 0) {
        fprintf(stderr, "premature eof on fd %d\n", fd);
        return -1;
    }
    else if (numread == -1) {
        fprintf(stderr, "error reading on fd %d: %s", fd, strerror(errno));
        return -1;
    }
    else if ((size_t)numread != amount) {
        fprintf(stderr, "read %zd bytes, expecting %zu bytes on fd %d\n",
            numread, amount, fd);
        return -1;
    }
    else
        return send(s, buf, amount, 0);
#endif
#endif
}

/* Sending reply. */
static void poll_send_reply(struct connection *conn)
{
    ssize_t sent;
    /* off_t can be wider than size_t, avoid overflow in send_len */
    const size_t max_size_t = ~((size_t)0);
    off_t send_len = conn->reply_length - conn->reply_sent;
    if (send_len > max_size_t) send_len = max_size_t;

    assert(conn->state == SEND_REPLY);
    assert(!conn->header_only);
    if (conn->reply_type == REPLY_GENERATED) {
        assert(conn->reply_length >= conn->reply_sent);
        sent = send(conn->socket,
            conn->reply + conn->reply_start + conn->reply_sent,
            (size_t)send_len, 0);
    }
    else {
        errno = 0;
        assert(conn->reply_length >= conn->reply_sent);
        sent = send_from_file(conn->socket, conn->reply_fd,
            conn->reply_start + conn->reply_sent, (size_t)send_len);
        if (debug && (sent < 1))
            printf("send_from_file returned %lld (errno=%d %s)\n",
                (long long)sent, errno, strerror(errno));
    }
    conn->last_active = srv.now;
    if (debug)
        printf("poll_send_reply(%d) sent %d: %llu+[%llu-%llu] of %llu\n",
               conn->socket, (int)sent, llu(conn->reply_start),
               llu(conn->reply_sent), llu(conn->reply_sent + sent - 1),
               llu(conn->reply_length));

    /* handle any errors (-1) or closure (0) in send() */
    if (sent < 1) {
        if (sent == -1) {
            if (errno == EAGAIN) {
                if (debug)
                    printf("poll_send_reply would have blocked\n");
                return;
            }
            if (debug)
                printf("send(%d) error: %s\n", conn->socket, strerror(errno));
        }
        else if (sent == 0) {
            if (debug)
                printf("send(%d) closure\n", conn->socket);
        }
        conn->conn_close = 1;
        conn->state = DONE;
        return;
    }
    conn->reply_sent += sent;
    conn->total_sent += (size_t)sent;
    srv.total_out += (size_t)sent;

    /* check if we're done sending */
    if (conn->reply_sent == conn->reply_length)
        conn->state = DONE;
}

/* Main loop of the httpd - a select() and then delegation to accept
 * connections, handle receiving of requests, and sending of replies.
 */
static void httpd_poll(void) {
    fd_set recv_set, send_set;
    int max_fd, select_ret;
    struct connection *conn, *next;
    int bother_with_timeout = 0;
    struct timeval timeout, t0, t1;

    timeout.tv_sec = srv.timeout_secs;
    timeout.tv_usec = 0;

    FD_ZERO(&recv_set);
    FD_ZERO(&send_set);
    max_fd = 0;

    /* set recv/send fd_sets */
#define MAX_FD_SET(sock, fdset) do { FD_SET(sock,fdset); \
                                max_fd = (max_fd<sock) ? sock : max_fd; } \
                                while (0)
    if (srv.accepting) MAX_FD_SET(srv.sockin, &recv_set);

    LIST_FOREACH_SAFE(conn, &connlist, entries, next) {
        switch (conn->state) {
        case DONE:
            /* do nothing */
            break;

        case RECV_REQUEST:
            MAX_FD_SET(conn->socket, &recv_set);
            bother_with_timeout = 1;
            break;

        case SEND_HEADER:
        case SEND_REPLY:
            MAX_FD_SET(conn->socket, &send_set);
            bother_with_timeout = 1;
            break;
        }
    }
#undef MAX_FD_SET

#if defined(__has_feature)
# if __has_feature(memory_sanitizer)
    __msan_unpoison(&recv_set, sizeof(recv_set));
    __msan_unpoison(&send_set, sizeof(send_set));
# endif
#endif

    /* -select- */
    if (debug) {
        printf("select() with max_fd %d timeout %d\n",
                max_fd, bother_with_timeout ? (int)timeout.tv_sec : 0);
        gettimeofday(&t0, NULL);
    }
    select_ret = select(max_fd + 1, &recv_set, &send_set, NULL,
        (bother_with_timeout) ? &timeout : NULL);
    if (select_ret == 0) {
        if (!bother_with_timeout)
            errx(1, "select() timed out");
    }
    if (select_ret == -1) {
        if (errno == EINTR)
            return; /* interrupted by signal */
        else
            err(1, "select() failed");
    }
    if (debug) {
        long long sec, usec;
        gettimeofday(&t1, NULL);
        sec = t1.tv_sec - t0.tv_sec;
        usec = t1.tv_usec - t0.tv_usec;
        if (usec < 0) {
            usec += 1000000;
            sec--;
        }
        printf("select() returned %d after %lld.%06lld secs\n",
                select_ret, sec, usec);
    }

    /* update time */
    srv.now = time(NULL);

    /* poll connections that select() says need attention */
    if (FD_ISSET(srv.sockin, &recv_set))
        accept_connection();

    LIST_FOREACH_SAFE(conn, &connlist, entries, next) {
        poll_check_timeout(conn);
        switch (conn->state) {
        case RECV_REQUEST:
            if (FD_ISSET(conn->socket, &recv_set)) poll_recv_request(conn);
            break;

        case SEND_HEADER:
            if (FD_ISSET(conn->socket, &send_set)) poll_send_header(conn);
            break;

        case SEND_REPLY:
            if (FD_ISSET(conn->socket, &send_set)) poll_send_reply(conn);
            break;

        case DONE:
            /* (handled later; ignore for now as it's a valid state) */
            break;
        }

        /* Handling SEND_REPLY could have set the state to done. */
        if (conn->state == DONE) {
            /* clean out finished connection */
            if (conn->conn_close) {
                LIST_REMOVE(conn, entries);
                free_connection(conn);
                free(conn);
            } else {
                recycle_connection(conn);
                /* and go right back to recv_request without going through
                 * select() again.
                 */
                poll_recv_request(conn);
            }
        }
    }
}

/* Daemonize helpers. */
#define PATH_DEVNULL "/dev/null"
static int lifeline[2] = { -1, -1 };
static int fd_null = -1;

static void daemonize_start(void) {
    pid_t f;

    if (pipe(lifeline) == -1)
        err(1, "pipe(lifeline)");

    fd_null = open(PATH_DEVNULL, O_RDWR, 0);
    if (fd_null == -1)
        err(1, "open(" PATH_DEVNULL ")");

    f = fork();
    if (f == -1)
        err(1, "fork");
    else if (f != 0) {
        /* parent: wait for child */
        char tmp[1];
        int status;
        pid_t w;

        if (close(lifeline[1]) == -1)
            warn("close lifeline in parent");
        if (read(lifeline[0], tmp, sizeof(tmp)) == -1)
            warn("read lifeline in parent");
        w = waitpid(f, &status, WNOHANG);
        if (w == -1)
            err(1, "waitpid");
        else if (w == 0)
            /* child is running happily */
            exit(EXIT_SUCCESS);
        else
            /* child init failed, pass on its exit status */
            exit(WEXITSTATUS(status));
    }
    /* else we are the child: continue initializing */
}

static void daemonize_finish(void) {
    if (fd_null == -1)
        return; /* didn't daemonize_start() so we're not daemonizing */

    if (setsid() == -1)
        err(1, "setsid");
    if (close(lifeline[0]) == -1)
        warn("close read end of lifeline in child");
    if (close(lifeline[1]) == -1)
        warn("couldn't cut the lifeline");

    /* close all our std fds */
    if (dup2(fd_null, STDIN_FILENO) == -1)
        warn("dup2(stdin)");
    if (dup2(fd_null, STDOUT_FILENO) == -1)
        warn("dup2(stdout)");
    if (dup2(fd_null, STDERR_FILENO) == -1)
        warn("dup2(stderr)");
    if (fd_null > 2)
        close(fd_null);
}

/* [->] pidfile helpers, based on FreeBSD src/lib/libutil/pidfile.c,v 1.3
 * Original was copyright (c) 2005 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 */
static int pidfile_fd = -1;
#define PIDFILE_MODE 0600

static void pidfile_remove(void) {
    if (unlink(srv.pidfile_name) == -1)
        err(1, "unlink(pidfile) failed");
 /* if (flock(pidfile_fd, LOCK_UN) == -1)
        err(1, "unlock(pidfile) failed"); */
    xclose(pidfile_fd);
    pidfile_fd = -1;
}

static int pidfile_read(void) {
    char buf[16];
    int fd, i;
    long long pid;

    fd = open(srv.pidfile_name, O_RDONLY);
    if (fd == -1)
        err(1, " after create failed");

    i = (int)read(fd, buf, sizeof(buf) - 1);
    if (i == -1)
        err(1, "read from pidfile failed");
    xclose(fd);
    buf[i] = '\0';

    if (!str_to_num(buf, &pid)) {
        err(1, "invalid pidfile contents: \"%s\"", buf);
    }
    return (int)pid;
}

static void pidfile_create(void) {
    int error, fd;
    char pidstr[16];

    /* Open the PID file and obtain exclusive lock. */
    fd = open(srv.pidfile_name,
        O_WRONLY | O_CREAT | O_EXLOCK | O_TRUNC | O_NONBLOCK, PIDFILE_MODE);
    if (fd == -1) {
        if ((errno == EWOULDBLOCK) || (errno == EEXIST))
            errx(1, "daemon already running with PID %d", pidfile_read());
        else
            err(1, "can't create pidfile %s", srv.pidfile_name);
    }
    pidfile_fd = fd;

    if (ftruncate(fd, 0) == -1) {
        error = errno;
        pidfile_remove();
        errno = error;
        err(1, "ftruncate() failed");
    }

    snprintf(pidstr, sizeof(pidstr), "%d", (int)getpid());
    if (pwrite(fd, pidstr, strlen(pidstr), 0) != (ssize_t)strlen(pidstr)) {
        error = errno;
        pidfile_remove();
        errno = error;
        err(1, "pwrite() failed");
    }
}
/* [<-] end of pidfile helpers. */

/* Close all sockets and FILEs and exit. */
static void stop_running(int sig unused) {
    srv.running = 0;
}

/* Set the keep alive field. */
extern void set_keep_alive_field(struct server *srv);

/* Execution starts here. */
int main(int argc, char **argv) {
    printf("%s, %s.\n", srv.pkgname, srv.copyright);
    parse_default_extension_map(&srv);
    parse_commandline(argc, argv);
    set_keep_alive_field(&srv);
    if (srv.want_server_id)
        xasprintf(&srv.server_hdr, "Server: %s\r\n", srv.pkgname);
    else
        srv.server_hdr = xstrdup("");
    init_sockin();

    /* open logfile */
    if (srv.logfile_name == NULL)
        srv.logfile = stdout;
    else {
        srv.logfile = fopen(srv.logfile_name, "ab");
        if (srv.logfile == NULL)
            err(1, "opening logfile: fopen(\"%s\")", srv.logfile_name);
    }

    if (srv.want_daemon)
        daemonize_start();

    /* signals */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        err(1, "signal(ignore SIGPIPE)");
    if (signal(SIGINT, stop_running) == SIG_ERR)
        err(1, "signal(SIGINT)");
    if (signal(SIGTERM, stop_running) == SIG_ERR)
        err(1, "signal(SIGTERM)");

    /* security */
    if (srv.want_chroot) {
        tzset(); /* read /etc/localtime before we chroot */
        if (chdir(srv.wwwroot) == -1)
            err(1, "chdir(%s)", srv.wwwroot);
        if (chroot(srv.wwwroot) == -1)
            err(1, "chroot(%s)", srv.wwwroot);
        printf("chrooted to `%s'\n", srv.wwwroot);
        srv.wwwroot[0] = '\0'; /* empty string */
    }
    if (drop_gid != INVALID_GID) {
        gid_t list[1];
        list[0] = drop_gid;
        if (setgroups(1, list) == -1)
            err(1, "setgroups([%d])", (int)drop_gid);
        if (setgid(drop_gid) == -1)
            err(1, "setgid(%d)", (int)drop_gid);
        printf("set gid to %d\n", (int)drop_gid);
    }
    if (drop_uid != INVALID_UID) {
        if (setuid(drop_uid) == -1)
            err(1, "setuid(%d)", (int)drop_uid);
        printf("set uid to %d\n", (int)drop_uid);
    }

    /* create pidfile */
    if (srv.pidfile_name) pidfile_create();

    if (srv.want_daemon) daemonize_finish();

    /* main loop */
    while (srv.running) httpd_poll();

    /* clean exit */
    xclose(srv.sockin);
    if (srv.logfile != NULL) fclose(srv.logfile);
    if (srv.pidfile_name) pidfile_remove();

    /* close and free connections */
    {
        struct connection *conn, *next;

        LIST_FOREACH_SAFE(conn, &connlist, entries, next) {
            LIST_REMOVE(conn, entries);
            free_connection(conn);
            free(conn);
        }
    }

    /* free the mallocs */
    {
        if (srv.forward_map)
            free(srv.forward_map);
        free(srv.wwwroot);
        free(srv.server_hdr);
        free(srv.auth_key);
    }

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
