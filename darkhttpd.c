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

struct connection {
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
    void *connections;          /* used by Rust */
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

#define INVALID_UID ((uid_t) -1)
#define INVALID_GID ((gid_t) -1)

static uid_t drop_uid = INVALID_UID;
static gid_t drop_gid = INVALID_GID;

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

extern int connection_exists(const struct server *srv, int index);

extern struct connection *get_connection(struct server *srv, int index);

extern void remove_connection(struct server *srv, int index);

/* Log a connection, then cleanly deallocate its internals. */
extern void free_connection(struct server *srv, struct connection *conn);

/* Main loop of the httpd - a select() and then delegation to accept
 * connections, handle receiving of requests, and sending of replies.
 */
extern void httpd_poll(struct server *srv);

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

/* Initialize connections list. */
extern void init_connections_list(struct server *srv);

extern void free_connections_list(struct server *srv);

extern void free_mime_map(struct server *srv);

extern void free_keep_alive_field(struct server *srv);

/* Execution starts here. */
int main(int argc, char **argv) {
    printf("%s, %s.\n", srv.pkgname, srv.copyright);
    init_connections_list(&srv);
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
    while (srv.running) httpd_poll(&srv);

    /* clean exit */
    xclose(srv.sockin);
    if (srv.logfile != NULL) fclose(srv.logfile);
    if (srv.pidfile_name) pidfile_remove();

    /* close and free connections */
    {
        while (connection_exists(&srv, 0)) {
            struct connection *conn = get_connection(&srv, 0);
            free_connection(&srv, conn);  // logs connection and drops fields
            remove_connection(&srv, 0); // drops connection
        }
    }

    /* free the mallocs */
    {
        if (srv.forward_map)
            free(srv.forward_map);
        free(srv.wwwroot);
        free(srv.server_hdr);
        free(srv.auth_key);
        free_connections_list(&srv);
        free_mime_map(&srv);
        free_keep_alive_field(&srv);
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
