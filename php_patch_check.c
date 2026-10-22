/*
 * php_patch_check.c
 *
 * Non-destructive patch-status probe for the PHP RCE advisory of 2026-10-21
 * (CVE-2026-109618 / CVE-2026-109619).
 *
 * It does ONE harmless HTTP request per URL, reads the PHP version the server
 * advertises in its response headers (X-Powered-By / Server), and compares it
 * against the first patched release of each branch:
 *
 *     8.5 -> 8.5.12   8.4 -> 8.4.27   8.3 -> 8.3.36   8.2 -> 8.2.35
 *
 * It sends no payload and triggers neither bug. It only reads version banners.
 *
 * IMPORTANT CAVEATS (read these before trusting the output):
 *   1. Many hosts set expose_php=Off, so no version is advertised. Then this
 *      tool reports UNKNOWN -- that is not "safe", it just means you must check
 *      another way (php -v over SSH, phpinfo(), or your control panel).
 *   2. Distros (Debian/RHEL/Ubuntu/cPanel/Plesk vendors) backport security
 *      fixes WITHOUT bumping the upstream version string. A box showing
 *      "8.2.20" may well be patched by the vendor. A version-based VULNERABLE
 *      verdict for such a build is only a strong hint -- confirm with the
 *      vendor's package changelog.
 *   3. Only probe hosts you own or are authorized to test.
 *
 * Build:
 *     cc -O2 -Wall -Wextra -o php_patch_check php_patch_check.c -lssl -lcrypto
 *
 * Usage:
 *     ./php_patch_check https://example.com https://blog.example.com:8443
 *     ./php_patch_check example.com                # https assumed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifndef NO_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define HDR_BUF 65536

/* First patched release per supported branch. */
struct branch {
    int major, minor, patch;
};
static const struct branch PATCHED[] = {
    {8, 5, 12},
    {8, 4, 27},
    {8, 3, 36},
    {8, 2, 35},
};
static const size_t N_PATCHED = sizeof(PATCHED) / sizeof(PATCHED[0]);

struct url {
    int   https;
    char  host[512];
    char  port[8];
    char  path[1024];
};

static int parse_url(const char *in, struct url *u)
{
    const char *p = in;
    u->https = 1;                 /* default to https */
    strcpy(u->port, "443");
    strcpy(u->path, "/");

    if (strncasecmp(p, "https://", 8) == 0) { u->https = 1; p += 8; }
    else if (strncasecmp(p, "http://", 7) == 0) {
        u->https = 0; p += 7; strcpy(u->port, "80");
    }

    /* host[:port], up to the first '/' */
    char authority[512];
    size_t i = 0;
    while (*p && *p != '/' && i < sizeof(authority) - 1)
        authority[i++] = *p++;
    authority[i] = '\0';
    if (*p == '/')
        snprintf(u->path, sizeof(u->path), "%s", p);

    char *colon = strrchr(authority, ':');
    if (colon) {
        *colon = '\0';
        snprintf(u->port, sizeof(u->port), "%s", colon + 1);
    }
    snprintf(u->host, sizeof(u->host), "%s", authority);
    return u->host[0] ? 0 : -1;
}

/* Open a TCP connection; returns fd or -1. */
static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Fetch raw response headers into buf (NUL-terminated). Returns 0 on success. */
static int fetch_headers(const struct url *u, char *buf, size_t buflen)
{
    int fd = tcp_connect(u->host, u->port);
    if (fd < 0) {
        fprintf(stderr, "  ! could not connect to %s:%s\n", u->host, u->port);
        return -1;
    }

    char req[2048];
    /* GET is used (not HEAD) because some servers answer HEAD without the
     * X-Powered-By header; we stop reading as soon as headers end. */
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: php-patch-check/1.0\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n\r\n",
             u->path, u->host);

#ifndef NO_TLS
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
#endif
    int rc = -1;

#ifdef NO_TLS
    if (u->https) {
        fprintf(stderr, "  ! built without TLS (NO_TLS); cannot probe %s over "
                        "https -- install libssl-dev or use http://\n", u->host);
        close(fd);
        return -1;
    }
    if (write(fd, req, strlen(req)) < 0) goto done;
#else
    if (u->https) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) goto done;
        /* We are reading a public version banner, not transferring secrets,
         * so we do not hard-fail on cert problems; we just want the header. */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, u->host);   /* SNI */
        if (SSL_connect(ssl) != 1) {
            fprintf(stderr, "  ! TLS handshake failed for %s\n", u->host);
            goto done;
        }
        if (SSL_write(ssl, req, (int)strlen(req)) <= 0) goto done;
    } else {
        if (write(fd, req, strlen(req)) < 0) goto done;
    }
#endif

    size_t off = 0;
    for (;;) {
        int n;
#ifndef NO_TLS
        if (u->https) n = SSL_read(ssl, buf + off, (int)(buflen - 1 - off));
        else          n = (int)read(fd, buf + off, buflen - 1 - off);
#else
        n = (int)read(fd, buf + off, buflen - 1 - off);
#endif
        if (n <= 0) break;
        off += (size_t)n;
        buf[off] = '\0';
        if (strstr(buf, "\r\n\r\n")) break;       /* headers complete */
        if (off >= buflen - 1) break;
    }
    buf[off] = '\0';
    rc = (off > 0) ? 0 : -1;

done:
#ifndef NO_TLS
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
#endif
    close(fd);
    return rc;
}

/* Find "PHP/<maj>.<min>.<patch>" anywhere in the headers. Returns 1 if found. */
static int extract_php_version(const char *headers, int *maj, int *min, int *pat)
{
    const char *p = headers;
    while ((p = strcasestr(p, "PHP/")) != NULL) {
        if (sscanf(p + 4, "%d.%d.%d", maj, min, pat) == 3)
            return 1;
        p += 4;
    }
    return 0;
}

/* <0 if version is older than its branch's fix, 0 if >= fix, 1 if branch
 * is not in our patched table (unknown/EOL branch). */
static int compare_patch(int maj, int min, int pat)
{
    for (size_t i = 0; i < N_PATCHED; i++) {
        if (PATCHED[i].major == maj && PATCHED[i].minor == min) {
            if (pat < PATCHED[i].patch) return -1;   /* vulnerable */
            return 0;                                /* patched */
        }
    }
    return 1;                                        /* branch unknown */
}

static void check_one(const char *raw)
{
    struct url u;
    if (parse_url(raw, &u) != 0) {
        printf("[?] %-40s  invalid URL\n", raw);
        return;
    }

    char headers[HDR_BUF];
    if (fetch_headers(&u, headers, sizeof(headers)) != 0) {
        printf("[?] %-40s  UNREACHABLE\n", raw);
        return;
    }

    int maj, min, pat;
    if (!extract_php_version(headers, &maj, &min, &pat)) {
        printf("[?] %-40s  UNKNOWN (no PHP version advertised; "
               "check php -v / phpinfo / control panel)\n", raw);
        return;
    }

    int r = compare_patch(maj, min, pat);
    if (r < 0) {
        printf("[!] %-40s  VULNERABLE?  reports PHP/%d.%d.%d "
               "(branch fix is higher) -- confirm vendor backport\n",
               raw, maj, min, pat);
    } else if (r == 0) {
        printf("[+] %-40s  PATCHED       reports PHP/%d.%d.%d\n",
               raw, maj, min, pat);
    } else {
        printf("[?] %-40s  branch %d.%d not in advisory table "
               "(EOL/other) -- reports PHP/%d.%d.%d, check vendor\n",
               raw, maj, min, maj, min, pat);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <url> [url ...]\n"
            "  Reads the advertised PHP version and compares it against the\n"
            "  2026-10-21 advisory fixes (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).\n"
            "  Non-destructive: it only reads response headers.\n",
            argv[0]);
        return 2;
    }

#ifndef NO_TLS
    SSL_library_init();
    SSL_load_error_strings();
#endif

    printf("PHP patch-status probe (CVE-2026-109618 / -109619)\n");
    printf("Fixes: 8.5.12  8.4.27  8.3.36  8.2.35\n");
    printf("------------------------------------------------------------\n");

    for (int i = 1; i < argc; i++)
        check_one(argv[i]);

    printf("------------------------------------------------------------\n");
    printf("Note: UNKNOWN != safe. Distro backports keep old version\n"
           "strings, so a VULNERABLE? verdict needs vendor confirmation.\n");
    return 0;
}
