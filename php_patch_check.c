/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Daniel Rodriguez
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. It is distributed WITHOUT ANY WARRANTY. See the LICENSE
 * file or <https://www.gnu.org/licenses/> for details.
 *
 * php_patch_check.c
 *
 * Non-destructive patch-status probe for the PHP RCE advisory of 2026-10-21
 * (CVE-2026-109618 / CVE-2026-109619).
 *
 * It does ONE harmless HTTP GET per URL and reports patch status against the
 * first patched release of each branch:
 *
 *     8.5 -> 8.5.12   8.4 -> 8.4.27   8.3 -> 8.3.36   8.2 -> 8.2.35
 *
 * For each URL it tries three sources, in order:
 *   1. ENDPOINT  -- a vulncheck.php marker in the response body (authoritative;
 *                   the no-shell method: deploy vulncheck.php, point the tool at
 *                   it with its ?token=..., read the real running version).
 *   2. HEADER    -- the version advertised in X-Powered-By / Server.
 *   3. FINGERPRINT when neither is available: it reports passive signals
 *                   (PHP session cookie, Server/distro) that confirm PHP and
 *                   hint at the branch, but CANNOT establish the patch level.
 *
 * It sends no payload and triggers neither bug. It only reads banners/markers.
 *
 * IMPORTANT CAVEATS (read before trusting the output):
 *   1. A hidden version yields UNKNOWN + fingerprint. That is not "safe" --
 *      use the endpoint, php -v over SSH, phpinfo(), or your control panel.
 *   2. Passive fingerprinting cannot tell a patched point release from an
 *      unpatched one. No HTTP banner exposes that; only the endpoint or a
 *      server-side check can.
 *   3. Distros backport fixes WITHOUT bumping the version string, so a
 *      header/endpoint "VULNERABLE?" is a strong hint -- confirm the vendor
 *      package (see php_patch_check_server.sh).
 *   4. Only probe hosts you own or are authorized to test.
 *
 * Build:
 *     cc -O2 -Wall -Wextra -o php_patch_check php_patch_check.c -lssl -lcrypto
 *
 * Usage:
 *     ./php_patch_check https://example.com https://blog.example.com:8443
 *     ./php_patch_check example.com                         # https assumed
 *     ./php_patch_check "https://example.com/vulncheck.php?token=SECRET"
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

/* Fetch the response (headers + a bounded slice of the body) into buf,
 * NUL-terminated. The body is needed so we can read a vulncheck.php marker.
 * Returns 0 on success. */
static int fetch_response(const struct url *u, char *buf, size_t buflen)
{
    int fd = tcp_connect(u->host, u->port);
    if (fd < 0) {
        fprintf(stderr, "  ! could not connect to %s:%s\n", u->host, u->port);
        return -1;
    }

    char req[2048];
    /* GET (not HEAD): some servers omit X-Powered-By on HEAD, and we also want
     * the body so a deployed vulncheck.php marker can be read. */
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
        if (off >= buflen - 1) break;             /* buffer full */
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

/* Look for a vulncheck.php marker in the response body:
 *   PHPVULNCHECK version=8.3.6 branch=8.3 verdict=... sapi=fpm-fcgi
 * On success fills maj/min/pat and (if present) copies the SAPI string.
 * Returns 1 if a version was parsed from the marker. */
static int parse_endpoint_marker(const char *resp, int *maj, int *min, int *pat,
                                 char *sapi, size_t sapilen)
{
    const char *m = strstr(resp, "PHPVULNCHECK");
    if (!m) return 0;
    const char *v = strstr(m, "version=");
    if (!v || sscanf(v + 8, "%d.%d.%d", maj, min, pat) != 3) return 0;
    if (sapi && sapilen) {
        sapi[0] = '\0';
        const char *s = strstr(m, "sapi=");
        if (s) sscanf(s + 5, "%31[^ \r\n]", sapi);
    }
    return 1;
}

/* Print whatever passive signals the response leaks when no version is known.
 * This can confirm "PHP is here" and hint at the distro, but it CANNOT
 * determine the patch level -- that is a point-release distinction no banner
 * exposes. */
static void fingerprint(const char *resp)
{
    int php = 0;
    /* Session cookie is the strongest "this is PHP" tell. */
    if (strcasestr(resp, "PHPSESSID")) { php = 1;
        printf("       - Set-Cookie PHPSESSID present (PHP confirmed)\n"); }
    if (strcasestr(resp, "X-Powered-By: PHP") || strcasestr(resp, "X-Powered-By:PHP")) {
        php = 1; printf("       - X-Powered-By names PHP (version suppressed)\n"); }

    /* Server header often leaks the distro, which hints at the vendor whose
     * backport timeline applies -- useful context, not a verdict. */
    const char *s = strcasestr(resp, "\nServer:");
    if (!s && strncasecmp(resp, "Server:", 7) == 0) s = resp - 1;
    if (s) {
        char val[160]; val[0] = '\0';
        sscanf(s + 8, " %159[^\r\n]", val);   /* leading space skips the SP after the colon */
        if (val[0]) printf("       - Server: %s\n", val);
    }
    if (!php)
        printf("       - no PHP-specific signals seen (reverse proxy/CDN, or not PHP)\n");
    printf("       -> deploy vulncheck.php for an authoritative answer "
           "(see README), or check the control panel.\n");
}

static void report_verdict(const char *raw, int maj, int min, int pat,
                           const char *source, const char *sapi)
{
    char tag[64];
    if (sapi && sapi[0]) snprintf(tag, sizeof(tag), "PHP %d.%d.%d [%s]", maj, min, pat, sapi);
    else                 snprintf(tag, sizeof(tag), "PHP %d.%d.%d", maj, min, pat);

    int r = compare_patch(maj, min, pat);
    if (r < 0)
        printf("[!] %-38s  VULNERABLE?   %s via %s "
               "(older than branch fix -- confirm vendor backport)\n",
               raw, tag, source);
    else if (r == 0)
        printf("[+] %-38s  PATCHED       %s via %s\n", raw, tag, source);
    else
        printf("[?] %-38s  branch %d.%d not in advisory table (EOL/other) -- "
               "%s via %s, check vendor\n", raw, maj, min, tag, source);
}

static void check_one(const char *raw)
{
    struct url u;
    if (parse_url(raw, &u) != 0) {
        printf("[?] %-38s  invalid URL\n", raw);
        return;
    }

    char resp[HDR_BUF];
    if (fetch_response(&u, resp, sizeof(resp)) != 0) {
        printf("[?] %-38s  UNREACHABLE\n", raw);
        return;
    }

    int maj, min, pat;
    char sapi[32];

    /* 1. Authoritative: a deployed vulncheck.php marker in the body. */
    if (parse_endpoint_marker(resp, &maj, &min, &pat, sapi, sizeof(sapi))) {
        report_verdict(raw, maj, min, pat, "endpoint", sapi);
        return;
    }

    /* 2. Advertised banner: X-Powered-By / Server header. */
    if (extract_php_version(resp, &maj, &min, &pat)) {
        report_verdict(raw, maj, min, pat, "header", NULL);
        return;
    }

    /* 3. No version anywhere -- fall back to passive fingerprinting. */
    printf("[?] %-38s  UNKNOWN (version not disclosed)\n", raw);
    fingerprint(resp);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <url> [url ...]\n"
            "  Reports PHP patch status vs the 2026-10-21 advisory fixes\n"
            "  (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) using, in order: a deployed\n"
            "  vulncheck.php marker, the advertised header version, then passive\n"
            "  fingerprinting. Non-destructive: it only reads banners/markers.\n"
            "  For hosts with no shell, deploy vulncheck.php and pass its URL\n"
            "  including ?token=... (see README).\n",
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
    printf("Note: UNKNOWN != safe -- fingerprinting cannot read the patch\n"
           "level. For those hosts deploy vulncheck.php or check server-side.\n"
           "Distro backports keep old version strings, so a VULNERABLE? verdict\n"
           "still needs vendor confirmation.\n");
    return 0;
}
