# PHP RCE Patch-Status Tools — CVE-2026-109618 / CVE-2026-109619

Two small, **read-only** tools to confirm whether your PHP installations are
patched against the critical RCE advisory published **2026-10-21** on
[php.net](https://www.php.net/archive/2026.php).

Neither tool is an exploit. They do **not** trigger the vulnerabilities and send
no attack payload — they only read version information. The goal is a clean
"patched / not patched" answer for servers you own or are authorized to test.

---

## The vulnerability

The advisory covers two unauthenticated remote-code-execution bugs in the PHP
request lifecycle, each rated CVSS v4.0 9.2:

| CVE | GHSA | Summary |
|-----|------|---------|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | Out-of-memory handling can interrupt PHP while request data is only partially initialized; request cleanup may then treat invalid data as valid. |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | Request-owned internal state can survive after its memory is freed (use-after-free), so a later request on the same worker may use stale state. |

**Affected:** all PHP installations serving web requests (PHP-FPM, Apache
`mod_php`, `php-cgi`, FrankenPHP, LiteSpeed). `mod_php` is rated highest risk.

**Fixed upstream in:**

| Branch | First patched release |
|--------|-----------------------|
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** |

PHP 8.1 and older are end-of-life upstream; minimal source backports exist for
7.4 / 8.0 / 8.1, and many distributions ship their own backports. **Updating is
the only complete fix**; the advisory's interim mitigations do not make an
installation safe.

---

## The two tools

### 1. `php_patch_check.c` — network banner probe

A C program that makes one harmless HTTP `GET` per site, reads the PHP version
advertised in the `X-Powered-By` / `Server` response headers, and compares it
to the fix table. Use it to **sweep many sites quickly** and find the obvious
misses.

Verdicts per site: `PATCHED`, `VULNERABLE?`, `UNKNOWN` (no version advertised),
`UNREACHABLE`.

### 2. `php_patch_check_server.sh` — on-server authoritative check

A POSIX shell script you run **on the server** (e.g. over SSH). It:

- discovers every PHP SAPI present (CLI, versioned CLIs, `php-fpm`, `php-cgi`,
  including cPanel / Plesk / Remi paths);
- reads each real installed version and compares it to the fix table;
- reads the **installed package's changelog** (`dpkg` / `rpm`) to detect
  **vendor backports** — fixes shipped without bumping the upstream version;
- reports the advisory's interim mitigation settings
  (`session.upload_progress.enabled`, and `fatal_error_backtraces` on 8.5).

Verdicts per SAPI: `PATCHED`, `LIKELY PATCHED via vendor backport`,
`VULNERABLE`, `UNKNOWN`.
Exit code: `0` all clear, `1` a genuine vulnerability found, `2` an unknown
(with `1` taking precedence) — suitable for cron / monitoring.

---

## Build & run

### `php_patch_check.c`

Requires OpenSSL development headers for HTTPS.

```bash
# Debian / Ubuntu
sudo apt install libssl-dev
# RHEL / Alma / Rocky
sudo dnf install openssl-devel

cc -O2 -Wall -Wextra -D_GNU_SOURCE -o php_patch_check php_patch_check.c -lssl -lcrypto
```

Run against your sites:

```bash
./php_patch_check https://example.com https://blog.example.com:8443
```

If you cannot install the OpenSSL headers, a headers-free build is available for
plain-HTTP targets only:

```bash
cc -O2 -Wall -Wextra -D_GNU_SOURCE -DNO_TLS -o php_patch_check_notls php_patch_check.c
./php_patch_check_notls http://internal-host.example
```

### `php_patch_check_server.sh`

No build step; needs only a POSIX shell. Copy it to the server and run:

```bash
sh php_patch_check_server.sh
```

Over SSH in one shot:

```bash
ssh user@your-server 'sh -s' < php_patch_check_server.sh
```

---

## Recommended workflow

1. Run `php_patch_check` from your machine to sweep all sites and flag anything
   that is not a clean `PATCHED` (expect many `UNKNOWN`s — well-configured hosts
   set `expose_php=Off` and advertise no version).
2. For each flagged or unknown host, run `php_patch_check_server.sh` on the
   server for the authoritative answer, including backport detection.
3. Update any host that is not patched to the fixed release for its branch (or
   your vendor's fixed package).

---

## ⚠️ Warnings & limitations

- **Authorization.** Only probe or run these against systems you own or have
  explicit permission to test. Scanning third-party hosts may be unlawful.
- **`UNKNOWN` is not "safe."** It means the version could not be determined —
  verify another way (`php -v`, `phpinfo()`, control panel).
- **Version strings lie (backports).** Distributions patch security bugs
  *without* changing the upstream version number. A `VULNERABLE?` verdict from
  the network probe is only a hint; confirm with the on-server script or your
  vendor's advisory.
- **`LIKELY PATCHED via vendor backport` is strong evidence, not proof.** The
  server script matches a CVE string in the installed package's changelog. For a
  hard guarantee, confirm the exact package version against your vendor's
  security advisory (Ubuntu USN, Debian DSA, RHEL errata, your host's changelog).
- **These tools only check PHP.** They do not detect WAF rules, proxy-level
  limits, or whether mitigations were actually effective.
- **Not a substitute for updating.** Per the advisory, interim mitigations do
  not make an installation safe. Patch.

---

## License

Copyright (C) 2026 Daniel Rodriguez.

This project is licensed under the **GNU General Public License v3.0 or later**
(GPL-3.0-or-later). You may redistribute and/or modify it under those terms. It
is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the [LICENSE](LICENSE) file or <https://www.gnu.org/licenses/> for
the full text.
