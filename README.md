# PHP RCE Patch-Status Tools — CVE-2026-109618 / CVE-2026-109619

Three small, **read-only** tools to confirm whether your PHP installations are
patched against the critical RCE advisory published **2026-10-21** on
[php.net](https://www.php.net/archive/2026.php): a remote probe, an on-server
check, and a no-shell version endpoint.

None of them is an exploit. They do **not** trigger the vulnerabilities and send
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

## The tools

### 1. `php_patch_check.c` — remote probe

A C program that makes one harmless HTTP `GET` per site and determines patch
status from, in order of preference:

1. **endpoint** — a `vulncheck.php` marker in the response body (authoritative;
   see tool 3). This is the answer for **hosting with no shell**.
2. **header** — the version advertised in `X-Powered-By` / `Server`.
3. **fingerprint** — when neither is available, passive signals (a `PHPSESSID`
   cookie, the `Server`/distro banner) that **confirm PHP and hint at the
   branch but cannot establish the patch level**.

Use it to **sweep many sites quickly**. Verdicts per site: `PATCHED`,
`VULNERABLE?`, `UNKNOWN` (+ fingerprint), `UNREACHABLE`.

> **Why fingerprinting can't give a verdict.** The fix is a *point release*
> (e.g. 8.3.36 vs 8.3.35). No HTTP banner exposes that when the version is
> hidden, and the two bugs are memory-corruption flaws with no safe remote
> "is it patched?" oracle — the only way to probe them remotely is to attempt
> the exploit, which risks crashing your workers. So for hidden-version hosts,
> use the endpoint (tool 3) or a server-side check (tool 2).

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

### 3. `vulncheck.php` — no-shell version endpoint

For hosting with **no terminal** but where you can still upload files. Drop this
token-gated PHP file in your own webroot; it prints the **real running PHP
version** (which the server may hide from its headers) and the verdict. Read it
with a browser/`curl`, or point `php_patch_check` at its URL to fold it into a
sweep. **Delete it when done.**

```php
// 1. set a long random secret inside vulncheck.php:
$TOKEN = 'CHANGE_ME_TO_A_LONG_RANDOM_STRING';
```
```bash
# 2. generate a token, e.g.:
php -r "echo bin2hex(random_bytes(16)), PHP_EOL;"
# 3. upload, then check (404 without the correct token, so it doesn't leak):
curl "https://example.com/vulncheck.php?token=YOUR_TOKEN"
./php_patch_check "https://example.com/vulncheck.php?token=YOUR_TOKEN"
# 4. delete vulncheck.php from the server.
```

It reports `PHP_VERSION` (the upstream string), so a vendor backport may still
read `VULNERABLE_BY_VERSION` — confirm the package version with your vendor if
so.

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
2. For each flagged or unknown host, get an authoritative answer:
   - **has a shell:** run `php_patch_check_server.sh` on the server (also
     detects vendor backports);
   - **no shell (managed hosting):** upload `vulncheck.php`, read it (directly
     or via `php_patch_check "<url>?token=..."`), then delete it;
   - or check the host's control panel / ask the provider.
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
