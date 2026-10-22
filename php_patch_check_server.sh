#!/bin/sh
# php_patch_check_server.sh
#
# Run this ON the server (e.g. over SSH) to confirm whether the PHP RCE
# advisory of 2026-10-21 (CVE-2026-109618 / CVE-2026-109619) is patched.
#
# Unlike a network banner probe, this reads the REAL installed version of
# every PHP SAPI present and then inspects the OS package changelog, so it
# also catches vendor BACKPORTS -- fixes shipped without bumping the upstream
# version string (common on Debian/Ubuntu/RHEL/cPanel).
#
# It is strictly read-only: it runs `-v`, queries the package DB, and reads
# php.ini. It changes nothing and triggers neither bug.
#
# Usage:
#   sh php_patch_check_server.sh
#
# Exit status: 0 all clear, 1 at least one SAPI looks vulnerable,
#              2 at least one UNKNOWN (could not determine), checked in that
#              order of precedence (1 wins over 2).

set -u

# First patched upstream release per branch (from the advisory).
# branch:fix
FIXES="8.5:8.5.12 8.4:8.4.27 8.3:8.3.36 8.2:8.2.35"
CVES="CVE-2026-109618 CVE-2026-109619"

RC=0            # final exit code
set_rc() {      # set_rc <code>; 1 beats 2 beats 0
    case "$1" in
        1) RC=1 ;;
        2) [ "$RC" = 1 ] || RC=2 ;;
    esac
}

say()  { printf '%s\n' "$*"; }
hr()   { printf -- '------------------------------------------------------------\n'; }

# numeric compare of a.b.c vs the branch fix. echoes: patched|vulnerable|unknownbranch
version_verdict() {
    v=$1
    maj=$(printf '%s' "$v" | cut -d. -f1)
    min=$(printf '%s' "$v" | cut -d. -f2)
    pat=$(printf '%s' "$v" | cut -d. -f3)
    case "$maj$min$pat" in *[!0-9]*|'') echo unknownbranch; return;; esac
    for pair in $FIXES; do
        br=${pair%:*}; fix=${pair#*:}
        if [ "$maj.$min" = "$br" ]; then
            fpat=${fix##*.}
            if [ "$pat" -lt "$fpat" ]; then echo vulnerable; else echo patched; fi
            return
        fi
    done
    echo unknownbranch
}

# --- discover PHP SAPIs -------------------------------------------------------
# CLI + versioned CLIs + FPM binaries, from PATH and common locations.
discover() {
    {
        command -v php 2>/dev/null
        for p in /usr/bin /usr/local/bin /opt/remi/*/root/usr/bin \
                 /opt/cpanel/ea-php*/root/usr/bin /opt/plesk/php/*/bin; do
            for b in "$p"/php "$p"/php[0-9]* "$p"/php-fpm "$p"/php-fpm[0-9]* \
                     "$p"/php-cgi "$p"/php-cgi[0-9]*; do
                [ -x "$b" ] && printf '%s\n' "$b"
            done 2>/dev/null
        done
        # FPM master binaries that may live in sbin
        for p in /usr/sbin /usr/local/sbin; do
            for b in "$p"/php-fpm "$p"/php-fpm[0-9]*; do
                [ -x "$b" ] && printf '%s\n' "$b"
            done 2>/dev/null
        done
    } | sort -u
}

# --- vendor changelog / backport check ---------------------------------------
# Given a binary path, find the owning package and report whether the INSTALLED
# package's changelog mentions either CVE or a fixed upstream version. Because a
# .deb/.rpm ships the changelog for exactly the version installed, a mention
# there is strong evidence the running build already contains the backport.
# Returns 0 = backport confirmed, 1 = not confirmed. Offline where possible.
vendor_backport() {
    bin=$1
    if command -v dpkg-query >/dev/null 2>&1; then
        pkg=$(dpkg-query -S "$(readlink -f "$bin")" 2>/dev/null | head -n1 | cut -d: -f1)
        [ -z "$pkg" ] && { echo "  vendor: dpkg package for $bin not found"; return 1; }
        pkgver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)
        echo "  vendor: $pkg $pkgver (Debian/Ubuntu)"
        ch=$(ls /usr/share/doc/"$pkg"/changelog.Debian.gz \
                /usr/share/doc/"$pkg"/changelog.gz 2>/dev/null | head -n1)
        if [ -n "$ch" ]; then
            hit=$(zcat "$ch" 2>/dev/null | grep -iE "$(echo $CVES | tr ' ' '|')|8\.[2345]\.(35|36|27|12)" | head -n3)
            if [ -n "$hit" ]; then
                echo "  vendor: installed package's changelog MENTIONS the fix:"
                printf '%s\n' "$hit" | sed 's/^/          /'
                return 0
            fi
            echo "  vendor: no CVE/fix mention in local changelog (try: apt-get changelog $pkg)"
            return 1
        fi
        echo "  vendor: local changelog not found (try: apt-get changelog $pkg)"
        return 1
    elif command -v rpm >/dev/null 2>&1; then
        pkg=$(rpm -qf "$(readlink -f "$bin")" 2>/dev/null | head -n1)
        [ -z "$pkg" ] && { echo "  vendor: rpm package for $bin not found"; return 1; }
        echo "  vendor: $pkg (RHEL family)"
        hit=$(rpm -q --changelog "$pkg" 2>/dev/null | grep -iE "$(echo $CVES | tr ' ' '|')" | head -n3)
        if [ -n "$hit" ]; then
            echo "  vendor: installed package's changelog MENTIONS a CVE fix:"
            printf '%s\n' "$hit" | sed 's/^/          /'
            return 0
        fi
        echo "  vendor: no CVE mention in rpm changelog"
        return 1
    fi
    echo "  vendor: no dpkg/rpm found; cannot check backport (source build?)"
    return 1
}

# --- relevant interim mitigations (advisory) ----------------------------------
check_mitigations() {
    bin=$1 ver=$2
    maj_min=$(printf '%s' "$ver" | cut -d. -f1,2)
    up=$("$bin" -i 2>/dev/null | awk -F'=>' '/session.upload_progress.enabled/{gsub(/ /,"",$2);print $2;exit}')
    [ -n "$up" ] && echo "  mitig : session.upload_progress.enabled = $up (advisory suggests 0 as interim)"
    if [ "$maj_min" = "8.5" ]; then
        fb=$("$bin" -i 2>/dev/null | awk -F'=>' '/fatal_error_backtraces/{gsub(/ /,"",$2);print $2;exit}')
        [ -n "$fb" ] && echo "  mitig : fatal_error_backtraces = $fb (advisory suggests 0 on 8.5)"
    fi
}

# --- main ---------------------------------------------------------------------
say "PHP on-server patch check  (CVE-2026-109618 / CVE-2026-109619)"
say "Fixed in: 8.5.12  8.4.27  8.3.36  8.2.35"
say "Host: $(uname -n)   Date: $(date -u '+%Y-%m-%d %H:%M UTC')"
hr

bins=$(discover)
if [ -z "$bins" ]; then
    say "No PHP binaries found in PATH or common locations."
    say "If PHP runs only as an Apache module, check: apachectl -M | grep php,"
    say "then the module's package version via dpkg -l / rpm -qa."
    exit 2
fi

for bin in $bins; do
    raw=$("$bin" -v 2>/dev/null | head -n1)
    ver=$(printf '%s' "$raw" | sed -n 's/^PHP \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    say "SAPI : $bin"
    if [ -z "$ver" ]; then
        say "  ver  : could not parse ($raw)"
        say "  VERDICT: UNKNOWN"
        set_rc 2; hr; continue
    fi
    say "  ver  : PHP $ver"
    verdict=$(version_verdict "$ver")
    case "$verdict" in
        patched)
            say "  VERDICT: PATCHED (version string is at or past the branch fix)"
            ;;
        vulnerable)
            if vendor_backport "$bin"; then
                say "  VERDICT: LIKELY PATCHED via vendor backport"
                say "           (upstream version $ver is old, but the installed"
                say "           package ships the CVE fix -- verify the package"
                say "           version against your vendor's advisory to be sure)."
            else
                say "  VERDICT: VULNERABLE -- version $ver is older than the branch"
                say "           fix and no vendor backport was found. Update PHP."
                set_rc 1
            fi
            ;;
        unknownbranch)
            say "  VERDICT: UNKNOWN branch $ver (EOL or unsupported here)."
            say "           8.1 and older need a vendor/backport build -- verify manually."
            set_rc 2
            ;;
    esac
    [ "$verdict" = patched ] || true
    check_mitigations "$bin" "$ver"
    hr
done

say "Legend: PATCHED = safe by version. VULNERABLE = older than the branch fix;"
say "confirm with the 'vendor:' line (backports keep old version numbers)."
say "UNKNOWN = determine manually. The ONLY complete fix is updating PHP."
exit $RC
