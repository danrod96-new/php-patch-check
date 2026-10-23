#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Daniel Rodriguez
#
# scan_serialize_handler.sh -- source audit for the CVE-2026-115560 code
# pattern (informational advisory, PHP, Oct 2026).
#
# CVE-2026-115560 is only reachable when BOTH hold:
#   1. session.upload_progress.enabled is On (check with vulncheck.php /
#      php_patch_check_server.sh), AND
#   2. application code switches session.serialize_handler to "php" at RUNTIME
#      via ini_set() before session_start().
#
# No scanner can prove exploitability, but (2) is a specific code pattern this
# script greps for. It is read-only: it only reads your source files.
#
# Usage:
#   sh scan_serialize_handler.sh [path ...]      # default: current directory
#
# Exit: 1 if the high-risk pattern (switch to 'php') is found, else 0.

set -u

paths=${*:-.}

# Quote class matching either ' or " ; built in a double-quoted string so both
# quote characters can appear literally.
Q="[\"']"

# HIGH: ini_set(..., 'session.serialize_handler', 'php')  -- the dangerous switch
RE_HIGH="ini_set[[:space:]]*\([[:space:]]*${Q}session\.serialize_handler${Q}[[:space:]]*,[[:space:]]*${Q}php${Q}"
# ANY: any runtime ini_set of session.serialize_handler (context / precondition)
RE_ANY="ini_set[[:space:]]*\([[:space:]]*${Q}session\.serialize_handler${Q}"

find_php() {
    find "$@" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.inc' \
                         -o -name '*.module' \) 2>/dev/null
}

echo "CVE-2026-115560 source audit"
echo "Scanning: $paths"
echo "------------------------------------------------------------"

files=$(find_php $paths)
if [ -z "$files" ]; then
    echo "No PHP source files (*.php, *.phtml, *.inc, *.module) found under: $paths"
    exit 0
fi

# High-risk: the runtime switch to 'php'.
high=$(printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 grep -nHE "$RE_HIGH" 2>/dev/null)
if [ -n "$high" ]; then
    echo "[HIGH] runtime switch of session.serialize_handler to 'php' found:"
    printf '%s\n' "$high" | sed 's/^/   /'
    echo
    echo "   Review each: if session_start() is reached afterward while upload"
    echo "   progress is enabled, this is the CVE-2026-115560 vector. Set"
    echo "   session.upload_progress.enabled=0 (or avoid the runtime switch)."
else
    echo "[ok]   no runtime switch of session.serialize_handler to 'php' found."
fi

echo "------------------------------------------------------------"

# Context: any other runtime ini_set of the handler (e.g. to php_binary).
other=$(printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 grep -nHE "$RE_ANY" 2>/dev/null \
        | grep -vE "$RE_HIGH")
if [ -n "$other" ]; then
    echo "[info] other runtime ini_set of session.serialize_handler (review for context):"
    printf '%s\n' "$other" | sed 's/^/   /'
    echo "------------------------------------------------------------"
fi

echo "Note: a grep cannot confirm exploitability (control flow, config, and"
echo "whether upload progress is enabled all matter). Treat HIGH hits as"
echo "'review these', not 'definitely vulnerable'. The simplest fix remains"
echo "session.upload_progress.enabled=0 until the fixed release."

[ -n "$high" ] && exit 1
exit 0
