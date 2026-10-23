<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Daniel Rodriguez
 *
 * vulncheck.php -- authoritative, no-shell patch check for the PHP RCE
 * advisory of 2026-10-21 (CVE-2026-109618 / CVE-2026-109619).
 *
 * For hosting with NO terminal access: upload this file to your own webroot,
 * request it once (see below), read the verdict, then DELETE it. It prints the
 * REAL running PHP version -- which the server may hide from its HTTP headers --
 * and the verdict against the advisory's fix table. php_patch_check reads the
 * "PHPVULNCHECK ..." marker line automatically.
 *
 * It is read-only: it reports php version/SAPI/ini values and changes nothing.
 *
 * SETUP (required):
 *   1. Set $TOKEN below to a long random string, e.g. the output of:
 *          php -r "echo bin2hex(random_bytes(16)), PHP_EOL;"
 *      (or any password-manager random string). Without the right token the
 *      page returns 404, so it does not leak your version to the world.
 *   2. Upload vulncheck.php to your webroot.
 *   3. Check it:
 *          curl "https://example.com/vulncheck.php?token=YOUR_TOKEN"
 *      or:
 *          ./php_patch_check "https://example.com/vulncheck.php?token=YOUR_TOKEN"
 *   4. DELETE vulncheck.php from the server when done.
 *
 * CAVEAT: this reports PHP_VERSION, the upstream version string. If your distro
 * backported the fix without bumping that string, the verdict may read
 * VULNERABLE_BY_VERSION even though you are patched -- confirm the package
 * version with your vendor's advisory (see php_patch_check_server.sh).
 */

// === 1. SET THIS to a long random secret before uploading ====================
$TOKEN = 'CHANGE_ME_TO_A_LONG_RANDOM_STRING';
// =============================================================================

header('Content-Type: text/plain; charset=utf-8');
header('X-Robots-Tag: noindex, nofollow');

$provided = isset($_GET['token']) ? (string) $_GET['token'] : '';
if ($TOKEN === 'CHANGE_ME_TO_A_LONG_RANDOM_STRING' || !hash_equals($TOKEN, $provided)) {
    // Do not reveal that this endpoint exists without the correct token.
    http_response_code(404);
    echo "Not Found\n";
    exit;
}

// First patched release per supported branch (from the advisory).
$fixes = array('8.5' => 12, '8.4' => 27, '8.3' => 36, '8.2' => 35);

$maj    = PHP_MAJOR_VERSION;
$min    = PHP_MINOR_VERSION;
$rel    = PHP_RELEASE_VERSION;
$branch = $maj . '.' . $min;

if (isset($fixes[$branch])) {
    $verdict = ($rel >= $fixes[$branch]) ? 'PATCHED' : 'VULNERABLE_BY_VERSION';
} else {
    // 8.1 and older are EOL upstream; rely on a vendor/backport build.
    $verdict = 'UNKNOWN_BRANCH';
}

// Machine-readable marker line that php_patch_check parses:
printf("PHPVULNCHECK version=%s branch=%s verdict=%s sapi=%s\n",
       PHP_VERSION, $branch, $verdict, PHP_SAPI);

// Human-readable detail (ignored by the tool).
echo "----\n";
echo "PHP version : " . PHP_VERSION . "\n";
echo "SAPI        : " . PHP_SAPI . "\n";
echo "Branch fix  : " . (isset($fixes[$branch]) ? "$branch.{$fixes[$branch]}" : "n/a (EOL/unsupported)") . "\n";
echo "Verdict     : $verdict\n";

// Advisory interim-mitigation settings, for context.
$up = ini_get('session.upload_progress.enabled');
echo "session.upload_progress.enabled : " . ($up === false ? 'n/a' : ($up ? 'On' : 'Off')) . "\n";
if ($branch === '8.5') {
    $fb = ini_get('fatal_error_backtraces');
    echo "fatal_error_backtraces          : " . ($fb === false ? 'n/a' : ($fb ? 'On' : 'Off')) . "\n";
}
echo "----\n";
echo "Reminder: delete this file from the server when you are done.\n";
echo "If VULNERABLE_BY_VERSION, confirm against your vendor's backport before acting.\n";
