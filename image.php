<?php

// H7 remediation: this endpoint is deliberately excluded from config.php's
// blanket per-IP rate limit — it enforces its own, separately-sized limit
// below instead (see RATE_LIMIT_IMAGE_* in config.php for why: shared image
// links are meant for high-volume public viewing — mass email, advertising —
// so they need a much larger budget than login/admin actions, and mixing the
// two buckets would either throttle legitimate view traffic or weaken the
// protection the blanket limit is meant to give the rest of the app).
define('SKIP_GLOBAL_RATE_LIMIT', true);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/Autoloader.php';

use App\ImageMetadata;

// H7/H11 remediation: this is the ONLY path that can serve a stored image —
// IMAGES_DIR lives outside the web document root (see config.php) and Apache
// can no longer reach it directly. That closes two gaps the pentest retest
// demonstrated concretely:
//   H7  — 3,000 GET requests against a direct /images/<file> URL all
//         returned 200, because that path never touched PHP and so could
//         never be rate-limited.
//   H11 — an image removed from the library for having expired remained
//         fully downloadable at its old URL, because expiration was only
//         ever checked by the *listing* code, never by whatever served the
//         file itself.
// Every request here re-checks both, right before the bytes go out, so
// there's no window between "checked" and "served" (TOCTOU).

startSecureSession();

function imageError(int $code, string $error): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode(['success' => false, 'error' => $error]);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'HEAD') {
    imageError(405, 'method_not_allowed');
}

// H7: dedicated rate limit — this endpoint's ONLY limit, since it's exempted
// from config.php's blanket guard (see SKIP_GLOBAL_RATE_LIMIT above). Identity
// prefers the logged-in user (so one account's own gallery browsing is
// tracked together regardless of IP/device); anonymous viewers of a shared
// link fall back to IP, same as every other unauthenticated limiter bucket in
// this app — with the caveat that many real recipients of a mass-distributed
// link can share one IP via an email provider's image proxy (see config.php).
if (RATE_LIMIT_ENABLED) {
    $identity = isLoggedIn() ? ('u_' . $_SESSION['user']) : ('ip_' . getClientIp());
    $limiter  = new \App\RateLimiter(RATE_LIMIT_STORAGE_FILE);
    $result   = $limiter->check('img_' . $identity, RATE_LIMIT_IMAGE_ATTEMPTS, RATE_LIMIT_IMAGE_WINDOW);

    if (!$result['allowed']) {
        http_response_code(429);
        header('Retry-After: ' . $result['retryAfter']);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode([
            'success'     => false,
            'error'       => 'rate_limit_exceeded',
            'message'     => 'Demasiadas solicitudes. Inténtalo de nuevo más tarde.',
            'retry_after' => $result['retryAfter'],
        ]);
        exit;
    }
}

// The filename itself is the sharing token (H11.5): a 128-bit random hex
// name, never sequential/predictable, generated server-side at upload time
// (see ImageUploader::save()). Strict whitelist — same pattern delete.php
// already uses — rejects anything else before it ever reaches the filesystem.
$filename = $_GET['f'] ?? '';
if (!is_string($filename) || !preg_match('/^[a-f0-9]{32}\.(jpg|jpeg|png)$/i', $filename)) {
    imageError(404, 'not_found');
}

// H11: authoritative existence + expiration check, from the metadata store,
// immediately before serving.
$metadata = ImageMetadata::get($filename);
if ($metadata === null) {
    imageError(404, 'not_found');
}

if (!empty($metadata['expires_at']) && $metadata['expires_at'] <= time()) {
    logSecurityEvent('image_expired_access_attempt', ['file' => $filename]);
    imageError(410, 'expired');
}

$path = IMAGES_DIR . $filename;
if (!is_file($path)) {
    // Metadata says it should exist but the file is gone (e.g. cleanup.php
    // already reaped it in the gap between the check above and here) —
    // same response as "never existed", no internal detail leaked.
    imageError(404, 'not_found');
}

$ext  = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
$mime = ($ext === 'png') ? 'image/png' : 'image/jpeg';

// H11.7: short-lived, private caching only. Long enough that a page with
// several references to the same image doesn't refetch it, short enough
// that a browser/shared cache can't keep serving an image past the moment
// it expires. Clamped to whatever time is actually left before expiry.
$maxAge = 60;
if (!empty($metadata['expires_at'])) {
    $maxAge = max(0, min($maxAge, $metadata['expires_at'] - time()));
}

header('Content-Type: ' . $mime);
header('Content-Length: ' . (string) filesize($path));
header('Cache-Control: private, max-age=' . $maxAge);
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex, nofollow');

if ($method === 'GET') {
    // Streamed straight from disk (readfile), never buffered into a PHP
    // string — matters for large files and for keeping memory flat under
    // concurrent requests.
    readfile($path);
}
exit;
