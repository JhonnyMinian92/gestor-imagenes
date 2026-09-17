<?php
define('APP_NAME', 'Security Image');
define('APP_VERSION', '1.0.0');

define('APP_ENV', getenv('APP_ENV') ?: 'development'); // 'development' or 'production'

// --- H1: HTTPS and HSTS Enforcement ---
// Tied to APP_ENV so a production deploy (APP_ENV=production, see .env.example)
// enforces HTTPS automatically, while local dev (APP_ENV unset/'development')
// keeps working without a cert. Override explicitly via APP_FORCE_HTTPS if a
// given deployment needs to diverge from that default (e.g. production behind
// a TLS-terminating proxy that isn't yet in TRUSTED_PROXY_IPS).
define('FORCE_HTTPS', getenv('APP_FORCE_HTTPS') !== false
    ? filter_var(getenv('APP_FORCE_HTTPS'), FILTER_VALIDATE_BOOLEAN)
    : (APP_ENV === 'production'));
define('HSTS_ENABLED', true); // Only enable if FORCE_HTTPS is true and you have a valid cert
define('HSTS_MAX_AGE', 31536000); // 1 year
define('HSTS_INCLUDE_SUBDOMAINS', true); // Confirmed: all subdomains also serve HTTPS
define('HSTS_PRELOAD', false); // Set to true only if you intend to submit to the preload list

// --- H10: Content Security Policy ---
define('CSP_ENABLED', true);
// Use CSP_REPORT_ONLY to test policies without enforcing them.
define('CSP_REPORT_ONLY', false);

// --- Trusted reverse proxies (M1/M3 remediation) ---
// Only requests whose REMOTE_ADDR is in this list may influence protocol/IP
// detection via X-Forwarded-* headers. Comma-separated list via env var.
// Leave empty (default) if the app is directly exposed to the Internet.
define('TRUSTED_PROXY_IPS', array_filter(array_map('trim', explode(',', getenv('APP_TRUSTED_PROXIES') ?: ''))));

// Entries may be a single IP ("172.20.0.5") or a CIDR range ("172.16.0.0/12").
// CIDR support matters for containerized deployments: a reverse proxy's own
// container IP isn't guaranteed to stay fixed across recreations, but the
// Docker network's subnet is stable and trivial to read off `docker network
// inspect`. Works for both IPv4 and IPv6 via inet_pton's binary form.
function ipMatchesTrustedEntry(string $ip, string $entry): bool
{
    if (strpos($entry, '/') === false) {
        return hash_equals($entry, $ip);
    }

    [$subnet, $prefixLen] = explode('/', $entry, 2);
    $ipBin = @inet_pton($ip);
    $subnetBin = @inet_pton($subnet);
    if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
        return false;
    }

    $prefixLen = (int) $prefixLen;
    $fullBytes = intdiv($prefixLen, 8);
    $remainderBits = $prefixLen % 8;

    if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
        return false;
    }
    if ($remainderBits === 0) {
        return true;
    }

    $mask = chr((0xFF << (8 - $remainderBits)) & 0xFF);
    return (substr($ipBin, $fullBytes, 1) & $mask) === (substr($subnetBin, $fullBytes, 1) & $mask);
}

function isTrustedProxyRequest(): bool
{
    if (empty(TRUSTED_PROXY_IPS)) return false;
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
    if ($remoteAddr === '') return false;
    foreach (TRUSTED_PROXY_IPS as $entry) {
        if (ipMatchesTrustedEntry($remoteAddr, $entry)) return true;
    }
    return false;
}

function isSecureConnection(): bool
{
    if (isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] === 'on' || $_SERVER['HTTPS'] == 1)) return true;
    // Only honor X-Forwarded-Proto if the request actually came from a configured trusted proxy;
    // otherwise a direct client could forge this header and bypass HTTPS enforcement.
    if (isTrustedProxyRequest() && isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') return true;
    return false;
}

// --- M3/B8 remediation: real client IP resolution, spoof-resistant by default ---
function getClientIp(): string
{
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? 'unknown_ip';
    if (!isTrustedProxyRequest() || empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $remoteAddr;
    }
    // Leftmost entry is the original client when the immediate hop is a trusted proxy.
    $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $candidate = trim($parts[0]);
    return $candidate !== '' ? $candidate : $remoteAddr;
}

if (FORCE_HTTPS && !isSecureConnection() && php_sapi_name() !== 'cli') {
    $redirectUrl = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header('HTTP/1.1 301 Moved Permanently');
    header('Location: ' . $redirectUrl);
    exit;
}

// --- End H1 Remediation ---

define('ROOT_DIR',    __DIR__);

// --- G3 remediation: sensitive data lives OUTSIDE the web document root by default. ---
// Override with APP_DATA_DIR if you need a specific location; whatever path is used,
// it must not be reachable over HTTP (do not point it inside this project's folder
// unless that folder itself is not the vhost document root).
$defaultDataDir = dirname(ROOT_DIR) . DIRECTORY_SEPARATOR . 'security-image-data';
define('DATA_DIR', rtrim(getenv('APP_DATA_DIR') ?: $defaultDataDir, '\\/') . DIRECTORY_SEPARATOR);
define('USERS_FILE',  DATA_DIR . 'users.json');

function ensureDataDir(): void
{
    if (!is_dir(DATA_DIR)) {
        mkdir(DATA_DIR, 0750, true);
        file_put_contents(DATA_DIR . '.htaccess', "Require all denied\n");
    }
}
ensureDataDir();

// Configurar sesiones en directorio protegido, fuera del webroot
define('SESSIONS_DIR', DATA_DIR . 'sessions' . DIRECTORY_SEPARATOR);
if (!is_dir(SESSIONS_DIR)) {
    mkdir(SESSIONS_DIR, 0750, true);
}
ini_set('session.save_path', SESSIONS_DIR);

// --- Session Cookie Security ---
// Belt-and-suspenders alongside auth.php's session_set_cookie_params() (which
// is what actually takes effect, since it's called right before session_start()):
// these ini_set() calls make the secure defaults apply even to any code path
// that might call session_start() directly without going through
// startSecureSession(). 'secure' tracks isSecureConnection() rather than a
// hardcoded '1' so it still works if a request ever reaches PHP over plain
// HTTP (e.g. a misconfigured proxy) instead of silently dropping the cookie.
ini_set('session.cookie_secure', isSecureConnection() ? '1' : '0');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1'); // Reject uninitialized session IDs (mitigates session fixation)
ini_set('session.use_only_cookies', '1'); // Never accept session IDs via URL/query string

// --- H7/H11 remediation: uploaded images live OUTSIDE the web document root,
// same as every other piece of sensitive state (see G3 above). Previously
// this pointed at ROOT_DIR/images, a folder Apache served directly — which
// meant a request for /images/<file> never touched PHP at all, so it could
// never be rate-limited and never re-checked for expiration once issued.
// Moving storage here means the ONLY way to reach a file is image.php,
// which enforces both on every request (see image.php).
define('IMAGES_DIR', DATA_DIR . 'images' . DIRECTORY_SEPARATOR);

function ensureImagesDir(): void
{
    if (!is_dir(IMAGES_DIR)) {
        mkdir(IMAGES_DIR, 0750, true);
    }
    $htaccess = IMAGES_DIR . '.htaccess';
    if (!is_file($htaccess)) {
        file_put_contents($htaccess, "Require all denied\n");
    }
}
ensureImagesDir();

define('MAX_FILE_SIZE',     10 * 1024 * 1024);
define('ALLOWED_MIME_TYPES', ['image/jpeg', 'image/png']);
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png']);
define('IMAGES_PER_PAGE', 24);

// --- H11: Image Expiration ---
define('IMAGE_METADATA_FILE', DATA_DIR . 'images.json');
define('DEFAULT_IMAGE_EXPIRATION_SECONDS', 7 * 86400); // 7 days. Set to null to disable expiration.

// H11 remediation: let the uploader pick from a fixed set of expirations
// (never "no expiration" — that stays an operator-only decision via
// DEFAULT_IMAGE_EXPIRATION_SECONDS). Whitelist validated server-side in
// ImageUploader; the client only ever sees these exact options.
define('ALLOWED_LINK_EXPIRATIONS', array_filter(array_map(
    'intval',
    explode(',', getenv('APP_ALLOWED_LINK_EXPIRATIONS') ?: (string) (3600 . ',' . 86400 . ',' . (7 * 86400) . ',' . (30 * 86400) . ',' . (365 * 86400)))
)));

// --- H3: User Storage Quotas ---
define('QUOTAS_ENABLED', true);
define('MAX_FILES_PER_USER', 100);
define('MAX_STORAGE_BYTES_PER_USER', 5 * 1024 * 1024 * 1024); // 5 GB

// --- H12: Image Dimension Limits ---
define('MAX_IMAGE_WIDTH', 4096); // Max width in pixels
define('MAX_IMAGE_HEIGHT', 4096); // Max height in pixels
define('MAX_IMAGE_PIXELS', 16777216); // Max total pixels (e.g., 4096 * 4096)

// --- H5: Session Security Settings ---
define('SESSION_LIFETIME',           7200); // Inactivity timeout in seconds (2 hours)
define('SESSION_ABSOLUTE_TIMEOUT',   86400); // Absolute session lifetime (24 hours)

// --- G2 remediation: no hardcoded fallback secret. ---
// The secret is read from APP_SESSION_SECRET if set; otherwise a random one is
// generated on first run and persisted (root-only-readable) under DATA_DIR,
// which already lives outside the web document root (see G3).
function getOrCreateSessionSecret(): string
{
    $envSecret = getenv('APP_SESSION_SECRET');
    if ($envSecret !== false && $envSecret !== '') {
        return $envSecret;
    }

    $secretFile = DATA_DIR . '.session_secret';
    if (is_file($secretFile)) {
        $existing = trim((string) file_get_contents($secretFile));
        if ($existing !== '') return $existing;
    }

    ensureDataDir();
    $generated = bin2hex(random_bytes(32));
    file_put_contents($secretFile, $generated, LOCK_EX);
    @chmod($secretFile, 0600);
    return $generated;
}
define('SESSION_FINGERPRINT_SECRET', getOrCreateSessionSecret());

define('LOGIN_MAX_ATTEMPTS',   5);
define('LOGIN_LOCKOUT_SECONDS', 900);

// --- Password Complexity (M5/B4 remediation: max length + special character) ---
define('PASSWORD_COMPLEXITY_REGEX', '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9\s]).{8,}$/');
define('PASSWORD_COMPLEXITY_MSG', 'La contraseña debe tener al menos 8 caracteres, e incluir una mayúscula, una minúscula, un número y un carácter especial.');
define('MAX_PASSWORD_LENGTH', 128);

// --- H9: CAPTCHA Settings ---
define('CAPTCHA_ENABLED', true);
define('CAPTCHA_AFTER_FAILED_ATTEMPTS', 3);

// --- H7: Rate Limiting Settings ---
define('RATE_LIMIT_ENABLED', true);
define('RATE_LIMIT_STORAGE_FILE', DATA_DIR . 'ratelimit.json');
define('RATE_LIMIT_LOGIN_ATTEMPTS', 20);
define('RATE_LIMIT_LOGIN_WINDOW', 300); // 5 minutes
define('RATE_LIMIT_UPLOAD_ATTEMPTS', 30);
define('RATE_LIMIT_UPLOAD_WINDOW', 600); // 10 minutes
define('RATE_LIMIT_API_ATTEMPTS', 100);
define('RATE_LIMIT_API_WINDOW', 300); // 5 minutes

// H7/H11 remediation: dedicated limiter for image.php (the only path that can
// now serve a stored image — see IMAGES_DIR above).
//
// UPLOADING is rare (roughly once every few hours) — that stays covered by
// the tight RATE_LIMIT_UPLOAD_* limit above, unaffected by anything below.
//
// VIEWING is a different traffic shape entirely: the resulting URL is meant
// to be embedded in mass email campaigns and advertising, so a single image
// can legitimately receive a very large number of views in a short window —
// and worse, many of those legitimate views can appear to come from a
// *handful* of source IPs, because major email providers (Gmail, Outlook)
// proxy-fetch embedded images server-side on the recipient's behalf, so
// hundreds of real recipients opening the same campaign can collapse onto
// just a few email-provider proxy IPs. A tight per-IP limit here would throttle
// exactly the traffic this feature exists to serve.
// So this is deliberately generous — sized to absorb that kind of legitimate
// concentrated burst — while still bounding a single identity's total pull on
// bandwidth/CPU per window. It will not perfectly distinguish "500 real
// recipients behind one mail-provider proxy" from "a script hitting the same
// URL 500 times"; no counter keyed only on source IP can. What it does do is
// cap the blast radius: the pentest's 3,000-in-seconds flood against one file
// still gets cut off partway through, and any single source is capped rather
// than unbounded. If real campaigns need more headroom, raise via env.
define('RATE_LIMIT_IMAGE_ATTEMPTS', (int) (getenv('RATE_LIMIT_IMAGE_MAX') ?: 1000));
define('RATE_LIMIT_IMAGE_WINDOW', (int) (getenv('RATE_LIMIT_IMAGE_WINDOW_SECONDS') ?: 300));

// H7 remediation: coarse, global-per-IP cap applied to every OTHER PHP
// endpoint (see enforcement below) — login, uploads, admin actions, page
// navigation — on top of the stricter per-feature limits above. Generous by
// design — it exists to blunt broad floods, not to throttle normal
// single-user browsing.
//
// image.php is deliberately EXEMPTED from this bucket (see SKIP_GLOBAL_RATE_LIMIT
// below): it already has its own, much larger, purpose-built limit above, and
// mixing the two would mean a legitimate traffic spike on a shared image link
// could burn through the budget meant to protect login/admin actions for
// anyone behind the same IP — or, if this limit were raised to accommodate
// image traffic instead, it would weaken the protection this bucket is
// actually meant to provide for those sensitive, low-volume-by-nature actions.
define('RATE_LIMIT_GLOBAL_ATTEMPTS', (int) (getenv('RATE_LIMIT_GLOBAL_MAX') ?: 300));
define('RATE_LIMIT_GLOBAL_WINDOW', (int) (getenv('RATE_LIMIT_WINDOW_SECONDS') ?: 300)); // 5 minutes

// --- H7 remediation: enforce the global limit for every request here, once,
// so no PHP entry point can be reached without passing through it — except
// image.php, which sets SKIP_GLOBAL_RATE_LIMIT before requiring this file
// because it enforces its own dedicated limit instead (see above). ---
if (RATE_LIMIT_ENABLED && php_sapi_name() !== 'cli' && !defined('SKIP_GLOBAL_RATE_LIMIT')) {
    require_once __DIR__ . '/Autoloader.php';
    $__globalLimiter = new \App\RateLimiter(RATE_LIMIT_STORAGE_FILE);
    $__globalCheck = $__globalLimiter->check('global_' . getClientIp(), RATE_LIMIT_GLOBAL_ATTEMPTS, RATE_LIMIT_GLOBAL_WINDOW);
    if (!$__globalCheck['allowed']) {
        http_response_code(429);
        header('Retry-After: ' . $__globalCheck['retryAfter']);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Demasiadas solicitudes. Inténtalo de nuevo más tarde.']);
        exit;
    }
    unset($__globalLimiter, $__globalCheck);
}

function getBaseUrl(): string
{
    $protocol = isSecureConnection() ? 'https' : 'http';
    $host     = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $script   = str_replace('\\', '/', $_SERVER['SCRIPT_NAME'] ?? '/index.php');
    // dirname() on Windows returns '\' (not '/') for a root-level path; normalize
    // again so getBaseUrl()/getImagesBaseUrl() build a clean URL on any OS.
    $dir      = rtrim(str_replace('\\', '/', dirname($script)), '/');
    return $protocol . '://' . $host . $dir;
}

// H7/H11 remediation: images are served by image.php (rate-limited,
// expiration-checked on every request), never by a direct path into
// IMAGES_DIR — see IMAGES_DIR above for why.
function getImagesBaseUrl(): string
{
    return getBaseUrl() . '/image.php?f=';
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// --- Next-level: TOTP two-factor authentication (opt-in per account) ---
define('TOTP_ISSUER', 'Security Image');
define('TOTP_ENABLED', true); // Master switch. Per-account enrollment stays opt-in either way.

// --- Next-level: append-only security event log ---
define('SECURITY_LOG_FILE', DATA_DIR . 'security.log');
define('SECURITY_LOG_MAX_LINES', 5000); // Soft cap; trimmed opportunistically, see logSecurityEvent().

// Best-effort structured logging of security-relevant events (auth outcomes,
// admin actions, 2FA changes). Deliberately never throws: a logging failure
// (e.g. disk full) must not be able to break the feature it's observing.
function logSecurityEvent(string $event, array $context = []): void
{
    try {
        $entry = ['ts' => date('c'), 'event' => $event, 'ip' => getClientIp()] + $context;
        $line = json_encode($entry, JSON_UNESCAPED_UNICODE) . "\n";

        $dir = dirname(SECURITY_LOG_FILE);
        if (!is_dir($dir)) mkdir($dir, 0750, true);

        $fh = @fopen(SECURITY_LOG_FILE, 'a+');
        if ($fh === false) return;
        if (flock($fh, LOCK_EX)) {
            fwrite($fh, $line);

            // Opportunistic trim so the log can't grow unbounded without a cron.
            // Cheap check first (avoids reading the whole file on every write).
            if (random_int(1, 200) === 1) {
                rewind($fh);
                $lines = [];
                while (($l = fgets($fh)) !== false) $lines[] = $l;
                if (count($lines) > SECURITY_LOG_MAX_LINES) {
                    $lines = array_slice($lines, -SECURITY_LOG_MAX_LINES);
                    rewind($fh);
                    ftruncate($fh, 0);
                    fwrite($fh, implode('', $lines));
                }
            }
            flock($fh, LOCK_UN);
        }
        fclose($fh);
    } catch (\Throwable $e) {
        // Swallow — logging must never be able to break the caller.
    }
}

// H11 remediation: human-readable label for an ALLOWED_LINK_EXPIRATIONS value.
function formatDurationLabel(int $seconds): string
{
    if ($seconds <= 0) return 'Sin expiración';
    // Checked largest-unit-first: 30/365 days are also exact multiples of a day,
    // so days must be checked after months/years or they'd never be reached.
    if ($seconds % (365 * 86400) === 0) {
        $years = intdiv($seconds, 365 * 86400);
        return $years . ($years === 1 ? ' año' : ' años');
    }
    if ($seconds % (30 * 86400) === 0) {
        $months = intdiv($seconds, 30 * 86400);
        return $months . ($months === 1 ? ' mes' : ' meses');
    }
    if ($seconds % 86400 === 0) {
        $days = intdiv($seconds, 86400);
        return $days . ($days === 1 ? ' día' : ' días');
    }
    if ($seconds % 3600 === 0) {
        $hours = intdiv($seconds, 3600);
        return $hours . ($hours === 1 ? ' hora' : ' horas');
    }
    return $seconds . ' s';
}

// --- Shared helper: atomic read-modify-write for the small JSON "databases" ---
// used across the app (users.json, images.json, ratelimit.json, attempts.json).
// Prevents lost updates when two requests write concurrently (M4/M9 remediation).
//
// $mutator receives the currently-decoded array and must return a 2-tuple
// [$newData, $result]. If $newData is null, the file is left untouched
// (useful for read-only lookups or aborted writes) and $result is returned as-is.
function withJsonFileLock(string $path, callable $mutator)
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0750, true);
    }

    $fh = fopen($path, 'c+');
    if ($fh === false) {
        throw new \RuntimeException("No se pudo abrir el archivo: {$path}");
    }

    try {
        if (!flock($fh, LOCK_EX)) {
            throw new \RuntimeException("No se pudo bloquear el archivo: {$path}");
        }

        $raw = stream_get_contents($fh);
        $data = ($raw !== false && $raw !== '') ? (json_decode($raw, true) ?? []) : [];

        [$newData, $result] = $mutator($data);

        if ($newData !== null) {
            rewind($fh);
            ftruncate($fh, 0);
            fwrite($fh, json_encode($newData, JSON_PRETTY_PRINT));
            fflush($fh);
        }

        return $result;
    } finally {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}

// --- H1 & H2 Remediation ---

// Send HSTS header if enabled and on a secure connection
if (FORCE_HTTPS && HSTS_ENABLED && isSecureConnection() && php_sapi_name() !== 'cli') {
    $hstsHeader = 'max-age=' . HSTS_MAX_AGE;
    if (HSTS_INCLUDE_SUBDOMAINS) $hstsHeader .= '; includeSubDomains';
    if (HSTS_PRELOAD) $hstsHeader .= '; preload';
    header('Strict-Transport-Security: ' . $hstsHeader);
}

// Disable caching for all dynamic PHP pages to protect sensitive data (H1)
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// --- M6 remediation: additional hardening headers ---
if (php_sapi_name() !== 'cli') {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY'); // Legacy fallback for browsers without CSP frame-ancestors support
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    // Cross-origin isolation baseline. Deliberately NOT setting
    // Cross-Origin-Embedder-Policy: this app's CSP allows third-party fonts
    // (fonts.googleapis.com/fonts.gstatic.com) that don't guarantee a CORP
    // header of their own — COEP:require-corp would silently block them.
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
}

// --- H10: Content Security Policy Header ---
if (CSP_ENABLED && php_sapi_name() !== 'cli') {
    $csp = [
        "default-src 'self'",
        // No inline scripts remain anywhere in the app; everything ships as external files.
        "script-src 'self'",
        // Allow styles from self, inline attributes, and Google Fonts.
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com",
        // Allow images from self, data URIs, and likely external domains from the template.
        "img-src 'self' data: *.securitydata.net.ec",
        // Allow fonts from self and Google Fonts.
        "font-src 'self' fonts.gstatic.com",
        "connect-src 'self'", // For fetch/XHR to own backend
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'", // Prevents clickjacking
        "form-action 'self'",
    ];
    $headerName = CSP_REPORT_ONLY ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
    header($headerName . ': ' . implode('; ', $csp));
}
