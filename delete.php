<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/Autoloader.php';

use App\ImageMetadata;

startSecureSession();
header('Content-Type: application/json; charset=utf-8');

function jsonError(int $code, string $msg): never
{
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

// B8 remediation: authenticate before consuming a rate-limit bucket, so
// unauthenticated callers can no longer share (and exhaust) the same bucket
// used by real users.
if (!isLoggedIn())                         jsonError(401, 'Unauthorized');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonError(405, 'Method not allowed');

$body = (string) file_get_contents('php://input');
$data = json_decode($body, true);

$csrf     = $data['csrf_token'] ?? '';
$filename = $data['filename']   ?? '';

if (!verifyCsrf($csrf))                    jsonError(403, 'Invalid CSRF token');

// --- H7: Rate Limiting on API actions ---
if (RATE_LIMIT_ENABLED) {
    $limiter = new \App\RateLimiter(RATE_LIMIT_STORAGE_FILE);
    $userKey = 'api_' . $_SESSION['user'];
    $result = $limiter->check($userKey, RATE_LIMIT_API_ATTEMPTS, RATE_LIMIT_API_WINDOW);

    if (!$result['allowed']) {
        http_response_code(429);
        header('Retry-After: ' . $result['retryAfter']);
        jsonError(429, 'Demasiadas solicitudes. Inténtalo de nuevo más tarde.');
    }
}

// Strict filename whitelist — only hex-named files we created
if (!preg_match('/^[a-f0-9]{32}\.(jpg|jpeg|png)$/i', $filename)) {
    jsonError(400, 'Nombre de archivo inválido');
}

// --- IDOR check: Verify image ownership or admin role ---
$metadata = ImageMetadata::get($filename);
if (!$metadata) {
    // If file exists on disk but not in metadata, it's an orphaned file.
    // Treat as not found from a user perspective to prevent information leakage.
    jsonError(404, 'Archivo no encontrado.');
}

if (($metadata['owner'] ?? null) !== $_SESSION['user'] && !isAdmin()) {
    jsonError(403, 'No tienes permiso para eliminar esta imagen.');
}

$path = IMAGES_DIR . $filename;

if (!file_exists($path)) jsonError(404, 'Archivo no encontrado');

// Temporarily make the file writable so unlink() can work on read-only files.
// The @ suppresses warnings if the file is already writable, which is fine.
if (!@chmod($path, 0644)) {
    error_log("Delete failed: Could not set permissions on {$path}");
    jsonError(500, 'No se pudo eliminar el archivo debido a un problema de permisos.');
}

if (!unlink($path)) {
    // If unlink fails, try to restore read-only permissions as a safety measure.
    @chmod($path, 0444);
    jsonError(500, 'No se pudo eliminar el archivo');
}

// --- H11: Remove image from metadata ---
ImageMetadata::remove($filename);

logSecurityEvent('image_deleted', [
    'user'  => $_SESSION['user'],
    'owner' => $metadata['owner'] ?? null,
    'file'  => $filename,
]);

echo json_encode(['success' => true, 'filename' => $filename]);
