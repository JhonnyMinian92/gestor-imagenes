<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/Autoloader.php';

use App\ImageUploader;
use App\ImageMetadata;
use App\UploadException;

startSecureSession();
header('Content-Type: application/json; charset=utf-8');

function jsonError(int $code, string $msg): never
{
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

try {
    // B8 remediation: reject unauthenticated/invalid requests before touching the
    // rate limiter, so anonymous callers can no longer share (and exhaust) the
    // same limiter bucket used by real users.
    if (!isLoggedIn())                          jsonError(401, 'Unauthorized');
    if ($_SERVER['REQUEST_METHOD'] !== 'POST')  jsonError(405, 'Method not allowed');
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) jsonError(403, 'Invalid CSRF token');

    // --- H7: Rate Limiting on Upload ---
    if (RATE_LIMIT_ENABLED) {
        $limiter = new \App\RateLimiter(RATE_LIMIT_STORAGE_FILE);
        $userKey = 'upload_' . $_SESSION['user'];
        $result = $limiter->check($userKey, RATE_LIMIT_UPLOAD_ATTEMPTS, RATE_LIMIT_UPLOAD_WINDOW);

        if (!$result['allowed']) {
            http_response_code(429);
            header('Retry-After: ' . $result['retryAfter']);
            jsonError(429, 'Has subido demasiadas imágenes. Inténtalo de nuevo más tarde.');
        }
    }

    $uploader = new ImageUploader($_FILES['image'] ?? []);

    // --- H3: Fast-path quota pre-check to avoid wasting work on obviously-over-quota
    // uploads. The authoritative, race-free check happens atomically inside
    // ImageUploader::processUpload() -> ImageMetadata::tryAdd() (M9 remediation).
    if (QUOTAS_ENABLED) {
        $user = $_SESSION['user'];
        $usage = ImageMetadata::getUserUsage($user);
        $newFileSize = $_FILES['image']['size'] ?? 0;

        if ($usage['count'] >= MAX_FILES_PER_USER) {
            jsonError(507, 'Has alcanzado el límite de archivos. Elimina imágenes para liberar espacio.');
        }

        if (($usage['size'] + $newFileSize) > MAX_STORAGE_BYTES_PER_USER) {
            jsonError(507, 'No tienes suficiente espacio de almacenamiento para esta imagen.');
        }
    }

    // H11 remediation: optional expiration choice from the upload form,
    // restricted to the configured whitelist (never trusted blindly — see
    // ImageUploader::processUpload(), which re-validates it independently).
    $requestedExpiration = null;
    if (isset($_POST['expires_in']) && ctype_digit((string) $_POST['expires_in'])) {
        $requestedExpiration = (int) $_POST['expires_in'];
    }

    $result = $uploader->processUpload($_SESSION['user'], $requestedExpiration);
    echo json_encode($result);
} catch (UploadException $e) {
    jsonError($e->getCode(), $e->getMessage());
} catch (\Exception $e) {
    error_log('Upload failed: ' . $e->getMessage());
    jsonError(500, 'Ocurrió un error inesperado en el servidor.');
}
