<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/Autoloader.php';

requireLogin();

$user = $_SESSION['user'];

// --- H7-style: rate limit before anything else runs, but only after auth ---
// (same B8 lesson as upload.php/delete.php: never share a bucket with anonymous
// callers, and never rate-limit before knowing who's asking).
if (RATE_LIMIT_ENABLED) {
    $limiter = new \App\RateLimiter(RATE_LIMIT_STORAGE_FILE);
    $result = $limiter->check('api_' . $user, RATE_LIMIT_API_ATTEMPTS, RATE_LIMIT_API_WINDOW);
    if (!$result['allowed']) {
        http_response_code(429);
        header('Retry-After: ' . $result['retryAfter']);
        header('Location: account.php?status=error&msg=' . rawurlencode('Demasiadas solicitudes. Inténtalo de nuevo más tarde.'));
        exit;
    }
}

$action = $_POST['action'] ?? '';

if (empty($action) || !isset($_POST['csrf']) || !verifyCsrf($_POST['csrf'])) {
    header('Location: account.php?status=error&msg=' . rawurlencode('Solicitud inválida.'));
    exit;
}

function redirectWith(string $status, string $msg): never
{
    header('Location: account.php?status=' . rawurlencode($status) . '&msg=' . rawurlencode($msg));
    exit;
}

switch ($action) {
    case 'change-password':
        $current   = $_POST['current_password'] ?? '';
        $password  = $_POST['password']  ?? '';
        $password2 = $_POST['password2'] ?? '';

        if (strlen($password) > MAX_PASSWORD_LENGTH) {
            redirectWith('error', 'La contraseña es demasiado larga (máx. ' . MAX_PASSWORD_LENGTH . ' caracteres).');
        }
        if (!preg_match(PASSWORD_COMPLEXITY_REGEX, $password)) {
            redirectWith('error', PASSWORD_COMPLEXITY_MSG);
        }
        if ($password !== $password2) {
            redirectWith('error', 'Las contraseñas no coinciden.');
        }

        $result = changeOwnPassword($user, $current, $password);
        if ($result['ok']) {
            logSecurityEvent('password_changed_self', ['user' => $user]);
        }
        redirectWith($result['ok'] ? 'ok' : 'error', $result['msg']);

    case 'totp-start':
        if (!TOTP_ENABLED) {
            redirectWith('error', 'La verificación en dos pasos no está habilitada en este servidor.');
        }
        $secret = startTotpEnrollment($user);
        if ($secret === null) {
            redirectWith('error', 'No se pudo iniciar la activación de 2FA.');
        }
        redirectWith('ok', 'Escanea o ingresa la clave en tu app de autenticación y confirma con un código.');

    case 'totp-confirm':
        $code = $_POST['totp_code'] ?? '';
        if (confirmTotpEnrollment($user, $code)) {
            logSecurityEvent('totp_enabled', ['user' => $user]);
            redirectWith('ok', 'Verificación en dos pasos activada correctamente.');
        }
        redirectWith('error', 'Código incorrecto. Vuelve a intentarlo.');

    case 'totp-cancel':
        // Discard a pending (never confirmed) enrollment.
        withJsonFileLock(USERS_FILE, function (array $users) use ($user) {
            if (!isset($users[$user])) return [null, null];
            unset($users[$user]['totp_pending_secret']);
            return [$users, null];
        });
        redirectWith('ok', 'Activación de 2FA cancelada.');

    case 'totp-disable':
        $current = $_POST['current_password'] ?? '';
        $result = disableTotpForUser($user, $current);
        if ($result['ok']) {
            logSecurityEvent('totp_disabled', ['user' => $user]);
        }
        redirectWith($result['ok'] ? 'ok' : 'error', $result['msg']);

    default:
        redirectWith('error', 'Acción no reconocida.');
}
