<?php
require_once __DIR__ . '/config.php';

function startSecureSession(): void
{
    if (session_status() !== PHP_SESSION_NONE) return;
    session_set_cookie_params([
        'lifetime' => 0, // Until browser is closed
        'path'     => '/', // Available on the whole domain
        'secure'   => isSecureConnection(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_name('IMGVAULT');
    session_start();

    // --- H5: Session Fingerprinting ---
    // On every request, verify the fingerprint to mitigate session hijacking.
    if (isset($_SESSION['fingerprint'])) {
        $currentUserAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $currentFingerprint = hash_hmac('sha256', $currentUserAgent, SESSION_FINGERPRINT_SECRET);

        if (!hash_equals($_SESSION['fingerprint'], $currentFingerprint)) {
            // Fingerprint mismatch. Potential hijacking. Invalidate session immediately.
            logSecurityEvent('session_hijack_suspected', ['user' => $_SESSION['user'] ?? null]);
            doLogout();
            header('Location: login.php?err=session_compromised');
            exit;
        }
    }
}

function isLoggedIn(): bool
{
    // --- H5: Add absolute timeout check ---
    $sessionValid = isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['last_activity'], $_SESSION['created_at'])
        && $_SESSION['auth'] === true
        && (time() - $_SESSION['last_activity']) < SESSION_LIFETIME // Inactivity timeout
        && (time() - $_SESSION['created_at']) < SESSION_ABSOLUTE_TIMEOUT; // Absolute timeout

    if (!$sessionValid) return false;

    // Re-validate against the current user list on every check: otherwise a
    // deleted account (or one demoted from admin) keeps a fully working,
    // stale-privileged session until it naturally times out.
    $users = loadUsers();
    if (!isset($users[$_SESSION['user']])) {
        return false;
    }
    $_SESSION['role'] = resolveUserRole($users, $_SESSION['user']);

    return true;
}

function requireLogin(): void
{
    startSecureSession();
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit;
    }

    // --- H5: Periodic Session ID Regeneration ---
    // Regenerate session ID every 15 minutes to make hijacking harder.
    if (time() - ($_SESSION['last_regen'] ?? 0) > 900) { // 900 seconds = 15 minutes
        session_regenerate_id(true);
        $_SESSION['last_regen'] = time();
    }

    $_SESSION['last_activity'] = time();
}

function isAdmin(): bool
{
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function requireAdmin(): void
{
    requireLogin();
    if (!isAdmin()) {
        http_response_code(403);
        die('<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>You don\'t have permission to access this resource.</p></body></html>');
    }
}

function attemptLogin(): array
{
    require_once __DIR__ . '/Autoloader.php';

    // Field-level encryption of the credentials, on top of (not instead of)
    // HTTPS: the login form (see login.php / assets/js/app.js) encrypts
    // username+password in the browser with this server's RSA public key
    // wrapping a one-time AES-256 key (see Crypto.php). Only the RSA private
    // key, which never leaves the server, can recover them — unlike the
    // shared-secret scheme this replaces (formerly flagged as G1: that one
    // sent the server the same key it gave the browser, so it added nothing
    // HTTPS didn't already provide).
    // Falls back to reading POST fields directly when the encrypted fields
    // are absent (JS disabled, or Web Crypto unavailable because the page
    // isn't loaded in a secure context) — HTTPS still protects that path.
    if (isset($_POST['enc_key'], $_POST['enc_iv'], $_POST['enc_data'])) {
        $decrypted = \App\Crypto::decryptLoginPayload($_POST['enc_key'], $_POST['enc_iv'], $_POST['enc_data']) ?? [];
        $username  = trim((string) ($decrypted['username'] ?? ''));
        $password  = (string) ($decrypted['password'] ?? '');
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
    }

    if ($username === '' || $password === '') {
        return ['ok' => false, 'msg' => 'Por favor completa todos los campos.'];
    }

    // M5 remediation: reject absurdly long input before any expensive processing.
    if (strlen($username) > 50 || strlen($password) > MAX_PASSWORD_LENGTH) {
        return ['ok' => false, 'msg' => 'Usuario o contraseña incorrectos.'];
    }

    // --- H1: Defense-in-depth: Refuse login over insecure connection ---
    // Gated on FORCE_HTTPS so the documented "local dev without HTTPS" mode
    // (config.php) actually works end-to-end, instead of still blocking here.
    if (FORCE_HTTPS && !isSecureConnection()) {
        return ['ok' => false, 'msg' => 'El login solo está permitido a través de una conexión segura (HTTPS).'];
    }

    // --- H8: CSRF Token Validation ---
    // This check is performed first to prevent any processing on invalid requests.
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        return ['ok' => false, 'msg' => 'Solicitud inválida. Por favor, recarga la página e inténtalo de nuevo.'];
    }

    // --- H9: CAPTCHA Validation ---
    if (CAPTCHA_ENABLED && ($_SESSION['login_failures'] ?? 0) >= CAPTCHA_AFTER_FAILED_ATTEMPTS) {
        $captchaAnswer = $_POST['captcha'] ?? null;
        $expectedAnswer = $_SESSION['captcha_answer'] ?? null;

        if ($captchaAnswer === null || $expectedAnswer === null || (int)$captchaAnswer !== $expectedAnswer) {
            // Still bump the main attempt counter to contribute to lockout
            bumpAttempt($username);
            return ['ok' => false, 'msg' => 'La respuesta de la suma de verificación es incorrecta.'];
        }
        // Unset CAPTCHA answer after validation (whether correct or incorrect)
        // to prevent replay and ensure a new CAPTCHA is generated for the next attempt.
        unset($_SESSION['captcha_answer']);
    }

    // --- H7: Rate Limiting on Login ---
    if (RATE_LIMIT_ENABLED) {
        require_once __DIR__ . '/Autoloader.php'; // Ensure autoloader is present
        $limiter = new \App\RateLimiter(RATE_LIMIT_STORAGE_FILE);
        $ip = getClientIp(); // M3 remediation: spoof-resistant IP resolution
        $result = $limiter->check('login_' . $ip, RATE_LIMIT_LOGIN_ATTEMPTS, RATE_LIMIT_LOGIN_WINDOW);

        if (!$result['allowed']) {
            http_response_code(429);
            header('Retry-After: ' . $result['retryAfter']);
            return ['ok' => false, 'msg' => 'Demasiadas solicitudes. Por favor, espera un momento.'];
        }
    }

    $attempts = getAttempts($username);
    if ($attempts['count'] >= LOGIN_MAX_ATTEMPTS) {
        $remaining = LOGIN_LOCKOUT_SECONDS - (time() - $attempts['ts']);
        if ($remaining > 0) {
            // To prevent username enumeration, return a generic error message
            // even if the account is locked. The lockout is silent to the attacker.
            logSecurityEvent('login_locked', ['user' => $username]);
            return ['ok' => false, 'msg' => 'Usuario o contraseña incorrectos.'];
        }
        resetAttempts($username);
    }

    $users  = loadUsers();
    $exists = isset($users[$username]);
    // Always run password_verify to prevent timing oracle
    $hash = $exists ? $users[$username]['password'] : '$2y$12$dummyhashpaddingtowaste.time.x';
    $ok   = password_verify($password, $hash) && $exists;

    if (!$ok) {
        $_SESSION['login_failures'] = ($_SESSION['login_failures'] ?? 0) + 1;
        bumpAttempt($username);
        logSecurityEvent('login_failed', ['user' => $username]);
        return ['ok' => false, 'msg' => 'Usuario o contraseña incorrectos.'];
    }

    resetAttempts($username);
    unset($_SESSION['login_failures']);

    // --- Next-level: opt-in TOTP second factor ---
    // Purely additive: accounts that never enrolled (i.e. every account that
    // existed before this feature) have totp_enabled unset/false and complete
    // login exactly as before, with zero behavior change.
    if (TOTP_ENABLED && userTotpEnabled($users[$username])) {
        $_SESSION['pending_2fa_user'] = $username;
        $_SESSION['pending_2fa_time'] = time();
        return ['ok' => false, 'needs_totp' => true];
    }

    completeLogin($username, resolveUserRole($users, $username));
    logSecurityEvent('login_success', ['user' => $username]);
    return ['ok' => true];
}

// Shared by the plain-password path and the TOTP second-factor path so both
// end up in an identical, fully-authenticated session state.
function completeLogin(string $username, string $role): void
{
    // --- H5: Regenerate ID and set session security tokens ---
    session_regenerate_id(true);

    unset($_SESSION['pending_2fa_user'], $_SESSION['pending_2fa_time']);

    $_SESSION['auth']          = true;
    $_SESSION['user']          = $username;
    $_SESSION['role']          = $role;
    $_SESSION['last_activity'] = time();
    $_SESSION['created_at']    = time(); // For absolute timeout
    $_SESSION['last_regen']    = time(); // For periodic regeneration
    $_SESSION['csrf']          = bin2hex(random_bytes(32));

    $currentUserAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $_SESSION['fingerprint']   = hash_hmac('sha256', $currentUserAgent, SESSION_FINGERPRINT_SECRET);
}

const PENDING_2FA_WINDOW_SECONDS = 300; // Must finish the second factor within 5 minutes.

// Second step of login when the account has TOTP enabled. Reuses the same
// per-username lockout counter as password attempts — guessing a 6-digit code
// is a login attempt like any other and should count against the same budget.
function attemptTotpLogin(): array
{
    require_once __DIR__ . '/Autoloader.php';
    $username = $_SESSION['pending_2fa_user'] ?? null;
    $pendingSince = $_SESSION['pending_2fa_time'] ?? 0;

    if ($username === null || (time() - $pendingSince) > PENDING_2FA_WINDOW_SECONDS) {
        unset($_SESSION['pending_2fa_user'], $_SESSION['pending_2fa_time']);
        return ['ok' => false, 'msg' => 'La verificación expiró. Inicia sesión de nuevo.'];
    }

    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        return ['ok' => false, 'needs_totp' => true, 'msg' => 'Solicitud inválida. Por favor, recarga la página e inténtalo de nuevo.'];
    }

    $attempts = getAttempts($username);
    if ($attempts['count'] >= LOGIN_MAX_ATTEMPTS) {
        $remaining = LOGIN_LOCKOUT_SECONDS - (time() - $attempts['ts']);
        if ($remaining > 0) {
            unset($_SESSION['pending_2fa_user'], $_SESSION['pending_2fa_time']);
            return ['ok' => false, 'msg' => 'Usuario o contraseña incorrectos.'];
        }
        resetAttempts($username);
    }

    $code = trim((string) ($_POST['totp_code'] ?? ''));
    $users = loadUsers();
    $secret = $users[$username]['totp_secret'] ?? null;

    if ($secret === null || !\App\Totp::verify($secret, $code)) {
        bumpAttempt($username);
        logSecurityEvent('totp_login_failed', ['user' => $username]);
        return ['ok' => false, 'needs_totp' => true, 'msg' => 'Código de verificación incorrecto.'];
    }

    resetAttempts($username);
    completeLogin($username, resolveUserRole($users, $username));
    logSecurityEvent('totp_login_success', ['user' => $username]);
    return ['ok' => true];
}

function doLogout(): void
{
    startSecureSession();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 86400,
            $p['path'],
            $p['domain'],
            $p['secure'],
            $p['httponly']
        );
    }
    session_destroy();
}

// ── CAPTCHA (H9) ──────────────────────────────────────────────────────────────

function generateCaptcha(): array
{
    startSecureSession();
    $num1 = rand(1, 10);
    $num2 = rand(1, 9);
    $_SESSION['captcha_answer'] = $num1 + $num2;
    return ['num1' => $num1, 'num2' => $num2];
}


// ── CSRF ──────────────────────────────────────────────────────────────────────

function csrfToken(): string
{
    startSecureSession();
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function verifyCsrf(string $token): bool
{
    return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

// ── User storage ──────────────────────────────────────────────────────────────

function loadUsers(): array
{
    if (!file_exists(USERS_FILE)) return [];
    $raw = file_get_contents(USERS_FILE);
    return $raw !== false ? (json_decode($raw, true) ?? []) : [];
}

// Resolves a user's role, honoring the legacy convention (pre-existing accounts
// created before the 'role' field existed): the first user in the file is admin,
// everyone else is a regular user. Kept as a single source of truth so login and
// user-management logic never disagree about who is an admin.
function resolveUserRole(array $users, string $username): string
{
    $userData = $users[$username] ?? null;
    if ($userData === null) return 'user';

    $role = $userData['role'] ?? null;
    if ($role !== null) return $role;

    $firstUser = array_key_first($users);
    return ($username === $firstUser) ? 'admin' : 'user';
}

// M4 remediation: create-first-admin and duplicate-username checks now happen
// atomically under an exclusive file lock, closing the race where two concurrent
// signups could both see "no users yet" and both become admin, or two requests
// could create the same username at once.
function createUser(string $username, string $password): bool
{
    return withJsonFileLock(USERS_FILE, function (array $users) use ($username, $password) {
        if (isset($users[$username])) {
            return [null, false];
        }
        $role = empty($users) ? 'admin' : 'user'; // First user is always admin
        $users[$username] = [
            'password'   => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
            'created_at' => date('c'),
            'role'       => $role,
        ];
        return [$users, true];
    });
}

// B7 remediation: refuse to delete the last remaining admin account so the
// system can never be left without anyone able to manage users.
function deleteUser(string $username): bool
{
    return withJsonFileLock(USERS_FILE, function (array $users) use ($username) {
        if (!isset($users[$username])) {
            return [null, false];
        }

        if (resolveUserRole($users, $username) === 'admin') {
            $adminCount = 0;
            foreach (array_keys($users) as $u) {
                if (resolveUserRole($users, $u) === 'admin') $adminCount++;
            }
            if ($adminCount <= 1) {
                return [null, false]; // Would remove the last admin — refuse.
            }
        }

        unset($users[$username]);
        return [$users, true];
    });
}

// Promote/demote an existing account. Mirrors the B7 last-admin protection
// used by deleteUser(): refuses to demote the last remaining admin, computed
// atomically under the same lock so a race between two concurrent demotions
// can't leave the system with zero admins.
function setUserRole(string $username, string $role): array
{
    if (!in_array($role, ['admin', 'user'], true)) {
        return ['ok' => false, 'msg' => 'Rol inválido.'];
    }

    return withJsonFileLock(USERS_FILE, function (array $users) use ($username, $role) {
        if (!isset($users[$username])) {
            return [null, ['ok' => false, 'msg' => 'El usuario no existe.']];
        }

        $currentRole = resolveUserRole($users, $username);
        if ($currentRole === $role) {
            return [null, ['ok' => true, 'msg' => 'El usuario ya tenía ese rol.']];
        }

        if ($currentRole === 'admin' && $role === 'user') {
            $adminCount = 0;
            foreach (array_keys($users) as $u) {
                if (resolveUserRole($users, $u) === 'admin') $adminCount++;
            }
            if ($adminCount <= 1) {
                return [null, ['ok' => false, 'msg' => 'No puedes quitarle el rol de administrador al último admin del sistema.']];
            }
        }

        $users[$username]['role'] = $role;
        return [$users, ['ok' => true, 'msg' => 'Rol actualizado correctamente.']];
    });
}

function updateUserPassword(string $username, string $password): bool
{
    return withJsonFileLock(USERS_FILE, function (array $users) use ($username, $password) {
        if (!isset($users[$username])) {
            return [null, false];
        }
        $users[$username]['password'] = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        return [$users, true];
    });
}

// Self-service password change: unlike the admin-triggered reset in
// manage-users-action.php, this requires knowing the CURRENT password —
// an admin can already reset anyone's password without it (they need that
// for account recovery), but a user changing their own password should have
// to prove they still are that user, same as any "change password" flow.
function changeOwnPassword(string $username, string $currentPassword, string $newPassword): array
{
    $users = loadUsers();
    if (!isset($users[$username])) {
        return ['ok' => false, 'msg' => 'Usuario no encontrado.'];
    }
    if (!password_verify($currentPassword, $users[$username]['password'])) {
        return ['ok' => false, 'msg' => 'La contraseña actual no es correcta.'];
    }
    updateUserPassword($username, $newPassword);
    return ['ok' => true, 'msg' => 'Contraseña actualizada correctamente.'];
}

// ── TOTP two-factor authentication (opt-in per account) ───────────────────────

function userTotpEnabled(array $userData): bool
{
    return !empty($userData['totp_enabled']) && !empty($userData['totp_secret']);
}

// Step 1 of enrollment: generate a secret and stash it as "pending" (NOT yet
// active) so a half-finished enrollment can never lock anyone out — the
// account keeps logging in with just a password until confirmTotpEnrollment()
// succeeds.
function startTotpEnrollment(string $username): ?string
{
    require_once __DIR__ . '/Autoloader.php';
    $secret = \App\Totp::generateSecret();

    $stored = withJsonFileLock(USERS_FILE, function (array $users) use ($username, $secret) {
        if (!isset($users[$username])) {
            return [null, false];
        }
        $users[$username]['totp_pending_secret'] = $secret;
        return [$users, true];
    });

    return $stored ? $secret : null;
}

// Step 2: the user proves they can generate a valid code with the pending
// secret before it's promoted to active. Prevents enrolling a secret the
// user never actually got into their authenticator app.
function confirmTotpEnrollment(string $username, string $code): bool
{
    require_once __DIR__ . '/Autoloader.php';
    return withJsonFileLock(USERS_FILE, function (array $users) use ($username, $code) {
        $pending = $users[$username]['totp_pending_secret'] ?? null;
        if ($pending === null || !\App\Totp::verify($pending, $code)) {
            return [null, false];
        }
        $users[$username]['totp_secret'] = $pending;
        $users[$username]['totp_enabled'] = true;
        unset($users[$username]['totp_pending_secret']);
        return [$users, true];
    });
}

// Disabling requires the current password (see changeOwnPassword() for the
// same reasoning) — a security control shouldn't be removable by session
// alone, in case the session itself is what's compromised.
function disableTotpForUser(string $username, string $currentPassword): array
{
    $users = loadUsers();
    if (!isset($users[$username])) {
        return ['ok' => false, 'msg' => 'Usuario no encontrado.'];
    }
    if (!password_verify($currentPassword, $users[$username]['password'])) {
        return ['ok' => false, 'msg' => 'La contraseña actual no es correcta.'];
    }

    withJsonFileLock(USERS_FILE, function (array $users) use ($username) {
        if (!isset($users[$username])) return [null, null];
        unset($users[$username]['totp_secret'], $users[$username]['totp_enabled'], $users[$username]['totp_pending_secret']);
        return [$users, null];
    });

    return ['ok' => true, 'msg' => 'Verificación en dos pasos desactivada.'];
}

function getAllUsers(): array
{
    return loadUsers();
}

function hasUsers(): bool
{
    return !empty(loadUsers());
}

// ── Rate limiting (flat-file) ─────────────────────────────────────────────────

function attemptsFile(): string
{
    ensureDataDir();
    return DATA_DIR . 'attempts.json';
}

function getAttempts(string $user): array
{
    $f = attemptsFile();
    if (!file_exists($f)) return ['count' => 0, 'ts' => 0];
    $d = json_decode((string) file_get_contents($f), true) ?? [];
    return $d[$user] ?? ['count' => 0, 'ts' => 0];
}

function bumpAttempt(string $user): void
{
    withJsonFileLock(attemptsFile(), function (array $d) use ($user) {
        $d[$user] = ['count' => ($d[$user]['count'] ?? 0) + 1, 'ts' => time()];
        return [$d, null];
    });
}

function resetAttempts(string $user): void
{
    withJsonFileLock(attemptsFile(), function (array $d) use ($user) {
        unset($d[$user]);
        return [$d, null];
    });
}
