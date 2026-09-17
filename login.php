<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/Autoloader.php';

startSecureSession();

if (!hasUsers()) {
    header('Location: setup.php');
    exit;
}

if (isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if (isset($_GET['cancel_2fa'])) {
    unset($_SESSION['pending_2fa_user'], $_SESSION['pending_2fa_time']);
    header('Location: login.php');
    exit;
}

$error = '';
$showCaptcha = false;
$captcha = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Two mutually-exclusive form shapes share this endpoint: the normal
    // username/password step, and (only for accounts that opted into 2FA)
    // the follow-up TOTP code step. The 'totp_code' field only exists on the
    // second form, so its presence alone tells us which one was submitted.
    $result = isset($_POST['totp_code']) ? attemptTotpLogin() : attemptLogin();
    if ($result['ok']) {
        header('Location: index.php');
        exit;
    }
    $error = $result['msg'] ?? '';
}

// Decide which step to render AFTER processing any POST above: a successful
// password step moves a 2FA-enabled account into "pending", and a failed
// TOTP attempt keeps it there — both need to redraw the code-entry form
// rather than the username/password one.
$pendingUser = $_SESSION['pending_2fa_user'] ?? null;
$showTotpForm = $pendingUser !== null
    && (time() - ($_SESSION['pending_2fa_time'] ?? 0)) <= PENDING_2FA_WINDOW_SECONDS;

if (!$showTotpForm) {
    // Generate a CAPTCHA for the view if needed, after any POST processing.
    if (CAPTCHA_ENABLED && ($_SESSION['login_failures'] ?? 0) >= CAPTCHA_AFTER_FAILED_ATTEMPTS) {
        $showCaptcha = true;
        $captcha = generateCaptcha();
    }
}
?>
<!DOCTYPE html>
<html lang="es">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Iniciar sesión — <?= h(APP_NAME) ?></title>
  <link rel="stylesheet" href="assets/css/style.css">
</head>

<body class="auth-page">
  <div class="auth-container">
    <div class="auth-card">
      <div class="auth-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none"
          stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <circle cx="8.5" cy="8.5" r="1.5" />
          <path d="m21 15-5-5L5 21" />
        </svg>
      </div>
      <h1><?= h(APP_NAME) ?></h1>
      <p class="auth-subtitle">Portal de gestión de imágenes</p>

      <?php if ($error): ?>
      <div class="alert alert-error"><?= h($error) ?></div>
      <?php endif; ?>

      <?php if ($showTotpForm): ?>
      <form id="totp-form" method="POST" action="login.php" novalidate>
        <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
        <div class="form-group">
          <label for="totp_code">Código de verificación</label>
          <input type="text" id="totp_code" name="totp_code" inputmode="numeric" pattern="[0-9]*"
            maxlength="6" autocomplete="one-time-code" required autofocus>
          <small>Abre tu aplicación de autenticación e ingresa el código de 6 dígitos.</small>
        </div>
        <button type="submit" class="btn btn-primary btn-block">Verificar</button>
      </form>
      <p style="text-align:center;margin-top:1rem">
        <a href="login.php?cancel_2fa=1" style="color:var(--muted);font-size:.85rem">¿No eres tú? Cancelar</a>
      </p>
      <?php else: ?>
      <form id="login-form" method="POST" action="login.php" novalidate data-public-key="<?= h(\App\Crypto::publicKeyPem()) ?>">
        <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
        <div class="form-group">
          <label for="username">Usuario</label>
          <input type="text" id="username" name="username" value="<?= h($_POST['username'] ?? '') ?>"
            autocomplete="username" required autofocus>
        </div>
        <div class="form-group">
          <label for="password">Contraseña</label>
          <input type="password" id="password" name="password" autocomplete="current-password" required>
        </div>

        <?php if ($showCaptcha): ?>
        <div class="form-group captcha-group">
          <label for="captcha">Verificación: ¿Cuánto es <?= $captcha['num1'] ?> + <?= $captcha['num2'] ?>?</label>
          <input type="number" id="captcha" name="captcha" required autocomplete="off">
        </div>
        <?php endif; ?>

        <button type="submit" class="btn btn-primary btn-block">Iniciar sesión</button>
      </form>
      <?php endif; ?>
    </div>
  </div>

  <script src="assets/js/app.js"></script>
</body>

</html>
