<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';

requireLogin();

$user = $_SESSION['user'];
$users = getAllUsers();
$userData = $users[$user] ?? [];
$role = resolveUserRole($users, $user);
$totpEnabled = userTotpEnabled($userData);
$totpPendingSecret = $userData['totp_pending_secret'] ?? null;

$csrfToken = csrfToken();

$statusMsg  = $_GET['msg'] ?? '';
$statusType = ($_GET['status'] ?? '') === 'ok' ? 'success' : 'error';
?>
<!DOCTYPE html>
<html lang="es">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mi cuenta — <?= h(APP_NAME) ?></title>
  <link rel="stylesheet" href="assets/css/style.css">
  <link rel="stylesheet" href="assets/css/manage-users.css">
  <link rel="icon" type="image/x-icon" href="favicon.ico">
</head>

<body>
  <div class="app-wrapper">

    <!-- Navbar -->
    <nav class="navbar">
      <a href="index.php" class="navbar-brand">
        <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none"
          stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <circle cx="8.5" cy="8.5" r="1.5" />
          <path d="m21 15-5-5L5 21" />
        </svg>
        <?= h(APP_NAME) ?>
      </a>
      <div class="navbar-nav">
        <a href="index.php" class="nav-link">Panel</a>
        <?php if (isAdmin()): ?>
          <a href="manage-users.php" class="nav-link">Usuarios</a>
          <a href="security-log.php" class="nav-link">Registro de seguridad</a>
        <?php endif; ?>
        <a href="email-builder.php" class="nav-link">Plantillas</a>
        <a href="account.php" class="nav-link active">Mi cuenta</a>
      </div>
      <div class="navbar-end">
        <span class="user-badge">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" />
            <circle cx="12" cy="7" r="4" />
          </svg>
          <?= h($user) ?>
        </span>
        <a href="logout.php" class="btn btn-ghost btn-sm">Cerrar sesión</a>
      </div>
    </nav>

    <main class="main-content">

      <div class="page-header">
        <div>
          <h1>Mi cuenta</h1>
          <p class="text-muted">
            <?= h($user) ?>
            <span class="badge badge-<?= $role === 'admin' ? 'primary' : 'secondary' ?>"><?= h(ucfirst($role)) ?></span>
          </p>
        </div>
      </div>

      <div id="alert-container">
        <?php if ($statusMsg): ?>
          <div class="alert alert-<?= $statusType ?>"><?= h($statusMsg) ?></div>
        <?php endif; ?>
      </div>

      <!-- Change own password -->
      <div class="card">
        <div class="card-header">
          <h2>Cambiar mi contraseña</h2>
        </div>
        <div class="card-body">
          <form method="POST" action="account-action.php">
            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
            <input type="hidden" name="action" value="change-password">
            <div class="form-group">
              <label for="current_password">Contraseña actual</label>
              <input type="password" id="current_password" name="current_password" required
                autocomplete="current-password" maxlength="<?= MAX_PASSWORD_LENGTH ?>">
            </div>
            <div class="form-group">
              <label for="new_password">Contraseña nueva</label>
              <input type="password" id="new_password" name="password" required minlength="8"
                maxlength="<?= MAX_PASSWORD_LENGTH ?>" autocomplete="new-password"
                placeholder="Mínimo 8 caracteres, con mayúscula, minúscula, número y carácter especial">
            </div>
            <div class="form-group">
              <label for="new_password2">Confirmar contraseña nueva</label>
              <input type="password" id="new_password2" name="password2" required minlength="8"
                maxlength="<?= MAX_PASSWORD_LENGTH ?>" autocomplete="new-password">
            </div>
            <button type="submit" class="btn btn-primary">Actualizar contraseña</button>
          </form>
        </div>
      </div>

      <!-- Two-factor authentication -->
      <div class="card">
        <div class="card-header">
          <h2>Verificación en dos pasos (2FA)</h2>
        </div>
        <div class="card-body">
          <?php if (!TOTP_ENABLED): ?>
            <p class="text-muted">La verificación en dos pasos no está habilitada en este servidor.</p>

          <?php elseif ($totpEnabled): ?>
            <p>✅ La verificación en dos pasos está <strong>activada</strong> en tu cuenta.</p>
            <form method="POST" action="account-action.php" style="margin-top:1rem">
              <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
              <input type="hidden" name="action" value="totp-disable">
              <div class="form-group">
                <label for="disable_password">Contraseña actual (para desactivar)</label>
                <input type="password" id="disable_password" name="current_password" required
                  autocomplete="current-password" maxlength="<?= MAX_PASSWORD_LENGTH ?>">
              </div>
              <button type="submit" class="btn btn-danger">Desactivar 2FA</button>
            </form>

          <?php elseif ($totpPendingSecret): ?>
            <p>Escanea esta clave con tu aplicación de autenticación (Google Authenticator, Authy, etc.)
              o ingrésala manualmente, luego confirma con el código de 6 dígitos que te muestre:</p>
            <p style="font-family:monospace;font-size:1.1rem;letter-spacing:.1em;background:#0f172a;padding:.75rem;border-radius:.375rem;word-break:break-all">
              <?= h($totpPendingSecret) ?>
            </p>
            <form method="POST" action="account-action.php" style="margin-top:1rem">
              <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
              <input type="hidden" name="action" value="totp-confirm">
              <div class="form-group">
                <label for="confirm_code">Código de 6 dígitos</label>
                <input type="text" id="confirm_code" name="totp_code" inputmode="numeric" maxlength="6" required autofocus>
              </div>
              <div style="display:flex;gap:.75rem">
                <button type="submit" class="btn btn-primary">Confirmar y activar</button>
                <button type="submit" form="cancel-totp-form" class="btn btn-secondary">Cancelar</button>
              </div>
            </form>
            <form id="cancel-totp-form" method="POST" action="account-action.php" style="display:none">
              <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
              <input type="hidden" name="action" value="totp-cancel">
            </form>

          <?php else: ?>
            <p class="text-muted">Agrega una capa adicional de seguridad: además de tu contraseña,
              se te pedirá un código de un solo uso generado por una app de autenticación en tu teléfono.</p>
            <form method="POST" action="account-action.php" style="margin-top:1rem">
              <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
              <input type="hidden" name="action" value="totp-start">
              <button type="submit" class="btn btn-primary">Activar verificación en dos pasos</button>
            </form>
          <?php endif; ?>
        </div>
      </div>

    </main>
  </div>

  <script src="assets/js/app.js"></script>
</body>

</html>
