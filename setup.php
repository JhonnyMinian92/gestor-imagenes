<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';

startSecureSession();

if (hasUsers()) {
    header('Location: login.php');
    exit;
}

$error   = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Solicitud inválida. Por favor, recarga la página e inténtalo de nuevo.';
    } else {
        $username  = trim($_POST['username'] ?? '');
        $password  = $_POST['password']  ?? '';
        $password2 = $_POST['password2'] ?? '';

        if (strlen($username) < 3 || strlen($username) > 50) {
            $error = 'El usuario debe tener entre 3 y 50 caracteres.';
        } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            $error = 'El usuario solo puede contener letras, números y guiones bajos.';
        } elseif (strlen($password) > MAX_PASSWORD_LENGTH) {
            $error = 'La contraseña es demasiado larga (máx. ' . MAX_PASSWORD_LENGTH . ' caracteres).';
        } elseif (!preg_match(PASSWORD_COMPLEXITY_REGEX, $password)) {
            $error = PASSWORD_COMPLEXITY_MSG;
        } elseif ($password !== $password2) {
            $error = 'Las contraseñas no coinciden.';
        } else {
            createUser($username, $password);
            $success = true;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configuración — <?= h(APP_NAME) ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>

<body class="auth-page">
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-logo">
                <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="3" width="18" height="18" rx="2" />
                    <circle cx="8.5" cy="8.5" r="1.5" />
                    <path d="m21 15-5-5L5 21" />
                </svg>
            </div>
            <h1><?= h(APP_NAME) ?></h1>

            <?php if ($success): ?>
                <div class="alert alert-success">
                    ¡Cuenta de administrador creada!<br>
                    <a href="login.php" style="color:inherit;font-weight:600">Iniciar sesión ahora &rarr;</a>
                </div>
            <?php else: ?>
                <p class="auth-subtitle">Configuración inicial — crear cuenta de administrador</p>

                <?php if ($error): ?>
                    <div class="alert alert-error"><?= h($error) ?></div>
                <?php endif; ?>

                <form method="POST" action="setup.php" novalidate>
                    <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
                    <div class="form-group">
                        <label for="username">Usuario</label>
                        <input type="text" id="username" name="username"
                            value="<?= h($_POST['username'] ?? '') ?>"
                            autocomplete="username" required autofocus
                            minlength="3" maxlength="50">
                        <small>Solo letras, números y guiones bajos</small>
                    </div>
                    <div class="form-group">
                        <label for="password">Contraseña</label>
                        <input type="password" id="password" name="password"
                            autocomplete="new-password" required minlength="8" maxlength="128">
                        <small>Mínimo 8 caracteres, con mayúsculas, minúsculas y números.</small>
                    </div>
                    <div class="form-group">
                        <label for="password2">Confirmar contraseña</label>
                        <input type="password" id="password2" name="password2"
                            autocomplete="new-password" required>
                    </div>
                    <button type="submit" class="btn btn-primary btn-block">Crear cuenta</button>
                </form>
            <?php endif; ?>
        </div>
    </div>
</body>

</html>