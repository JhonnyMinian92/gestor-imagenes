<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/Autoloader.php';

requireAdmin();

header('Content-Type: application/json');

$action = $_POST['action'] ?? '';
$response = ['ok' => false, 'msg' => ''];

// --- H7: Rate Limiting on API actions ---
if (RATE_LIMIT_ENABLED) {
  $limiter = new \App\RateLimiter(RATE_LIMIT_STORAGE_FILE);
  $userKey = 'api_' . ($_SESSION['user'] ?? 'guest');
  $result = $limiter->check($userKey, RATE_LIMIT_API_ATTEMPTS, RATE_LIMIT_API_WINDOW);

  if (!$result['allowed']) {
    http_response_code(429);
    header('Retry-After: ' . $result['retryAfter']);
    echo json_encode(['ok' => false, 'msg' => 'Demasiadas solicitudes. Inténtalo de nuevo más tarde.']);
    exit;
  }
}

if (empty($action) || !isset($_POST['csrf']) || !verifyCsrf($_POST['csrf'])) {
  $response['msg'] = 'Solicitud inválida';
  echo json_encode($response);
  exit;
}

switch ($action) {
  case 'create':
    $username  = trim($_POST['username'] ?? '');
    $password  = $_POST['password']  ?? '';
    $password2 = $_POST['password2'] ?? '';

    if (strlen($username) < 3 || strlen($username) > 50) {
      $response['msg'] = 'El usuario debe tener entre 3 y 50 caracteres.';
    } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
      $response['msg'] = 'El usuario solo puede contener letras, números y guiones bajos.';
    } elseif (strlen($password) > MAX_PASSWORD_LENGTH) {
      $response['msg'] = 'La contraseña es demasiado larga (máx. ' . MAX_PASSWORD_LENGTH . ' caracteres).';
    } elseif (!preg_match(PASSWORD_COMPLEXITY_REGEX, $password)) {
      $response['msg'] = PASSWORD_COMPLEXITY_MSG;
    } elseif ($password !== $password2) {
      $response['msg'] = 'Las contraseñas no coinciden.';
    } else {
      if (createUser($username, $password)) {
        $response['ok'] = true;
        $response['msg'] = 'Usuario creado exitosamente.';
        logSecurityEvent('user_created', ['user' => $username, 'admin' => $_SESSION['user']]);
      } else {
        $response['msg'] = 'El usuario ya existe.';
      }
    }
    break;

  case 'delete':
    $username = trim($_POST['username'] ?? '');
    $currentUser = $_SESSION['user'] ?? '';

    if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
      $response['msg'] = 'Nombre de usuario inválido.';
    } elseif ($username === $currentUser) {
      $response['msg'] = 'No puedes eliminar tu propia cuenta.';
    } else {
      // B7: friendlier message when the target is the last remaining admin.
      // deleteUser() enforces this atomically regardless; this is just a nicer error.
      $existingUsers = getAllUsers();
      $isLastAdmin = isset($existingUsers[$username])
        && resolveUserRole($existingUsers, $username) === 'admin'
        && count(array_filter(array_keys($existingUsers), fn($u) => resolveUserRole($existingUsers, $u) === 'admin')) <= 1;

      if ($isLastAdmin) {
        $response['msg'] = 'No puedes eliminar al último administrador del sistema.';
      } elseif (deleteUser($username)) {
        $response['ok'] = true;
        $response['msg'] = 'Usuario eliminado exitosamente.';
        logSecurityEvent('user_deleted', ['user' => $username, 'admin' => $_SESSION['user']]);
      } else {
        $response['msg'] = 'El usuario no existe.';
      }
    }
    break;

  case 'update-password':
    $username  = trim($_POST['username'] ?? '');
    $password  = $_POST['password']  ?? '';
    $password2 = $_POST['password2'] ?? '';
    $currentUser = $_SESSION['user'] ?? '';

    if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
      $response['msg'] = 'Nombre de usuario inválido.';
      // Admin can change anyone's password without knowing the current one (needed
      // for account recovery). A user changing their OWN password without admin
      // help now has a dedicated self-service flow: account.php/account-action.php,
      // which does require the current password.
    } elseif (strlen($password) > MAX_PASSWORD_LENGTH) {
      $response['msg'] = 'La contraseña es demasiado larga (máx. ' . MAX_PASSWORD_LENGTH . ' caracteres).';
    } elseif (!preg_match(PASSWORD_COMPLEXITY_REGEX, $password)) {
      $response['msg'] = PASSWORD_COMPLEXITY_MSG;
    } elseif ($password !== $password2) {
      $response['msg'] = 'Las contraseñas no coinciden.';
    } else {
      if (updateUserPassword($username, $password)) {
        $response['ok'] = true;
        $response['msg'] = 'Contraseña actualizada exitosamente.';
        logSecurityEvent('password_changed_by_admin', ['user' => $username, 'admin' => $_SESSION['user']]);
      } else {
        $response['msg'] = 'Error al actualizar la contraseña.';
      }
    }
    break;

  case 'set-role':
    $username = trim($_POST['username'] ?? '');
    $role     = trim($_POST['role'] ?? '');
    $currentUser = $_SESSION['user'] ?? '';

    if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
      $response['msg'] = 'Nombre de usuario inválido.';
    } elseif ($username === $currentUser) {
      // Same protection as self-deletion: an admin changing their OWN role
      // could lock themselves out of this very page. Another admin can
      // change it for them if that's really the intent.
      $response['msg'] = 'No puedes cambiar tu propio rol.';
    } elseif (!in_array($role, ['admin', 'user'], true)) {
      $response['msg'] = 'Rol inválido.';
    } else {
      $result = setUserRole($username, $role);
      $response['ok'] = $result['ok'];
      $response['msg'] = $result['msg'];
      if ($result['ok']) {
        logSecurityEvent('role_changed', ['user' => $username, 'role' => $role, 'admin' => $currentUser]);
      }
    }
    break;

  default:
    $response['msg'] = 'Acción no reconocida.';
}

echo json_encode($response);
