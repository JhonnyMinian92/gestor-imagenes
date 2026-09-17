<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';

requireAdmin();

$users = getAllUsers();
$csrfToken = csrfToken();
?>
<!DOCTYPE html>
<html lang="es">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gestión de Usuarios — <?= h(APP_NAME) ?></title>
  <link rel="stylesheet" href="assets/css/style.css">
  <link rel="stylesheet" href="assets/css/manage-users.css">
  <link rel="icon" type="image/x-icon" href="favicon.ico">
</head>

<body data-csrf-token="<?= h($csrfToken) ?>">
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
        <a href="index.php" class="nav-link">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="7" height="7" />
            <rect x="14" y="3" width="7" height="7" />
            <rect x="14" y="14" width="7" height="7" />
            <rect x="3" y="14" width="7" height="7" />
          </svg>
          Panel
        </a>
        <?php if (isAdmin()): ?>
        <a href="manage-users.php" class="nav-link active">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" />
            <circle cx="9" cy="7" r="4" />
            <path d="M23 21v-2a4 4 0 00-3-3.87" />
            <path d="M16 3.13a4 4 0 010 7.75" />
          </svg>
          Usuarios
        </a>
        <a href="security-log.php" class="nav-link">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="8" y1="13" x2="16" y2="13"></line>
            <line x1="8" y1="17" x2="16" y2="17"></line>
          </svg>
          Registro
        </a>
        <?php endif; ?>
        <a href="email-builder.php" class="nav-link">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
            <polyline points="22,6 12,13 2,6"></polyline>
          </svg>
          Plantillas
        </a>
        <a href="account.php" class="nav-link">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" />
            <circle cx="12" cy="7" r="4" />
          </svg>
          Mi cuenta
        </a>
      </div>
      <div class="navbar-end">
        <span class="user-badge">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" />
            <circle cx="12" cy="7" r="4" />
          </svg>
          <?= h($_SESSION['user']) ?>
        </span>
        <a href="logout.php" class="btn btn-ghost btn-sm">Cerrar sesión</a>
      </div>
    </nav>

    <!-- Content -->
    <main class="main-content">

      <!-- Page Header -->
      <div class="page-header">
        <div>
          <h1>Gestión de Usuarios</h1>
          <p class="text-muted">Crear, editar y eliminar usuarios del sistema</p>
        </div>
      </div>

      <!-- Alerts -->
      <div id="alert-container"></div>

      <!-- Create User Form -->
      <div class="card">
        <div class="card-header">
          <h2>Crear Nuevo Usuario</h2>
        </div>
        <div class="card-body">
          <form id="create-user-form">
            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
            <input type="hidden" name="action" value="create">

            <div class="form-row">
              <div class="form-group">
                <label for="username">Usuario</label>
                <input type="text" id="username" name="username" required minlength="3" maxlength="50"
                  placeholder="usuario123">
                <small>Solo letras, números y guiones bajos</small>
              </div>
              <div class="form-group">
                <label for="password">Contraseña</label>
                <input type="password" id="password" name="password" required minlength="8" maxlength="128"
                  placeholder="Mínimo 8 caracteres">
              </div>
              <div class="form-group">
                <label for="password2">Confirmar Contraseña</label>
                <input type="password" id="password2" name="password2" required minlength="8" maxlength="128"
                  placeholder="Confirmar contraseña">
              </div>
            </div>
            <button type="submit" class="btn btn-primary">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
              Crear usuario
            </button>
          </form>
        </div>
      </div>

      <!-- Users List -->
      <div class="card">
        <div class="card-header">
          <h2>Usuarios Existentes (<?= count($users) ?>)</h2>
        </div>
        <div class="card-body">
          <?php if (empty($users)): ?>
          <p class="text-muted text-center" style="padding: 2rem 0;">No hay usuarios registrados.</p>
          <?php else: ?>
          <div class="users-table">
            <table>
              <thead>
                <tr>
                  <th>Usuario</th>
                  <th>Creado</th>
                  <th>Rol</th>
                  <th>Acciones</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($users as $username => $userData): ?>
                <tr>
                  <td>
                    <strong><?= h($username) ?></strong>
                    <?php if ($username === $_SESSION['user']): ?>
                    <span class="badge badge-primary">Tú</span>
                    <?php endif; ?>
                  </td>
                  <td>
                    <small class="text-muted">
                      <?php
                          $date = DateTime::createFromFormat('U', (int)strtotime($userData['created_at']));
                          echo $date ? $date->format('d/m/Y H:i') : 'N/A';
                          ?>
                    </small>
                  </td>
                  <?php $displayRole = resolveUserRole($users, $username); ?>
                  <td>
                    <span
                      class="badge badge-<?= $displayRole === 'admin' ? 'primary' : 'secondary' ?>"><?= h(ucfirst($displayRole)) ?></span>
                  </td>
                  <td>
                    <div class="action-buttons">
                      <button type="button" class="btn btn-sm btn-secondary" data-action="open-password-modal"
                        data-username="<?= h($username) ?>">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                          stroke-width="2">
                          <path d="M12 2a10 10 0 1010 10H12.5"></path>
                        </svg>
                        Cambiar contraseña
                      </button>
                      <?php if ($username !== $_SESSION['user']): ?>
                      <button type="button" class="btn btn-sm btn-secondary" data-action="toggle-role"
                        data-username="<?= h($username) ?>"
                        data-new-role="<?= $displayRole === 'admin' ? 'user' : 'admin' ?>">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                          stroke-width="2">
                          <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" />
                          <circle cx="9" cy="7" r="4" />
                          <polyline points="16 11 18 13 22 9"></polyline>
                        </svg>
                        <?= $displayRole === 'admin' ? 'Quitar admin' : 'Hacer admin' ?>
                      </button>
                      <button type="button" class="btn btn-sm btn-danger" data-action="open-delete-modal"
                        data-username="<?= h($username) ?>">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                          stroke-width="2">
                          <polyline points="3 6 5 6 21 6"></polyline>
                          <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"></path>
                          <line x1="10" y1="11" x2="10" y2="17"></line>
                          <line x1="14" y1="11" x2="14" y2="17"></line>
                        </svg>
                        Eliminar
                      </button>
                      <?php endif; ?>
                    </div>
                  </td>
                </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
          <?php endif; ?>
        </div>
      </div>

    </main>

  </div>

  <!-- Change Password Modal -->
  <div id="password-modal" class="mu-modal">
    <div class="mu-modal-content">
      <div class="mu-modal-header">
        <h2 id="modal-title">Cambiar Contraseña</h2>
        <button type="button" class="mu-modal-close" data-action="close-password-modal">&times;</button>
      </div>
      <form id="password-form">
        <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
        <input type="hidden" name="action" value="update-password">
        <input type="hidden" name="username" id="modal-username">

        <div class="form-group">
          <label for="new-password">Nueva Contraseña</label>
          <input type="password" id="new-password" name="password" required minlength="8" maxlength="128"
            placeholder="Mínimo 8 caracteres">
        </div>
        <div class="form-group">
          <label for="confirm-password">Confirmar Contraseña</label>
          <input type="password" id="confirm-password" name="password2" required minlength="8" maxlength="128"
            placeholder="Confirmar contraseña">
        </div>

        <div style="display: flex; gap: 0.75rem; margin-top: 1.5rem;">
          <button type="submit" class="btn btn-primary">Actualizar</button>
          <button type="button" class="btn btn-secondary" data-action="close-password-modal">Cancelar</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Delete Confirmation Modal -->
  <div id="delete-modal" class="mu-modal">
    <div class="mu-modal-content mu-modal-sm">
      <div class="mu-modal-header">
        <h2>Confirmar Eliminación</h2>
        <button type="button" class="mu-modal-close" data-action="close-delete-modal">&times;</button>
      </div>
      <p id="delete-message"></p>
      <div style="display: flex; gap: 0.75rem; margin-top: 1.5rem;">
        <button type="button" class="btn btn-danger" id="confirm-delete-btn">Eliminar</button>
        <button type="button" class="btn btn-secondary" data-action="close-delete-modal">Cancelar</button>
      </div>
    </div>
  </div>

  <script src="assets/js/app.js"></script>
</body>

</html>