<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';

requireAdmin();

$PAGE_SIZE = IMAGES_PER_PAGE;

$entries = [];
if (is_file(SECURITY_LOG_FILE)) {
    $lines = file(SECURITY_LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $lines = array_reverse($lines); // most recent first
    foreach ($lines as $line) {
        $decoded = json_decode($line, true);
        if (is_array($decoded)) $entries[] = $decoded;
    }
}

$totalEntries = count($entries);
$totalPages   = max(1, (int) ceil($totalEntries / $PAGE_SIZE));
$currentPage  = isset($_GET['page']) ? (int) $_GET['page'] : 1;
$currentPage  = max(1, min($totalPages, $currentPage));
$pageEntries  = array_slice($entries, ($currentPage - 1) * $PAGE_SIZE, $PAGE_SIZE);

// Coarse severity grouping, purely for a visual hint in the UI — not a
// security boundary, just makes the log easier to scan.
$severityOf = function (string $event): string {
    if (in_array($event, ['login_failed', 'totp_login_failed', 'captcha_failed'], true)) return 'warn';
    if (in_array($event, ['session_hijack_suspected'], true)) return 'danger';
    return 'ok';
};
?>
<!DOCTYPE html>
<html lang="es">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Registro de seguridad — <?= h(APP_NAME) ?></title>
  <link rel="stylesheet" href="assets/css/style.css">
  <link rel="stylesheet" href="assets/css/manage-users.css">
  <link rel="icon" type="image/x-icon" href="favicon.ico">
  <style>
    .log-table td, .log-table th { font-size: .82rem; }
    .log-event { font-family: monospace; }
    .log-event.warn { color: #f59e0b; }
    .log-event.danger { color: #ef4444; font-weight: 600; }
  </style>
</head>

<body>
  <div class="app-wrapper">

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
        <a href="manage-users.php" class="nav-link">Usuarios</a>
        <a href="security-log.php" class="nav-link active">Registro de seguridad</a>
        <a href="email-builder.php" class="nav-link">Plantillas</a>
        <a href="account.php" class="nav-link">Mi cuenta</a>
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

    <main class="main-content">
      <div class="page-header">
        <div>
          <h1>Registro de seguridad</h1>
          <p class="text-muted">Eventos de autenticación y administración — solo lectura, <?= $totalEntries ?> registros</p>
        </div>
      </div>

      <div class="card">
        <div class="card-body">
          <?php if (empty($pageEntries)): ?>
            <p class="text-muted text-center" style="padding:2rem 0">Todavía no hay eventos registrados.</p>
          <?php else: ?>
            <div class="users-table log-table">
              <table>
                <thead>
                  <tr>
                    <th>Fecha</th>
                    <th>Evento</th>
                    <th>Usuario</th>
                    <th>IP</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($pageEntries as $entry): ?>
                    <tr>
                      <td><?= h((string) ($entry['ts'] ?? '')) ?></td>
                      <td class="log-event <?= h($severityOf((string) ($entry['event'] ?? ''))) ?>">
                        <?= h((string) ($entry['event'] ?? '')) ?>
                      </td>
                      <td><?= h((string) ($entry['user'] ?? '—')) ?></td>
                      <td><?= h((string) ($entry['ip'] ?? '—')) ?></td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>

            <?php if ($totalPages > 1): ?>
              <div class="pagination">
                <?php if ($currentPage > 1): ?>
                  <a href="?page=<?= $currentPage - 1 ?>" class="btn btn-ghost">&laquo; Anterior</a>
                <?php else: ?>
                  <span class="btn btn-ghost disabled">&laquo; Anterior</span>
                <?php endif; ?>
                <span class="pagination-info">Página <?= $currentPage ?> de <?= $totalPages ?></span>
                <?php if ($currentPage < $totalPages): ?>
                  <a href="?page=<?= $currentPage + 1 ?>" class="btn btn-ghost">Siguiente &raquo;</a>
                <?php else: ?>
                  <span class="btn btn-ghost disabled">Siguiente &raquo;</span>
                <?php endif; ?>
              </div>
            <?php endif; ?>
          <?php endif; ?>
        </div>
      </div>
    </main>
  </div>

  <script src="assets/js/app.js"></script>
</body>

</html>
