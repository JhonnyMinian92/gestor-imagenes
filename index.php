<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/Autoloader.php';

requireLogin();

if (!hasUsers()) {
  header('Location: setup.php');
  exit;
}

// Initialize variables
$images = [];
$totalImages = 0;
$totalSize = 0;
$latestMtime = null;
$currentPage = 1;
$totalPages = 1;

// --- H3: Get user quota usage for display ---
$userUsage = ['count' => 0, 'size' => 0];
if (defined('QUOTAS_ENABLED') && QUOTAS_ENABLED) {
  $userUsage = \App\ImageMetadata::getUserUsage($_SESSION['user']);
}

// --- H11 Remediation: Fetch images from metadata, not filesystem glob ---
$allImages = \App\ImageMetadata::getNonExpiredForUser($_SESSION['user']);
$totalImages = count($allImages);

if ($totalImages > 0) {
  $totalSize = array_sum(array_column($allImages, 'size'));
  $latestMtime = $allImages[0]['created_at']; // The list is pre-sorted by creation date

  // Pagination
  $imagesPerPage = defined('IMAGES_PER_PAGE') ? IMAGES_PER_PAGE : 24;
  $totalPages    = (int)ceil($totalImages / $imagesPerPage);
  $currentPage   = isset($_GET['page']) ? (int)$_GET['page'] : 1;
  $currentPage   = max(1, min($totalPages, $currentPage)); // Clamp page to valid range
  $offset        = ($currentPage - 1) * $imagesPerPage;

  $paginatedImages = array_slice($allImages, $offset, $imagesPerPage);

  // Add the 'url' to the final array for the view
  $baseUrl = getImagesBaseUrl();
  foreach ($paginatedImages as $img) {
    $images[] = [
      'filename' => $img['filename'],
      'url'      => $baseUrl . $img['filename'],
      'mtime'    => $img['created_at'], // Use created_at for display consistency
      'size'     => $img['size'] ?? 0,
    ];
  }
}

$csrfToken   = csrfToken();
?>
<!DOCTYPE html>
<html lang="es">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Panel — <?= h(APP_NAME) ?></title>
  <link rel="stylesheet" href="assets/css/style.css">
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
        <a href="index.php" class="nav-link active">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="7" height="7" />
            <rect x="14" y="3" width="7" height="7" />
            <rect x="14" y="14" width="7" height="7" />
            <rect x="3" y="14" width="7" height="7" />
          </svg>
          Panel
        </a>
        <?php if (isAdmin()): // Only show Users link to admins 
        ?>
          <a href="manage-users.php" class="nav-link">
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

      <!-- Stats -->
      <div class="stats-bar">
        <div class="stat-card">
          <div class="stat-icon blue">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="3" width="18" height="18" rx="2" />
              <circle cx="8.5" cy="8.5" r="1.5" />
              <path d="m21 15-5-5L5 21" />
            </svg>
          </div>
          <div>
            <div class="stat-value" id="stat-count"><?= $totalImages ?></div>
            <div class="stat-label">Total de imágenes</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon green">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <ellipse cx="12" cy="5" rx="9" ry="3" />
              <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
              <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
            </svg>
          </div>
          <div>
            <div class="stat-value" id="stat-total-size" data-bytes="<?= h($totalSize) ?>">
              <?= $totalSize > 0 ? number_format($totalSize / (1024 * 1024), 1) . ' MB' : '0 MB' ?></div>
            <div class="stat-label">Almacenamiento usado</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon orange">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
          </div>
          <div>
            <div class="stat-value" id="stat-last-upload"><?= $latestMtime ? date('d M', $latestMtime) : '—' ?></div>
            <div class="stat-label">Última carga</div>
          </div>
        </div>
        <?php if (defined('QUOTAS_ENABLED') && QUOTAS_ENABLED): ?>
          <div class="stat-card">
            <div class="stat-icon purple">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                <polyline points="22 4 12 14.01 9 11.01" />
              </svg>
            </div>
            <div>
              <div class="stat-value" id="stat-user-quota" data-bytes="<?= h($userUsage['size']) ?>"
                data-max-bytes="<?= h(MAX_STORAGE_BYTES_PER_USER) ?>">
                <?= number_format($userUsage['size'] / (1024 * 1024), 1) ?> /
                <?= (int)(MAX_STORAGE_BYTES_PER_USER / (1024 * 1024)) ?> MB
              </div>
              <div class="stat-label">Tu cuota usada</div>
              <div class="progress-quota">
                <div id="progress-quota-fill" class="progress-quota-fill" style="width: <?=
                                                                                        MAX_STORAGE_BYTES_PER_USER > 0
                                                                                          ? min(100, ($userUsage['size'] / MAX_STORAGE_BYTES_PER_USER) * 100)
                                                                                          : 0 ?>%;"></div>
              </div>
            </div>
          </div>
        <?php endif; ?>
      </div>

      <!-- Upload + Gallery -->
      <div class="two-col">

        <!-- Upload card -->
        <div class="card" style="align-self:start">
          <div class="card-header">
            <h3>Subir imagen</h3>
          </div>

          <form id="upload-form" enctype="multipart/form-data" data-max-size="<?= MAX_FILE_SIZE ?>"
            data-allowed-types="<?= h(implode(',', ALLOWED_MIME_TYPES)) ?>">
            <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
            <input type="hidden" id="csrf-token" value="<?= h($csrfToken) ?>">

            <div class="upload-area" id="drop-zone">
              <input type="file" id="file-input" name="image" accept=".<?= implode(',.', ALLOWED_EXTENSIONS) ?>"
                aria-label="Seleccionar imagen para subir">
              <div class="upload-icon">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                  <polyline points="17 8 12 3 7 8" />
                  <line x1="12" y1="3" x2="12" y2="15" />
                </svg>
              </div>
              <h4>Suelta aquí o haz clic para buscar</h4>
              <p>Solo JPG y PNG &middot; Máx. <?= (int)(MAX_FILE_SIZE / 1024 / 1024) ?> MB</p>
            </div>

            <div class="preview-container" id="preview-container">
              <div class="preview-image-wrap">
                <img id="preview-img" src="" alt="Preview">
              </div>
              <div class="preview-info">
                <span id="preview-name"
                  style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:60%"></span>
                <span id="preview-size"></span>
              </div>
            </div>

            <div class="form-group">
              <label for="upload-expires">Expiración del enlace</label>
              <select id="upload-expires" name="expires_in">
                <?php foreach (ALLOWED_LINK_EXPIRATIONS as $seconds): ?>
                  <option value="<?= (int) $seconds ?>" <?= $seconds === DEFAULT_IMAGE_EXPIRATION_SECONDS ? 'selected' : '' ?>>
                    <?= h(formatDurationLabel($seconds)) ?>
                  </option>
                <?php endforeach; ?>
              </select>
            </div>

            <div class="progress-wrap" id="progress-wrap">
              <div class="progress-bar">
                <div class="progress-fill" id="progress-fill"></div>
              </div>
              <div class="progress-label" id="progress-label">0%</div>
            </div>

            <button type="submit" class="btn btn-primary btn-block" id="upload-btn" disabled>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
              Subir imagen
            </button>
          </form>
        </div>

        <!-- Gallery card -->
        <div class="card">
          <div class="card-header">
            <h3>Biblioteca de imágenes</h3>
            <span style="color:var(--muted);font-size:.82rem">
              <span id="gallery-count"><?= $totalImages ?></span>
              <?= $totalImages !== 1 ? 'imágenes' : 'imagen' ?>
            </span>
          </div>

          <?php if ($totalImages > 0): ?>
          <div style="padding:0 1.25rem 1rem">
            <input type="search" id="gallery-filter" placeholder="Filtrar por nombre en esta página…"
              aria-label="Filtrar imágenes por nombre en esta página" autocomplete="off">
          </div>
          <?php endif; ?>

          <div class="images-grid" id="images-grid" data-current-page="<?= $currentPage ?>"
            data-total-pages="<?= $totalPages ?>">
            <?php if (empty($images)): ?>
              <div class="empty-state" id="empty-state">
                <svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 24 24" fill="none"
                  stroke="currentColor" stroke-width="1.5">
                  <rect x="3" y="3" width="18" height="18" rx="2" />
                  <circle cx="8.5" cy="8.5" r="1.5" />
                  <path d="m21 15-5-5L5 21" />
                </svg>
                <p>Aún no hay imágenes. ¡Sube la primera!</p>
              </div>
            <?php else: ?>
              <?php foreach ($images as $img): ?>
                <div class="image-card" data-filename="<?= h($img['filename']) ?>" data-url="<?= h($img['url']) ?>"
                  data-size="<?= h($img['size']) ?>">
                  <img class="image-card-thumb" src="<?= h($img['url']) ?>" alt="<?= h($img['filename']) ?>" loading="lazy">
                  <div class="image-card-body">
                    <div class="image-card-name" title="<?= h($img['filename']) ?>">
                      <?= h($img['filename']) ?>
                    </div>
                    <div class="image-card-actions">
                      <button class="btn btn-ghost btn-sm btn-copy-url" aria-label="Copiar URL">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                          <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                          <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
                        </svg>
                        Copiar URL
                      </button>
                      <button class="btn btn-danger btn-sm btn-delete" aria-label="Eliminar">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                          <polyline points="3 6 5 6 21 6" />
                          <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a1 1 0 011-1h4a1 1 0 011 1v2" />
                        </svg>
                        Eliminar
                      </button>
                    </div>
                  </div>
                </div>
              <?php endforeach; ?>
            <?php endif; ?>
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
        </div>

      </div><!-- /.two-col -->
    </main>
  </div>

  <script src="assets/js/app.js"></script>
</body>

</html>