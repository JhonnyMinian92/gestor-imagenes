<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/Autoloader.php';

requireLogin();

// Fetch user's images from metadata.
// H3 remediation: cap the picker instead of rendering the user's entire library
// unconditionally — getNonExpiredForUser() is pre-sorted newest-first, so this
// keeps the most recent images regardless of how large MAX_FILES_PER_USER is
// (or if quotas are ever disabled).
$allUserImages = array_slice(\App\ImageMetadata::getNonExpiredForUser($_SESSION['user']), 0, IMAGES_PER_PAGE);
$images = [];
$baseUrl = getImagesBaseUrl();
foreach ($allUserImages as $img) {
  $images[] = [
    'filename' => $img['filename'],
    'url'      => $baseUrl . $img['filename'],
    'mtime'    => $img['created_at'],
  ];
}

$csrfToken = csrfToken();

$templateBase64 = '';
$templateFound  = false;
$templatePath   = __DIR__ . DIRECTORY_SEPARATOR . 'plantilla' . DIRECTORY_SEPARATOR . 'plantilla-renovacion.html';
$rawTemplate    = @file_get_contents($templatePath);
if ($rawTemplate !== false && $rawTemplate !== '') {
  $templateBase64 = base64_encode($rawTemplate);
  $templateFound  = true;
}
?>
<!DOCTYPE html>
<html lang="es">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Plantillas de correo — <?= h(APP_NAME) ?></title>
  <link rel="stylesheet" href="assets/css/style.css">
  <link rel="icon" type="image/x-icon" href="favicon.ico">
</head>

<body data-template-b64="<?= h($templateBase64) ?>" data-template-missing="<?= $templateFound ? '0' : '1' ?>">
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
        <a href="email-builder.php" class="nav-link active">
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
      <div class="page-header">
        <h2>Editor de plantilla de correo</h2>
        <p>Completa los campos — la vista previa y el código se actualizan en tiempo real</p>
      </div>

      <div class="email-builder" id="email-builder">

        <!-- ── Izquierda: formulario ────────────────────────────────── -->
        <div>
          <div class="card email-form">
            <div class="card-header">
              <h3>Configuración de la plantilla</h3>
            </div>

            <form id="template-form" autocomplete="off">

              <!-- Imagen adicional (opcional) -->
              <div class="form-group">
                <label>Imagen adicional <span style="font-weight:400;color:var(--muted)">(opcional)</span></label>
                <?php if (empty($images)): ?>
                  <div style="color:var(--muted);font-size:.82rem;padding:.35rem 0">
                    No hay imágenes. <a href="index.php">Sube imágenes</a> desde el Panel.
                  </div>
                <?php else: ?>
                  <div class="image-picker-grid" id="image-picker-grid">
                    <?php foreach ($images as $img): ?>
                      <div class="image-picker-item" data-url="<?= h($img['url']) ?>"
                        data-filename="<?= h($img['filename']) ?>" role="button" tabindex="0"
                        aria-label="Seleccionar <?= h($img['filename']) ?>">
                        <img src="<?= h($img['url']) ?>" alt="<?= h($img['filename']) ?>" loading="lazy">
                      </div>
                    <?php endforeach; ?>
                  </div>
                  <button type="button" id="clear-img-btn" class="btn btn-ghost btn-sm"
                    style="margin-top:.4rem;width:100%;display:none">
                    × Quitar imagen seleccionada
                  </button>
                <?php endif; ?>
              </div>

              <!-- Título de notificación -->
              <div class="form-group">
                <label for="tpl-titulo">Título de notificación</label>
                <input type="text" id="tpl-titulo" value="Notificación de caducidad"
                  placeholder="Ej: Notificación de caducidad">
              </div>

              <!-- Nombre del usuario -->
              <div class="form-group">
                <label for="tpl-nombre">Nombre del usuario</label>
                <input type="text" id="tpl-nombre" value="Laura Gomez Ruidiaz"
                  placeholder="Nombre completo del destinatario">
              </div>

              <!-- Fecha de caducidad -->
              <div class="form-group">
                <label for="tpl-fecha">Fecha de caducidad</label>
                <input type="text" id="tpl-fecha" value="12 de agosto de 2025"
                  placeholder="Ej: 15 de septiembre de 2025">
              </div>

              <!-- Tipo de solicitud -->
              <div class="form-group">
                <label for="tpl-tipo">Tipo de solicitud</label>
                <input type="text" id="tpl-tipo" value="Firma P12 + Security Factura"
                  placeholder="Ej: Firma P12 + Security Factura">
              </div>

              <!-- Enlace de renovación -->
              <div class="form-group">
                <label for="tpl-enlace">Enlace de renovación</label>
                <input type="url" id="tpl-enlace" value="https://portal-sd.securitydata.net.ec" placeholder="https://...">
              </div>

              <!-- Enlace de rechazo -->
              <div class="form-group">
                <label for="tpl-enlace2">Enlace de rechazo</label>
                <input type="url" id="tpl-enlace2" value="https://portal-sd.securitydata.net.ec" placeholder="https://...">
              </div>

              <!-- Tabla de detalles -->
              <div class="form-group">
                <label>Detalles del certificado</label>
                <div id="tabla-rows" style="margin-top:.35rem"></div>
                <button type="button" class="btn btn-ghost btn-sm" id="add-row-btn" style="margin-top:.5rem;width:100%">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="12" y1="5" x2="12" y2="19" />
                    <line x1="5" y1="12" x2="19" y2="12" />
                  </svg>
                  Agregar fila
                </button>
              </div>

            </form>
          </div>
        </div>

        <!-- ── Derecha: vista previa + código simultáneos ─────────── -->
        <div>
          <div class="card" style="padding:0;overflow:hidden">

            <!-- Barra superior -->
            <div class="email-preview-header">
              <div style="display:flex;align-items:center;gap:.5rem;font-size:.85rem;font-weight:600">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                Vista previa
              </div>
              <button class="btn btn-primary btn-sm" id="copy-code-btn">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                  <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
                </svg>
                Copiar HTML
              </button>
            </div>

            <!-- iframe de vista previa -->
            <div class="preview-frame-wrap">
              <iframe id="preview-frame" class="preview-frame" title="Vista previa del correo"
                sandbox="allow-scripts"></iframe>
            </div>

            <!-- Cabecera del panel de código -->
            <div class="code-panel-header">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="16 18 22 12 16 6" />
                <polyline points="8 6 2 12 8 18" />
              </svg>
              Código HTML
              <span>(editable — los cambios se reflejan en la vista previa)</span>
            </div>

            <!-- Textarea de código editable -->
            <textarea id="code-output" class="code-output" spellcheck="false" autocorrect="off" autocapitalize="off"
              autocomplete="off" aria-label="Código HTML editable"></textarea>

          </div>
        </div>

      </div>
      <!-- /.email-builder -->
    </main>
  </div>
  <script src="assets/js/app.js"></script>
</body>

</html>