'use strict';

/* ── Utilidades ──────────────────────────────────────────────────────────────── */

// H6 remediation: escapes for BOTH HTML text and HTML-attribute-value contexts
// (the previous DOM round-trip only escaped &<> for text nodes, not quotes —
// unsafe if a caller ever interpolates the result inside src="" / title="").
const HTML_ESCAPE_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => HTML_ESCAPE_MAP[c]);
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function debounce(fn, ms) {
  let t;
  return function (...args) {
    clearTimeout(t);
    t = setTimeout(() => fn.apply(this, args), ms);
  };
}

/* ── Modal ───────────────────────────────────────────────────────────────────── */

function showModal({ title, body, bodyNodes, iconType, confirmText, confirmClass, cancelText, onConfirm, onCancel }) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';

  const iconMap = {
    danger: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a1 1 0 011-1h4a1 1 0 011 1v2"/></svg>',
    warning: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  };

  const iconHtml = iconType ? `<div class="modal-icon ${iconType}">${iconMap[iconType] || ''}</div>` : '';

  const cancelHtml = cancelText ? `<button class="btn btn-ghost" id="modal-cancel">${escapeHtml(cancelText)}</button>` : '';
  const confirmHtml = confirmText ? `<button class="btn ${confirmClass || 'btn-primary'}" id="modal-confirm">${escapeHtml(confirmText)}</button>` : '';

  // H6 remediation: placeholder only — the body is always populated below via
  // textContent/appendChild, never innerHTML, so no caller can smuggle markup
  // into the modal regardless of what it passes in.
  overlay.innerHTML = `
        <div class="modal">
            ${iconHtml}
            <div class="modal-title">${escapeHtml(title)}</div>
            <div class="modal-body"></div>
            <div class="modal-footer">${cancelHtml}${confirmHtml}</div>
        </div>`;

  document.body.appendChild(overlay);

  // H6 remediation: `body` is always plain text (textContent). For the rare
  // case that needs a little structure (e.g. a bolded phrase), `bodyNodes`
  // takes an array of strings and/or real DOM nodes built with
  // document.createElement — never a raw HTML string, so there is no
  // innerHTML sink here for any caller, trusted or not, to feed markup into.
  const modalBody = overlay.querySelector('.modal-body');
  if (bodyNodes) bodyNodes.forEach((n) => modalBody.appendChild(typeof n === 'string' ? document.createTextNode(n) : n));
  else if (body) modalBody.textContent = body;

  function close() {
    overlay.remove();
  }

  const confirmBtn = overlay.querySelector('#modal-confirm');
  const cancelBtn = overlay.querySelector('#modal-cancel');

  if (confirmBtn)
    confirmBtn.addEventListener('click', () => {
      close();
      if (onConfirm) onConfirm();
    });
  if (cancelBtn)
    cancelBtn.addEventListener('click', () => {
      close();
      if (onCancel) onCancel();
    });

  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) close();
  });

  if (confirmBtn) setTimeout(() => confirmBtn.focus(), 50);
  else if (cancelBtn) setTimeout(() => cancelBtn.focus(), 50);
}

/* ── Notificaciones toast ────────────────────────────────────────────────────── */

function showToast(msg, type = 'info', duration = 3500) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const ICONS = {
    success: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
    error: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    info: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  };

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = (ICONS[type] || ICONS.info) + '<span>' + escapeHtml(msg) + '</span>';
  container.appendChild(toast);

  const remove = () => {
    toast.style.animation = 'toastOut .22s ease forwards';
    setTimeout(() => toast.remove(), 220);
  };
  setTimeout(remove, duration);
  toast.addEventListener('click', remove);
}

/* ── Portapapeles ────────────────────────────────────────────────────────────── */

function copyToClipboard(text) {
  if (navigator.clipboard?.writeText) {
    navigator.clipboard
      .writeText(text)
      .then(() => showToast('¡Copiado al portapapeles!', 'success'))
      .catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;top:-9999px;opacity:0';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    showToast('¡Copiado!', 'success');
  } catch {
    showToast('No se pudo copiar', 'error');
  }
  document.body.removeChild(ta);
}

/* ── Helpers de galería ──────────────────────────────────────────────────────── */

function getCountEl() {
  return document.getElementById('stat-count') || document.getElementById('gallery-count');
}

function updateStatCount(delta) {
  const el = getCountEl();
  if (el) el.textContent = Math.max(0, (parseInt(el.textContent, 10) || 0) + delta);
}

function checkEmptyState() {
  const grid = document.getElementById('images-grid');
  const empty = document.getElementById('empty-state');
  if (!grid || !empty) return;
  empty.style.display = grid.querySelectorAll('.image-card').length === 0 ? 'block' : 'none';
}

function buildImageCard(filename, url) {
  const card = document.createElement('div');
  card.className = 'image-card';
  card.dataset.filename = filename;
  card.dataset.url = url;
  card.innerHTML = `
        <img class="image-card-thumb" src="${escapeHtml(url)}" alt="${escapeHtml(filename)}" loading="lazy">
        <div class="image-card-body">
            <div class="image-card-name" title="${escapeHtml(filename)}">${escapeHtml(filename)}</div>
            <div class="image-card-actions">
                <button class="btn btn-ghost btn-sm btn-copy-url">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                    Copiar URL
                </button>
                <button class="btn btn-danger btn-sm btn-delete">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a1 1 0 011-1h4a1 1 0 011 1v2"/></svg>
                    Eliminar
                </button>
            </div>
        </div>`;
  return card;
}

function addCardToGallery(filename, url) {
  const grid = document.getElementById('images-grid');
  const empty = document.getElementById('empty-state');
  if (!grid) return;
  if (empty) empty.style.display = 'none';
  const card = buildImageCard(filename, url);
  grid.insertBefore(card, grid.firstChild);
  updateStatCount(+1);
}

function updateDashboardStats(newImageSize) {
  if (typeof newImageSize !== 'number') return;

  // 1. Total Storage
  const totalSizeEl = document.getElementById('stat-total-size');
  if (totalSizeEl) {
    const currentBytes = parseInt(totalSizeEl.dataset.bytes, 10) || 0;
    const newTotalBytes = currentBytes + newImageSize;
    totalSizeEl.dataset.bytes = newTotalBytes;
    totalSizeEl.textContent = formatBytes(newTotalBytes);
  }

  // 2. Last Upload
  const lastUploadEl = document.getElementById('stat-last-upload');
  if (lastUploadEl && newImageSize > 0) {
    const now = new Date();
    const month = now.toLocaleString('es-ES', { month: 'short' });
    const day = now.getDate();
    // Capitalize month and remove dot if present (e.g., 'jul.' -> 'Jul')
    const formattedDate = `${day} ${month.charAt(0).toUpperCase() + month.slice(1).replace('.', '')}`;
    lastUploadEl.textContent = formattedDate;
  }

  // 3. User Quota
  const userQuotaEl = document.getElementById('stat-user-quota');
  const quotaFillEl = document.getElementById('progress-quota-fill');
  if (userQuotaEl && quotaFillEl) {
    const currentBytes = parseInt(userQuotaEl.dataset.bytes, 10) || 0;
    const maxBytes = parseInt(userQuotaEl.dataset.maxBytes, 10) || 0;
    const newUsageBytes = currentBytes + newImageSize;

    userQuotaEl.dataset.bytes = newUsageBytes;

    const newUsageMb = (newUsageBytes / (1024 * 1024)).toFixed(1);
    const maxMb = Math.round(maxBytes / (1024 * 1024));
    userQuotaEl.textContent = `${newUsageMb} / ${maxMb} MB`;

    const newPercentage = maxBytes > 0 ? Math.min(100, (newUsageBytes / maxBytes) * 100) : 0;
    quotaFillEl.style.width = `${newPercentage}%`;
  }
}

/* ── Eventos de galería ──────────────────────────────────────────────────────── */

function initGalleryEvents() {
  const grid = document.getElementById('images-grid');
  if (!grid) return;

  grid.addEventListener('click', (e) => {
    const copyBtn = e.target.closest('.btn-copy-url');
    const deleteBtn = e.target.closest('.btn-delete');

    if (copyBtn) {
      copyToClipboard(copyBtn.closest('.image-card').dataset.url);
      return;
    }
    if (deleteBtn) {
      handleDelete(deleteBtn.closest('.image-card'), deleteBtn);
    }
  });
}

/* ── Filtro de galería (cliente, solo dentro de la página actual) ────────────── */

function initGalleryFilter() {
  const input = document.getElementById('gallery-filter');
  const grid = document.getElementById('images-grid');
  if (!input || !grid) return;

  let noMatches = null;
  function ensureNoMatchesEl() {
    if (noMatches) return noMatches;
    noMatches = document.createElement('div');
    noMatches.className = 'empty-state';
    noMatches.id = 'gallery-filter-empty';
    noMatches.style.display = 'none';
    noMatches.innerHTML = '<p>Ninguna imagen de esta página coincide con el filtro.</p>';
    grid.appendChild(noMatches);
    return noMatches;
  }

  input.addEventListener(
    'input',
    debounce(() => {
      const query = input.value.trim().toLowerCase();
      const cards = grid.querySelectorAll('.image-card');
      let visibleCount = 0;

      cards.forEach((card) => {
        const matches = !query || (card.dataset.filename || '').toLowerCase().includes(query);
        card.style.display = matches ? '' : 'none';
        if (matches) visibleCount++;
      });

      ensureNoMatchesEl().style.display = query && visibleCount === 0 ? 'block' : 'none';
    }, 150),
  );
}

function handleDelete(card, btn) {
  const emphasis = document.createElement('strong');
  emphasis.textContent = 'Esta acción no se puede deshacer.';
  showModal({
    title: 'Eliminar imagen',
    bodyNodes: ['¿Estás seguro de que deseas eliminar esta imagen? ', emphasis],
    iconType: 'danger',
    confirmText: 'Eliminar',
    confirmClass: 'btn-danger',
    cancelText: 'Cancelar',
    onConfirm: () => performDelete(card, btn),
  });
}

function performDelete(card, btn) {
  const filename = card.dataset.filename;
  const imageSize = parseInt(card.dataset.size, 10) || 0;
  const csrfToken = document.getElementById('csrf-token')?.value || '';
  const origHTML = btn.innerHTML;

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';

  fetch('delete.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filename, csrf_token: csrfToken }),
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.success) {
        card.style.animation = 'fadeOut .3s ease forwards';
        setTimeout(() => {
          card.remove();
          updateStatCount(-1);
          updateDashboardStats(-imageSize);

          const grid = document.getElementById('images-grid');
          if (grid.querySelectorAll('.image-card').length === 0) {
            const currentPage = parseInt(grid.dataset.currentPage, 10);
            if (currentPage > 1) {
              // Redirect to previous page if current page is now empty
              window.location.href = `index.php?page=${currentPage - 1}`;
              return; // Don't show toast or check empty state, page will reload
            }
          }
          checkEmptyState(); // Show "empty" message if on page 1 and it's now empty
          showToast('Imagen eliminada', 'success');
        }, 300);
      } else {
        btn.disabled = false;
        btn.innerHTML = origHTML;
        showToast(data.error || 'Error al eliminar', 'error');
      }
    })
    .catch(() => {
      btn.disabled = false;
      btn.innerHTML = origHTML;
      showToast('Error de red — no se pudo eliminar la imagen', 'error');
    });
}

/* ── Subida de archivos ───────────────────────────────────────────────────────── */

function initUploader() {
  const form = document.getElementById('upload-form');
  const input = document.getElementById('file-input');
  const dropZone = document.getElementById('drop-zone');
  const preview = document.getElementById('preview-container');
  const previewImg = document.getElementById('preview-img');
  const previewName = document.getElementById('preview-name');
  const previewSize = document.getElementById('preview-size');
  const submitBtn = document.getElementById('upload-btn');
  const progressWrap = document.getElementById('progress-wrap');
  const progressFill = document.getElementById('progress-fill');
  const progressLbl = document.getElementById('progress-label');

  if (!form) return;

  // Leer configuración desde los atributos data-* del formulario para mantener consistencia con el backend.
  const MAX_SIZE = parseInt(form.dataset.maxSize, 10) || 10 * 1024 * 1024;
  const ALLOWED_TYPES = (form.dataset.allowedTypes || 'image/jpeg,image/png').split(',');
  const MAX_SIZE_MB = Math.round(MAX_SIZE / 1024 / 1024);

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) processFile(file);
  });

  input.addEventListener('change', () => {
    if (input.files[0]) processFile(input.files[0]);
  });

  function processFile(file) {
    if (!ALLOWED_TYPES.includes(file.type)) {
      showToast('Solo se permiten imágenes JPG y PNG', 'error');
      input.value = '';
      return;
    }
    if (file.size > MAX_SIZE) {
      showToast(`El archivo es demasiado grande (máx. ${MAX_SIZE_MB} MB)`, 'error');
      input.value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      previewImg.src = ev.target.result;
      previewName.textContent = file.name;
      previewSize.textContent = formatBytes(file.size);
      preview.classList.add('visible');
      submitBtn.disabled = false;
    };
    reader.readAsDataURL(file);
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!input.files[0]) return;

    const fd = new FormData(form);
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner"></span> Subiendo...';
    progressWrap.classList.add('visible');

    const xhr = new XMLHttpRequest();

    xhr.upload.addEventListener('progress', (ev) => {
      if (ev.lengthComputable) {
        const pct = Math.round((ev.loaded / ev.total) * 100);
        progressFill.style.width = pct + '%';
        progressLbl.textContent = pct + '%';
      }
    });

    xhr.addEventListener('load', () => {
      progressWrap.classList.remove('visible');
      progressFill.style.width = '0%';
      submitBtn.disabled = false;
      submitBtn.innerHTML = uploadBtnHTML();

      let res;
      try {
        res = JSON.parse(xhr.responseText);
      } catch {
        showToast('Respuesta inesperada del servidor', 'error');
        return;
      }

      if (res.success) {
        showToast('¡Imagen subida correctamente!', 'success');
        preview.classList.remove('visible');
        input.value = '';
        previewImg.src = '';
        addCardToGallery(res.filename, res.url);
        updateDashboardStats(res.size);
      } else {
        showToast(res.error || 'Error al subir', 'error');
      }
    });

    xhr.addEventListener('error', () => {
      progressWrap.classList.remove('visible');
      submitBtn.disabled = false;
      submitBtn.innerHTML = uploadBtnHTML();
      showToast('Error de red — no se pudo subir la imagen', 'error');
    });

    xhr.open('POST', 'upload.php');
    xhr.send(fd);
  });

  function uploadBtnHTML() {
    return `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg> Subir imagen`;
  }
}

/* ── Editor de plantilla de correo ───────────────────────────────────────────── */

// Rellenado desde atributos data-* del <body> (ver email-builder.php) en vez de un
// <script> inline: evita depender de hashes de CSP que se rompen si la plantilla cambia.
let EMAIL_TEMPLATE_HTML = '';
let EMAIL_TEMPLATE_MISSING = true;

function initEmailBuilder() {
  if (!document.getElementById('email-builder')) return;

  const b64 = document.body.dataset.templateB64 || '';
  EMAIL_TEMPLATE_MISSING = document.body.dataset.templateMissing === '1';
  EMAIL_TEMPLATE_HTML = b64 ? atob(b64) : '';

  /* Plantilla no encontrada → modal */
  if (EMAIL_TEMPLATE_MISSING) {
    const path = document.createElement('strong');
    path.textContent = 'plantilla/plantilla-renovacion.html';
    showModal({
      title: 'Plantilla no encontrada',
      bodyNodes: ['No se encontró el archivo ', path, '.', document.createElement('br'), 'Verifica que el archivo exista en el servidor.'],
      iconType: 'warning',
      confirmText: 'Entendido',
    });
    return;
  }

  /* Image picker */
  const clearImgBtn = document.getElementById('clear-img-btn');
  document.querySelectorAll('.image-picker-item').forEach((item) => {
    item.addEventListener('click', () => {
      const wasSelected = item.classList.contains('selected');
      document.querySelectorAll('.image-picker-item').forEach((i) => i.classList.remove('selected'));
      if (!wasSelected) {
        item.classList.add('selected');
        if (clearImgBtn) clearImgBtn.style.display = '';
      } else {
        if (clearImgBtn) clearImgBtn.style.display = 'none';
      }
      updatePreview();
    });
    item.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        item.click();
      }
    });
  });

  if (clearImgBtn) {
    clearImgBtn.addEventListener('click', () => {
      document.querySelectorAll('.image-picker-item').forEach((i) => i.classList.remove('selected'));
      clearImgBtn.style.display = 'none';
      updatePreview();
    });
  }

  /* Cambio de formulario → actualizar vista previa */
  const form = document.getElementById('template-form');
  if (form) {
    form.querySelectorAll('input, textarea, select').forEach((el) => {
      el.addEventListener('input', debounce(updatePreview, 280));
    });
  }

  /* Edición manual del textarea de código → actualizar solo el iframe */
  const codeTextarea = document.getElementById('code-output');
  if (codeTextarea) {
    codeTextarea.addEventListener(
      'input',
      debounce(() => {
        const frame = document.getElementById('preview-frame');
        if (frame) frame.srcdoc = codeTextarea.value;
      }, 400),
    );
  }

  /* Copiar HTML: copia el contenido actual del textarea */
  const copyBtn = document.getElementById('copy-code-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const html = codeTextarea ? codeTextarea.value : generateEmailHtml();
      copyToClipboard(html);
    });
  }

  /* Inicializar editor de filas de tabla y primer render */
  initTablaEditor();
}

/* ── Editor dinámico de filas de tabla ───────────────────────────────────────── */

function initTablaEditor() {
  const container = document.getElementById('tabla-rows');
  const addBtn = document.getElementById('add-row-btn');
  if (!container || !addBtn) return;

  function addRow(propiedad, valor) {
    const row = document.createElement('div');
    row.className = 'tabla-row';
    row.style.cssText = 'display:flex;gap:.4rem;margin-bottom:.4rem;align-items:center';

    const propInput = document.createElement('input');
    propInput.type = 'text';
    propInput.className = 'tabla-prop';
    propInput.placeholder = 'Propiedad';
    propInput.value = propiedad || '';
    propInput.style.flex = '1';

    const valInput = document.createElement('input');
    valInput.type = 'text';
    valInput.className = 'tabla-val';
    valInput.placeholder = 'Valor';
    valInput.value = valor || '';
    valInput.style.flex = '1';

    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'btn btn-danger btn-sm';
    delBtn.style.flexShrink = '0';
    delBtn.innerHTML = '&times;';
    delBtn.addEventListener('click', () => {
      row.remove();
      updatePreview();
    });

    [propInput, valInput].forEach((el) => el.addEventListener('input', debounce(updatePreview, 280)));

    row.appendChild(propInput);
    row.appendChild(valInput);
    row.appendChild(delBtn);
    container.appendChild(row);
  }

  addBtn.addEventListener('click', () => {
    addRow('', '');
    updatePreview();
  });

  /* Filas por defecto */
  addRow('Identificación', '1234567890');
  addRow('Correo', 'usuario@empresa.com');
  addRow('Teléfono', '0987654321');

  updatePreview();
}

/* ── Saneamiento de URLs (M7: bloquea esquemas javascript:/data: etc.) ───────── */

function sanitizeUrl(raw) {
  const value = (raw || '').trim();
  if (value === '') return '#';
  if (/^https?:\/\//i.test(value) || value.startsWith('/') || value.startsWith('#')) {
    return encodeURI(value).replace(/"/g, '%22');
  }
  return '#';
}

/* ── Construir HTML de la sección cuerpo ─────────────────────────────────────── */

function buildCuerpoHtml() {
  let html = '';

  /* Imagen adicional seleccionada desde la galería */
  const selectedPicker = document.querySelector('.image-picker-item.selected');
  if (selectedPicker) {
    const imgUrl = encodeURI(selectedPicker.dataset.url || '').replace(/"/g, '%22');
    if (imgUrl) {
      html += `<div style="margin-bottom:16px;text-align:center"><img src="${imgUrl}" alt="${escapeHtml(selectedPicker.dataset.filename || 'Imagen')}" style="max-width:100%;height:auto;border-radius:8px;display:inline-block;"></div>\n`;
    }
  }

  /* Tabla de detalles */
  const rows = document.querySelectorAll('#tabla-rows .tabla-row');
  if (rows.length > 0) {
    let filas = '';
    rows.forEach((row) => {
      const prop = escapeHtml(row.querySelector('.tabla-prop').value);
      const vl = escapeHtml(row.querySelector('.tabla-val').value);
      filas += `<tr><td width="40%" style="padding:10px 16px;color:#6b7280;font-family:Arial,Helvetica,sans-serif;font-size:13px;">${prop}</td><td style="padding:10px 16px;font-weight:bold;font-family:Arial,Helvetica,sans-serif;font-size:13px;">${vl}</td></tr>`;
    });
    html += `<table role="presentation" cellpadding="0" cellspacing="0" width="100%" border="0" style="border-collapse:collapse;color:#111827;"><tbody>${filas}</tbody></table>`;
  }

  return html;
}

/* ── Actualizar vista previa e iframe ────────────────────────────────────────── */

function updatePreview() {
  const html = generateEmailHtml();

  const frame = document.getElementById('preview-frame');
  if (frame) frame.srcdoc = html;

  const codeEl = document.getElementById('code-output');
  if (codeEl) codeEl.value = html;
}

function val(id, fallback = '') {
  const el = document.getElementById(id);
  return el ? el.value : fallback;
}

/* ── Generar HTML usando plantilla-renovacion.html ───────────────────────────── */

function generateEmailHtml() {
  if (!EMAIL_TEMPLATE_HTML) {
    return '<p style="color:red;font-family:sans-serif;padding:20px">Plantilla no disponible. Verifica que el archivo plantilla/plantilla-renovacion.html exista.</p>';
  }

  const titulo = val('tpl-titulo', 'Notificación de caducidad');
  const nombre = val('tpl-nombre', 'Usuario');
  const fecha = val('tpl-fecha', '—');
  const tipo = val('tpl-tipo', '—');
  const enlace = val('tpl-enlace', '#');
  const enlace2 = val('tpl-enlace2', '#');
  const cuerpo = buildCuerpoHtml();

  const safeEnlace = sanitizeUrl(enlace);
  const safeEnlace2 = sanitizeUrl(enlace2);

  return EMAIL_TEMPLATE_HTML.replace(/\[tituloNotificacion\]/g, () => escapeHtml(titulo))
    .replace(/\[nombreUsuario\]/g, () => escapeHtml(nombre))
    .replace(/\[cuerpo2\]/g, () => escapeHtml(fecha))
    .replace(/\[tipoSolicitud\]/g, () => escapeHtml(tipo))
    .replace(/\[cuerpo\]/g, () => cuerpo)
    .replace(/href="\[enlace\]"/g, () => `href="${safeEnlace}"`)
    .replace(/href="\[enlace2\]"/g, () => `href="${safeEnlace2}"`);
}

/* ── Login: cifrado híbrido RSA + AES-GCM de usuario/contraseña ──────────────── */
// Cifrado de campo, además de (no en lugar de) HTTPS. La clave pública RSA
// del servidor viaja en el propio HTML (no es secreta: solo sirve para
// cifrar). En cada envío el navegador genera una clave AES-256 nueva y
// aleatoria, cifra con ella el usuario y la contraseña, y cifra esa clave
// AES con la clave pública RSA del servidor. Solo la clave privada del
// servidor — que nunca sale de él — puede recuperar la clave AES y, con
// ella, las credenciales. El csrf_token sigue viajando tal cual: no es un
// secreto, solo prueba que la petición vino del propio formulario.

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

async function encryptLoginCredentials(publicKeyPem, username, password) {
  const publicKey = await window.crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(publicKeyPem),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );

  // Clave AES de un solo uso: nueva y aleatoria en cada envío del formulario.
  const aesKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey);

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify({ username, password }));
  const ciphertext = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
  const encryptedKey = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, rawAesKey);

  return {
    enc_key: bufferToBase64(encryptedKey),
    enc_iv: bufferToBase64(iv),
    enc_data: bufferToBase64(ciphertext),
  };
}

function initLoginPage() {
  const loginForm = document.getElementById('login-form');
  if (!loginForm) return;

  const publicKeyPem = loginForm.dataset.publicKey;
  // Sin clave pública o sin Web Crypto disponible (p. ej. la página no se
  // cargó en un contexto seguro) el formulario se envía tal cual, sin
  // cifrado de campo — igual que cualquier envío HTTPS estándar.
  if (!publicKeyPem || !window.crypto?.subtle) return;

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const btn = loginForm.querySelector('button[type="submit"]');
    const btnOrigHTML = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Procesando...';

    const username = loginForm.querySelector('input[name="username"]').value;
    const password = loginForm.querySelector('input[name="password"]').value;
    const csrfToken = loginForm.querySelector('input[name="csrf_token"]').value;
    const captchaEl = loginForm.querySelector('input[name="captcha"]');

    try {
      const encrypted = await encryptLoginCredentials(publicKeyPem, username, password);

      // El usuario/contraseña visibles nunca se envían: se construye un
      // formulario oculto aparte con solo los campos cifrados + csrf_token
      // (+ captcha, si aplica) y es ese el que se envía.
      const hiddenForm = document.createElement('form');
      hiddenForm.method = 'POST';
      hiddenForm.action = loginForm.action;
      hiddenForm.style.display = 'none';

      const fields = { csrf_token: csrfToken, ...encrypted };
      if (captchaEl) fields.captcha = captchaEl.value;

      for (const [name, value] of Object.entries(fields)) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = value;
        hiddenForm.appendChild(input);
      }

      document.body.appendChild(hiddenForm);
      hiddenForm.submit();
    } catch (error) {
      console.error('Fallo el cifrado del login:', error);
      btn.disabled = false;
      btn.innerHTML = btnOrigHTML;
      showToast('Error de cifrado. No se pudo iniciar sesión.', 'error');
    }
  });
}

/* ── Arranque ─────────────────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', () => {
  initGalleryEvents();
  initGalleryFilter();
  initUploader();
  initEmailBuilder();
  initManageUsersPage();
  initLoginPage();
});

/* ── Lógica de la página de gestión de usuarios ──────────────────────────────── */

function initManageUsersPage() {
  const createUserForm = document.getElementById('create-user-form');
  if (!createUserForm) return; // Only run on the manage users page

  const CSRF_TOKEN = document.body.dataset.csrfToken || '';
  let usernameToDelete = null;

  // --- Form Submissions ---
  createUserForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
      const response = await fetch('manage-users-action.php', { method: 'POST', body: formData });
      const data = await response.json();
      showAlert(data.ok ? 'success' : 'error', data.msg);
      if (data.ok) {
        e.target.reset();
        setTimeout(() => location.reload(), 1500);
      }
    } catch (error) {
      showAlert('error', 'Error al procesar la solicitud');
      console.error(error);
    }
  });

  document.getElementById('password-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
      const response = await fetch('manage-users-action.php', { method: 'POST', body: formData });
      const data = await response.json();
      showAlert(data.ok ? 'success' : 'error', data.msg);
      if (data.ok) {
        closePasswordModal();
        setTimeout(() => location.reload(), 1500);
      }
    } catch (error) {
      showAlert('error', 'Error al procesar la solicitud');
      console.error(error);
    }
  });

  // --- Modal Logic ---
  function openChangePasswordModal(username) {
    document.getElementById('modal-username').value = username;
    document.getElementById('modal-title').textContent = `Cambiar contraseña de "${username}"`;
    document.getElementById('password-modal').classList.add('active');
    document.getElementById('new-password').focus();
  }

  function closePasswordModal() {
    const modal = document.getElementById('password-modal');
    if (modal) modal.classList.remove('active');
    document.getElementById('password-form')?.reset();
  }

  function openDeleteModal(username) {
    usernameToDelete = username;
    const messageEl = document.getElementById('delete-message');
    if (messageEl) messageEl.textContent = `¿Está seguro de que desea eliminar el usuario "${username}"? Esta acción no se puede deshacer.`;
    document.getElementById('delete-modal')?.classList.add('active');
  }

  function closeDeleteModal() {
    document.getElementById('delete-modal')?.classList.remove('active');
    usernameToDelete = null;
  }

  async function confirmDelete() {
    if (!usernameToDelete) return;

    const formData = new FormData();
    formData.append('action', 'delete');
    formData.append('username', usernameToDelete);
    formData.append('csrf', CSRF_TOKEN);

    try {
      const response = await fetch('manage-users-action.php', { method: 'POST', body: formData });
      const data = await response.json();
      showAlert(data.ok ? 'success' : 'error', data.msg);
      if (data.ok) {
        closeDeleteModal();
        setTimeout(() => location.reload(), 1500);
      }
    } catch (error) {
      showAlert('error', 'Error al procesar la solicitud');
      console.error(error);
    }
  }

  function showAlert(type, message) {
    const container = document.getElementById('alert-container');
    if (!container) return;
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    container.appendChild(alert);
    setTimeout(() => alert.remove(), 5000);
  }

  async function toggleRole(username, newRole) {
    const formData = new FormData();
    formData.append('action', 'set-role');
    formData.append('username', username);
    formData.append('role', newRole);
    formData.append('csrf', CSRF_TOKEN);

    try {
      const response = await fetch('manage-users-action.php', { method: 'POST', body: formData });
      const data = await response.json();
      showAlert(data.ok ? 'success' : 'error', data.msg);
      if (data.ok) setTimeout(() => location.reload(), 1200);
    } catch (error) {
      showAlert('error', 'Error al procesar la solicitud');
      console.error(error);
    }
  }

  // --- Event Delegation for actions ---
  document.querySelector('.app-wrapper')?.addEventListener('click', (e) => {
    const target = e.target;
    const openPass = target.closest('[data-action="open-password-modal"]');
    if (openPass) openChangePasswordModal(openPass.dataset.username);

    const openDel = target.closest('[data-action="open-delete-modal"]');
    if (openDel) openDeleteModal(openDel.dataset.username);

    const toggleRoleBtn = target.closest('[data-action="toggle-role"]');
    if (toggleRoleBtn) {
      const { username, newRole } = toggleRoleBtn.dataset;
      const verb = newRole === 'admin' ? 'hacer administrador a' : 'quitarle el rol de administrador a';
      showModal({
        title: 'Confirmar cambio de rol',
        body: `¿Seguro que quieres ${verb} "${username}"?`,
        iconType: 'warning',
        confirmText: 'Confirmar',
        confirmClass: 'btn-primary',
        cancelText: 'Cancelar',
        onConfirm: () => toggleRole(username, newRole),
      });
    }

    if (target.closest('[data-action="close-password-modal"]')) closePasswordModal();
    if (target.closest('[data-action="close-delete-modal"]')) closeDeleteModal();
    if (target.closest('#confirm-delete-btn')) confirmDelete();
  });

  // Close modals when clicking outside
  document.querySelectorAll('.mu-modal').forEach((modal) => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        if (modal.id === 'password-modal') closePasswordModal();
        if (modal.id === 'delete-modal') closeDeleteModal();
      }
    });
  });
}
