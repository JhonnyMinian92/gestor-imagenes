<?php

namespace App;

/**
 * Custom exception for upload errors, carrying an HTTP status code.
 */
class UploadException extends \Exception
{
  public function __construct(string $message, int $code = 400, \Throwable $previous = null)
  {
    parent::__construct($message, $code, $previous);
  }
}

/**
 * Handles image validation, processing, and storage.
 */
class ImageUploader
{
  private const UPLOAD_ERRORS = [
    UPLOAD_ERR_INI_SIZE   => 'El archivo supera el límite de tamaño del servidor.',
    UPLOAD_ERR_FORM_SIZE  => 'El archivo supera el límite de tamaño del formulario.',
    UPLOAD_ERR_PARTIAL    => 'El archivo se subió solo parcialmente.',
    UPLOAD_ERR_NO_FILE    => 'No se recibió ningún archivo.',
    UPLOAD_ERR_NO_TMP_DIR => 'Error de configuración del servidor (sin directorio temporal).',
    UPLOAD_ERR_CANT_WRITE => 'El servidor no puede escribir el archivo.',
    UPLOAD_ERR_EXTENSION  => 'Subida bloqueada por una extensión del servidor.',
  ];

  private array $file;
  private string $extension;
  private string $mimeType;
  private array $imageInfo;
  private string $owner;
  private ?int $requestedExpirationSeconds = null;

  public function __construct(array $uploadedFile)
  {
    if (!isset($uploadedFile['error']) || is_array($uploadedFile['error'])) {
      // Handle cases of multiple file uploads or invalid $_FILES structure
      throw new UploadException('Parámetros de subida inválidos.');
    }

    if ($uploadedFile['error'] === UPLOAD_ERR_NO_FILE) {
      throw new UploadException('No se recibió ningún archivo.');
    }
    $this->file = $uploadedFile;
  }


  // H11 remediation: optional caller-requested expiration, validated here
  // against ALLOWED_LINK_EXPIRATIONS regardless of what upload.php already
  // checked — this class never trusts an unvalidated value from a caller.
  public function processUpload(string $owner, ?int $requestedExpirationSeconds = null): array
  {
    $this->owner = $owner;
    if ($requestedExpirationSeconds !== null && in_array($requestedExpirationSeconds, ALLOWED_LINK_EXPIRATIONS, true)) {
      $this->requestedExpirationSeconds = $requestedExpirationSeconds;
    }
    $this->validate();
    return $this->save();
  }

  private function validate(): void
  {
    if ($this->file['error'] !== UPLOAD_ERR_OK) {
      $message = self::UPLOAD_ERRORS[$this->file['error']] ?? 'Error desconocido al subir el archivo.';
      throw new UploadException($message);
    }

    if ($this->file['size'] === 0) {
      throw new UploadException('El archivo está vacío.');
    }

    if ($this->file['size'] > MAX_FILE_SIZE) {
      $mb = MAX_FILE_SIZE / (1024 * 1024);
      throw new UploadException("El archivo supera el tamaño máximo de {$mb} MB.");
    }

    // Security: Ensure the file is a genuine upload before processing it.
    if (!is_uploaded_file($this->file['tmp_name'])) {
      throw new UploadException('El archivo no es una subida válida.', 400);
    }

    // Use finfo to get the MIME type from file content, which is more reliable than the client-provided one.
    $finfo = new \finfo(FILEINFO_MIME_TYPE);
    $this->mimeType = $finfo->file($this->file['tmp_name']);

    if (!in_array($this->mimeType, ALLOWED_MIME_TYPES, true)) {
      throw new UploadException('Contenido de archivo inválido. Solo se aceptan imágenes JPEG y PNG.');
    }

    // Derive the extension from the trusted MIME type, not the user-provided filename.
    $extMap = ['image/jpeg' => 'jpg', 'image/png' => 'png'];
    $this->extension = $extMap[$this->mimeType];

    // Use getimagesize to verify it's a real image and get dimensions.
    // The @ suppresses warnings for corrupt images, which we handle by checking the return value.
    $this->imageInfo = @getimagesize($this->file['tmp_name']);
    if ($this->imageInfo === false) { // getimagesize returns false for non-image files or corrupt images
      throw new UploadException('El archivo no parece ser una imagen válida o está corrupto.');
    }

    // Cross-verify that the MIME type from getimagesize matches what finfo found.
    if ($this->imageInfo['mime'] !== $this->mimeType) {
      throw new UploadException('El tipo de imagen no coincide con su contenido.');
    }

    // --- H12: Image Dimension Validation ---
    $width = $this->imageInfo[0];
    $height = $this->imageInfo[1];

    if ($width <= 0 || $height <= 0) {
      throw new UploadException('La imagen tiene dimensiones inválidas.');
    }

    if (defined('MAX_IMAGE_WIDTH') && $width > MAX_IMAGE_WIDTH) {
      throw new UploadException('La imagen es demasiado ancha. Ancho máximo: ' . MAX_IMAGE_WIDTH . 'px.');
    }

    if (defined('MAX_IMAGE_HEIGHT') && $height > MAX_IMAGE_HEIGHT) {
      throw new UploadException('La imagen es demasiado alta. Alto máximo: ' . MAX_IMAGE_HEIGHT . 'px.');
    }

    $pixels = (float)$width * $height;
    if (defined('MAX_IMAGE_PIXELS') && $pixels > MAX_IMAGE_PIXELS) {
      throw new UploadException('La imagen tiene demasiados píxeles (es demasiado grande).');
    }

    // --- M8 remediation: refuse to decode images we can't safely fit in memory. ---
    $this->ensureSufficientMemory($width, $height);
  }

  /**
   * GD needs roughly 4 bytes/pixel for the decoded truecolor buffer, plus
   * decoding overhead. Reject early (before the expensive decode call) if the
   * estimate doesn't comfortably fit within the PHP memory_limit, so a handful
   * of concurrent near-the-limit uploads can't exhaust worker memory (M8).
   */
  private function ensureSufficientMemory(int $width, int $height): void
  {
    $memoryLimit = ini_get('memory_limit');
    if ($memoryLimit === false || $memoryLimit === '' || $memoryLimit === '-1') {
      return; // Unlimited or unknown; nothing to guard against here.
    }

    $limitBytes = self::parseMemoryLimit($memoryLimit);
    if ($limitBytes <= 0) {
      return;
    }

    $estimatedBytes = $width * $height * 4 * 1.5; // decode buffer + safety margin
    $available = $limitBytes - memory_get_usage(true);

    if ($estimatedBytes > $available) {
      throw new UploadException('La imagen requiere más memoria de la disponible en el servidor para procesarse de forma segura.', 413);
    }
  }

  private static function parseMemoryLimit(string $value): int
  {
    $value = trim($value);
    if ($value === '') return 0;

    $unit = strtolower(substr($value, -1));
    $number = (float) $value;

    switch ($unit) {
      case 'g':
        return (int) ($number * 1024 * 1024 * 1024);
      case 'm':
        return (int) ($number * 1024 * 1024);
      case 'k':
        return (int) ($number * 1024);
      default:
        return (int) $number;
    }
  }

  private function save(): array
  {
    if (!is_dir(IMAGES_DIR)) {
      // 0750, not 0755: matches ensureImagesDir() in config.php, which normally
      // creates this directory (with its deny-all .htaccess) before any upload
      // runs. This fallback only fires if IMAGES_DIR was removed externally
      // after that — it must not silently recreate it world-readable.
      if (!mkdir(IMAGES_DIR, 0750, true)) {
        throw new UploadException('No se pudo crear el directorio de imágenes.', 500);
      }
    }

    // --- Security Hardening: Sanitize image by re-processing ---
    // This is the most effective way to prevent attacks that hide malicious code
    // inside a seemingly valid image file (e.g., polyglot images).
    // It also strips potentially sensitive EXIF data.
    if (!extension_loaded('gd')) {
      error_log('CRITICAL SECURITY REQUIREMENT: The GD extension is not loaded. Image uploads are disabled.');
      throw new UploadException('La configuración del servidor no permite procesar imágenes de forma segura.', 500);
    }

    $uniqueName = bin2hex(random_bytes(16)) . '.' . $this->extension;
    $destination = IMAGES_DIR . $uniqueName;

    $imageResource = null;
    if ($this->mimeType === 'image/jpeg') {
      $imageResource = @imagecreatefromjpeg($this->file['tmp_name']);
    } elseif ($this->mimeType === 'image/png') {
      $imageResource = @imagecreatefrompng($this->file['tmp_name']);
    }

    if ($imageResource === false) {
      throw new UploadException('No se pudo procesar el archivo de imagen (podría estar corrupto).', 400);
    }

    // For PNGs, preserve transparency
    if ($this->mimeType === 'image/png') {
      imagealphablending($imageResource, false);
      imagesavealpha($imageResource, true);
    }

    $success = false;
    if ($this->mimeType === 'image/jpeg') {
      $success = imagejpeg($imageResource, $destination, 85); // Quality 85
    } elseif ($this->mimeType === 'image/png') {
      $success = imagepng($imageResource, $destination, 6); // Compression level 6
    }

    imagedestroy($imageResource);

    if (!$success) {
      throw new UploadException('No se pudo guardar la imagen procesada en el servidor.', 500);
    }

    // Set the file to read-only as a security hardening measure.
    chmod($destination, 0444);

    $newFileSize = filesize($destination);

    // --- H11: Save image metadata with expiration ---
    $effectiveExpirationSeconds = $this->requestedExpirationSeconds
      ?? (defined('DEFAULT_IMAGE_EXPIRATION_SECONDS') ? DEFAULT_IMAGE_EXPIRATION_SECONDS : null);
    $expires_at = $effectiveExpirationSeconds > 0 ? time() + $effectiveExpirationSeconds : null;

    // --- M9 remediation: atomic quota check + metadata write. ---
    // The physical file was already written optimistically above; if the
    // atomic check below determines the owner is actually over quota (which
    // can only be known for certain inside the lock), roll back by deleting it.
    if (defined('QUOTAS_ENABLED') && QUOTAS_ENABLED) {
      $result = ImageMetadata::tryAdd(
        $uniqueName,
        $this->owner,
        $newFileSize,
        $expires_at,
        MAX_FILES_PER_USER,
        MAX_STORAGE_BYTES_PER_USER
      );

      if (!$result['ok']) {
        @chmod($destination, 0644);
        @unlink($destination);
        $msg = $result['reason'] === 'files'
          ? 'Has alcanzado el límite de archivos. Elimina imágenes para liberar espacio.'
          : 'No tienes suficiente espacio de almacenamiento para esta imagen.';
        throw new UploadException($msg, 507);
      }
    } else {
      ImageMetadata::add($uniqueName, $this->owner, $newFileSize, $expires_at);
    }

    return [
      'success'   => true,
      'filename'  => $uniqueName,
      'url'       => getImagesBaseUrl() . $uniqueName,
      'size'      => $newFileSize,
      'mime'      => $this->mimeType,
      'width'     => $this->imageInfo[0],
      'height'    => $this->imageInfo[1],
    ];
  }
}
