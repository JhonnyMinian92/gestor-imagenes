# Security Image — production image
#
# Serves the app under /security-image/ so it matches
# https://portal-sd.securitydata.net.ec/security-image/ behind the
# organization's existing shared reverse proxy (which terminates TLS and
# forwards plain HTTP to this container — see docker-compose.yml).
FROM php:8.3-apache

# --- System deps + PHP extensions ---
# gd: required by ImageUploader.php (imagecreatefromjpeg/png, imagejpeg/imagepng)
# opcache: production performance
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpng-dev \
        libjpeg62-turbo-dev \
        unzip \
        curl \
    && docker-php-ext-configure gd --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" gd opcache \
    && apt-get purge -y --auto-remove libpng-dev libjpeg62-turbo-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# --- Apache hardening ---
# ServerTokens/ServerSignature can't be set from .htaccess (see .htaccess's
# own comment on this) — must live in the main server config.
RUN { \
        echo 'ServerTokens Prod'; \
        echo 'ServerSignature Off'; \
    } >> /etc/apache2/apache2.conf \
    # AllowOverride so this project's own .htaccess files (Require all
    # denied on sensitive dirs, Options -Indexes) actually take effect.
    && sed -ri 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf \
    && a2enmod headers rewrite

# --- PHP hardening + limits for production ---
# upload_max_filesize/post_max_size must cover MAX_FILE_SIZE (10MB, see
# config.php) plus multipart overhead, or valid uploads get silently
# truncated/rejected by PHP before the app's own validation ever runs.
RUN { \
        echo 'expose_php = Off'; \
        echo 'display_errors = Off'; \
        echo 'display_startup_errors = Off'; \
        echo 'log_errors = On'; \
        echo 'upload_max_filesize = 12M'; \
        echo 'post_max_size = 13M'; \
        echo 'opcache.enable = 1'; \
        echo 'opcache.validate_timestamps = 0'; \
    } > /usr/local/etc/php/conf.d/99-security-image.ini

WORKDIR /var/www/html/security-image

# Install dependencies first so this layer is cached unless composer.* change.
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader

COPY . .

# Never ship the load-testing script (its own header comment says as much).
RUN rm -f test_ratelimit.php \
    && chown -R www-data:www-data /var/www/html/security-image

# Pre-create APP_DATA_DIR's mount point owned by www-data *before* the
# named volume is attached: on first `docker compose up`, Docker seeds a
# fresh named volume from whatever already exists at its mount path in the
# image, ownership included. Without this, the volume would start out
# root-owned and every mkdir/fopen the app does under DATA_DIR (users.json,
# sessions/, images/, security.log, ...) would fail with a permission error.
RUN mkdir -p /var/lib/security-image-data \
    && chown -R www-data:www-data /var/lib/security-image-data

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -fsS http://localhost/security-image/login.php -o /dev/null || exit 1
