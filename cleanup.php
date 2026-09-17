<?php

/**
 * This script is intended to be run from a cron job or scheduled task.
 * It cleans up expired images and stale state files (rate limits, login attempts).
 *
 * Example cron job:
 * 0 3 * * * /usr/bin/php /path/to/your/project/cleanup.php
 */

// Prevent web access for security
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('Access Denied: This script can only be run from the command line.');
}

require_once __DIR__ . '/config.php';

echo "Starting cleanup process at " . date('c') . "...\n";

function cleanupJsonFile(string $filePath, int $maxAgeSeconds, string $logPrefix): void
{
    if (!file_exists($filePath)) {
        echo "{$logPrefix}: File not found. Skipping.\n";
        return;
    }

    $data = json_decode((string) file_get_contents($filePath), true) ?? [];
    if (empty($data)) {
        echo "{$logPrefix}: File is empty. Skipping.\n";
        return;
    }

    $currentTime = time();
    $originalCount = count($data);
    $cleanedData = array_filter($data, function ($entry) use ($currentTime, $maxAgeSeconds) {
        return isset($entry['ts']) && ($currentTime - $entry['ts']) < $maxAgeSeconds;
    });

    $deletedCount = $originalCount - count($cleanedData);
    if ($deletedCount > 0) {
        file_put_contents($filePath, json_encode($cleanedData, JSON_PRETTY_PRINT), LOCK_EX);
        echo "{$logPrefix}: Cleaned up {$deletedCount} stale entries.\n";
    } else {
        echo "{$logPrefix}: No stale entries found.\n";
    }
}

// --- Cleanup of expired images (H11) ---
echo "\n--- Cleaning expired images ---\n";
$metadataFile = IMAGE_METADATA_FILE;
if (file_exists($metadataFile)) {
    $metadata = json_decode((string) file_get_contents($metadataFile), true) ?? [];
    $currentTime = time();
    $deletedCount = 0;

    foreach ($metadata as $filename => $data) {
        if (!empty($data['expires_at']) && $data['expires_at'] < $currentTime) {
            $path = IMAGES_DIR . $filename;
            echo "Expired: {$filename} (Expired on: " . date('c', $data['expires_at']) . "). ";

            if (file_exists($path)) {
                @chmod($path, 0644); // Make writable to delete
                if (unlink($path)) {
                    echo "File deleted. ";
                    $deletedCount++;
                } else {
                    echo "ERROR: Could not delete file at {$path}. ";
                }
            }
            unset($metadata[$filename]); // Remove metadata entry regardless
            echo "\n";
        }
    }

    if ($deletedCount > 0) {
        file_put_contents($metadataFile, json_encode($metadata, JSON_PRETTY_PRINT), LOCK_EX);
        echo "Image cleanup complete. Deleted {$deletedCount} expired images.\n";
    } else {
        echo "No expired images found.\n";
    }
} else {
    echo "Image metadata file not found. Skipping.\n";
}

// --- Cleanup of state files (Low Severity Finding) ---
echo "\n--- Cleaning state files ---\n";
cleanupJsonFile(DATA_DIR . 'attempts.json', LOGIN_LOCKOUT_SECONDS, 'Login Attempts');
$maxRateLimitWindow = max(
    RATE_LIMIT_LOGIN_WINDOW,
    RATE_LIMIT_UPLOAD_WINDOW,
    RATE_LIMIT_API_WINDOW,
    RATE_LIMIT_IMAGE_WINDOW,
    RATE_LIMIT_GLOBAL_WINDOW
);
cleanupJsonFile(RATE_LIMIT_STORAGE_FILE, $maxRateLimitWindow, 'Rate Limiter');

echo "\nCleanup process finished at " . date('c') . ".\n";
exit(0);
