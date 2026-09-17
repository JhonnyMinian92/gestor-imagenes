<?php

namespace App;

/**
 * Manages image metadata stored in a JSON file.
 * H11 Remediation.
 */
class ImageMetadata
{
  private static function load(): array
  {
    if (!file_exists(IMAGE_METADATA_FILE)) {
      return [];
    }
    $raw = file_get_contents(IMAGE_METADATA_FILE);
    return $raw ? (json_decode($raw, true) ?? []) : [];
  }

  public static function add(string $filename, string $owner, int $size, ?int $expires_at): void
  {
    \withJsonFileLock(IMAGE_METADATA_FILE, function (array $metadata) use ($filename, $owner, $size, $expires_at) {
      $metadata[$filename] = [
        'owner'      => $owner,
        'created_at' => time(),
        'expires_at' => $expires_at,
        'size'       => $size,
      ];
      return [$metadata, null];
    });
  }

  /**
   * Atomically checks the owner's current quota usage and inserts the new
   * entry within the same file lock, so two concurrent uploads can never both
   * "pass" a quota check that only one of them should have passed (M9).
   *
   * @return array{ok: bool, reason?: 'files'|'size'}
   */
  public static function tryAdd(
    string $filename,
    string $owner,
    int $size,
    ?int $expires_at,
    int $maxFiles,
    int $maxBytes
  ): array {
    return \withJsonFileLock(IMAGE_METADATA_FILE, function (array $metadata) use ($filename, $owner, $size, $expires_at, $maxFiles, $maxBytes) {
      $count = 0;
      $totalSize = 0;
      foreach ($metadata as $image) {
        if (($image['owner'] ?? null) === $owner) {
          $count++;
          $totalSize += $image['size'] ?? 0;
        }
      }

      if ($count >= $maxFiles) {
        return [null, ['ok' => false, 'reason' => 'files']];
      }
      if (($totalSize + $size) > $maxBytes) {
        return [null, ['ok' => false, 'reason' => 'size']];
      }

      $metadata[$filename] = [
        'owner'      => $owner,
        'created_at' => time(),
        'expires_at' => $expires_at,
        'size'       => $size,
      ];
      return [$metadata, ['ok' => true]];
    });
  }

  public static function remove(string $filename): bool
  {
    return \withJsonFileLock(IMAGE_METADATA_FILE, function (array $metadata) use ($filename) {
      if (!isset($metadata[$filename])) {
        return [null, false];
      }
      unset($metadata[$filename]);
      return [$metadata, true];
    });
  }

  public static function get(string $filename): ?array
  {
    $metadata = self::load();
    return $metadata[$filename] ?? null;
  }

  public static function getUserUsage(string $owner): array
  {
    $metadata = self::load();
    $usage = ['count' => 0, 'size' => 0];

    foreach ($metadata as $image) {
      if (isset($image['owner']) && $image['owner'] === $owner) {
        $usage['count']++;
        $usage['size'] += $image['size'] ?? 0;
      }
    }
    return $usage;
  }

  public static function getNonExpiredForUser(string $owner): array
  {
    $metadata = self::load();
    $currentTime = time();

    $userImages = array_filter($metadata, function ($image) use ($currentTime, $owner) {
      return isset($image['owner'])
        && $image['owner'] === $owner
        && (is_null($image['expires_at']) || $image['expires_at'] > $currentTime);
    });

    foreach ($userImages as $filename => &$data) {
      $data['filename'] = $filename;
    }

    uasort($userImages, fn($a, $b) => $b['created_at'] - $a['created_at']);

    return array_values($userImages);
  }
}
