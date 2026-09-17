<?php

namespace App;

/**
 * A simple file-based rate limiter.
 * H7 Remediation.
 */
class RateLimiter
{
  private string $storagePath;

  // B3 remediation: this constant is now actually used (see purgeStale()) —
  // roughly 1 in CLEANUP_CHANCE checks also purges long-stale entries, so the
  // storage file stays bounded even if the cleanup.php cron isn't configured.
  private const CLEANUP_CHANCE = 100;

  // Generous upper bound, well above any configured rate-limit window, used
  // only as a safety net for the probabilistic cleanup above.
  private const MAX_ENTRY_AGE = 86400;

  public function __construct(string $storagePath)
  {
    $this->storagePath = $storagePath;
  }

  /**
   * Checks if a request for a given key is allowed.
   * M4/M9-style remediation: the read-check-increment-write cycle now happens
   * atomically under a single file lock (via withJsonFileLock), closing the
   * race where two concurrent requests could both read the same stale count
   * and both be allowed through past the limit.
   *
   * @return array ['allowed' => bool, 'retryAfter' => int]
   */
  public function check(string $key, int $limit, int $window): array
  {
    return \withJsonFileLock($this->storagePath, function (array $data) use ($key, $limit, $window) {
      $currentTime = time();
      $entry = $data[$key] ?? ['count' => 0, 'ts' => $currentTime];

      // If the time window has passed since the first request in the series, reset the counter.
      if ($currentTime - $entry['ts'] > $window) {
        $entry['count'] = 1;
        $entry['ts'] = $currentTime;
      } else {
        $entry['count']++;
      }

      if ($entry['count'] > $limit) {
        $retryAfter = $entry['ts'] + $window - $currentTime;
        // Leave storage untouched: the persisted count stays at the last
        // allowed value until the window naturally expires.
        return [null, ['allowed' => false, 'retryAfter' => max(1, $retryAfter)]];
      }

      $data[$key] = $entry;

      if (random_int(1, self::CLEANUP_CHANCE) === 1) {
        $data = self::purgeStale($data, $currentTime);
      }

      return [$data, ['allowed' => true, 'retryAfter' => 0]];
    });
  }

  private static function purgeStale(array $data, int $currentTime): array
  {
    return array_filter($data, function ($entry) use ($currentTime) {
      return isset($entry['ts']) && ($currentTime - $entry['ts']) < self::MAX_ENTRY_AGE;
    });
  }
}
