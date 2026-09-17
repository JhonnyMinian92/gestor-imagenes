<?php

namespace App;

/**
 * Minimal TOTP (RFC 6238) implementation, compatible with standard
 * authenticator apps (Google Authenticator, Authy, etc.): SHA-1, 6 digits,
 * 30-second step. No external dependency — just hash_hmac(), which PHP
 * ships with by default.
 */
class Totp
{
  private const SECRET_BYTES = 20; // 160 bits, standard for TOTP
  private const DIGITS = 6;
  private const PERIOD = 30;
  private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  public static function generateSecret(): string
  {
    return self::base32Encode(random_bytes(self::SECRET_BYTES));
  }

  public static function currentCode(string $base32Secret, ?int $timestamp = null): string
  {
    return self::codeForCounter($base32Secret, intdiv($timestamp ?? time(), self::PERIOD));
  }

  /**
   * Verifies a user-submitted code, tolerating clock drift of one step
   * before/after the current one (standard practice for TOTP UX).
   */
  public static function verify(string $base32Secret, string $code, ?int $timestamp = null): bool
  {
    $code = trim($code);
    if (!preg_match('/^\d{6}$/', $code)) {
      return false;
    }

    $now = $timestamp ?? time();
    $counter = intdiv($now, self::PERIOD);

    foreach ([0, -1, 1] as $drift) {
      $expected = self::codeForCounter($base32Secret, $counter + $drift);
      if (hash_equals($expected, $code)) {
        return true;
      }
    }
    return false;
  }

  /**
   * otpauth:// URI for manual entry / QR generation by the user's own tool.
   * No QR image is generated server-side (no external dependency) — the app
   * shows the secret as text so the user can type it into their authenticator.
   */
  public static function otpAuthUri(string $base32Secret, string $accountLabel): string
  {
    $issuer = rawurlencode(TOTP_ISSUER);
    $label = rawurlencode(TOTP_ISSUER . ':' . $accountLabel);
    return "otpauth://totp/{$label}?secret={$base32Secret}&issuer={$issuer}&digits=" . self::DIGITS . "&period=" . self::PERIOD;
  }

  private static function codeForCounter(string $base32Secret, int $counter): string
  {
    $key = self::base32Decode($base32Secret);
    $counterBytes = pack('N*', 0, $counter); // 8-byte big-endian counter

    $hash = hash_hmac('sha1', $counterBytes, $key, true);
    $offset = ord($hash[19]) & 0x0F;

    $binary = (ord($hash[$offset]) & 0x7F) << 24
      | (ord($hash[$offset + 1]) & 0xFF) << 16
      | (ord($hash[$offset + 2]) & 0xFF) << 8
      | (ord($hash[$offset + 3]) & 0xFF);

    $code = $binary % (10 ** self::DIGITS);
    return str_pad((string) $code, self::DIGITS, '0', STR_PAD_LEFT);
  }

  private static function base32Encode(string $binary): string
  {
    $bits = '';
    foreach (str_split($binary) as $byte) {
      $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
    }
    $bits = str_pad($bits, (int) (ceil(strlen($bits) / 5) * 5), '0', STR_PAD_RIGHT);

    $encoded = '';
    foreach (str_split($bits, 5) as $chunk) {
      $encoded .= self::BASE32_ALPHABET[bindec($chunk)];
    }
    return $encoded;
  }

  private static function base32Decode(string $base32): string
  {
    $base32 = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $base32));
    $bits = '';
    foreach (str_split($base32) as $char) {
      $pos = strpos(self::BASE32_ALPHABET, $char);
      if ($pos === false) continue;
      $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }

    $binary = '';
    foreach (str_split($bits, 8) as $byte) {
      if (strlen($byte) < 8) break; // discard padding remainder
      $binary .= chr(bindec($byte));
    }
    return $binary;
  }
}
