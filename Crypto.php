<?php

namespace App;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

/**
 * RSA + AES-256-GCM hybrid encryption for the login form.
 *
 * The browser generates a fresh random AES-256 key for every submission,
 * uses it to encrypt the username/password, and wraps that one-time AES key
 * with this server's RSA public key (RSA-OAEP/SHA-256). Only the RSA
 * private key — generated here, stored outside the web document root, and
 * never sent to the browser — can unwrap the AES key and recover the
 * credentials.
 *
 * This differs from the old client-side scheme removed in the G1 fix
 * (see auth.php): that one derived its AES key from a secret the server
 * also handed to the browser, so anything that could read the page already
 * had everything needed to decrypt — no confidentiality was actually
 * gained. Here the decryption key is asymmetric and never leaves the
 * server, so only the server can decrypt what the browser encrypts.
 */
class Crypto
{
    private const RSA_KEY_BITS = 2048;

    public static function publicKeyPem(): string
    {
        return self::loadOrCreateKeyPair()['public'];
    }

    /**
     * Decrypts the hybrid payload produced by encryptLoginCredentials() in
     * assets/js/app.js. Returns the decoded {username, password} array, or
     * null if any part fails to decode/decrypt/parse.
     */
    public static function decryptLoginPayload(string $encKeyB64, string $ivB64, string $dataB64): ?array
    {
        $encKey = base64_decode($encKeyB64, true);
        $iv     = base64_decode($ivB64, true);
        $data   = base64_decode($dataB64, true);

        if ($encKey === false || $iv === false || $data === false) {
            return null;
        }
        // AES-GCM IV is 12 bytes; SubtleCrypto appends a 16-byte tag to the
        // ciphertext, so anything shorter than that couldn't be genuine.
        if (strlen($iv) !== 12 || strlen($data) < 17) {
            return null;
        }

        try {
            $privateKey = PublicKeyLoader::loadPrivateKey(self::loadOrCreateKeyPair()['private'])
                ->withPadding(RSA::ENCRYPTION_OAEP)
                ->withHash('sha256')
                ->withMGFHash('sha256');
            $aesKey = $privateKey->decrypt($encKey);
        } catch (\Throwable $e) {
            return null;
        }

        if (strlen($aesKey) !== 32) {
            return null;
        }

        $ciphertext = substr($data, 0, -16);
        $tag        = substr($data, -16);

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $iv, $tag);
        if ($plaintext === false) {
            return null;
        }

        $decoded = json_decode($plaintext, true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Loads the server's RSA keypair from DATA_DIR, generating it once on
     * first use. Stored outside the web document root alongside the other
     * server secrets (session secret, users file — see G3 in config.php).
     */
    private static function loadOrCreateKeyPair(): array
    {
        ensureDataDir();
        $privatePath = DATA_DIR . 'rsa_private.pem';
        $publicPath  = DATA_DIR . 'rsa_public.pem';

        if (is_file($privatePath) && is_file($publicPath)) {
            return [
                'private' => (string) file_get_contents($privatePath),
                'public'  => (string) file_get_contents($publicPath),
            ];
        }

        $privateKey = RSA::createKey(self::RSA_KEY_BITS);
        $publicKey  = $privateKey->getPublicKey();

        $privatePem = (string) $privateKey;
        $publicPem  = (string) $publicKey;

        file_put_contents($privatePath, $privatePem, LOCK_EX);
        @chmod($privatePath, 0600);
        file_put_contents($publicPath, $publicPem, LOCK_EX);
        @chmod($publicPath, 0644);

        return ['private' => $privatePem, 'public' => $publicPem];
    }
}
