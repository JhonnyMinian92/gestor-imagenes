<?php

// Third-party dependencies (currently: phpseclib/phpseclib, used by Crypto.php
// for the login RSA keypair). Installed via composer.json at the project root.
$vendorAutoload = __DIR__ . '/vendor/autoload.php';
if (file_exists($vendorAutoload)) require_once $vendorAutoload;

/**
 * Simple autoloader for the 'App' namespace.
 */
spl_autoload_register(function ($className) {
  // Project-specific namespace prefix
  $prefix = 'App\\';
  // Base directory for the namespace prefix
  $baseDir = __DIR__ . '/';

  // Does the class use the namespace prefix?
  if (strncmp($prefix, $className, strlen($prefix)) !== 0) return; // No, move to the next autoloader

  // Get the relative class name
  $relativeClass = substr($className, strlen($prefix));

  // Replace namespace separators with directory separators in the relative class name,
  // append .php
  $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

  // If the file exists, require it
  if (file_exists($file)) require $file;
});
