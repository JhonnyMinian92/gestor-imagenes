<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';

startSecureSession();
doLogout();
header('Location: login.php');
exit;
