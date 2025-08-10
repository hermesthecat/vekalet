<?php

/**
 * Kullanıcı Giriş İşlemi
 * @author A. Kerem Gök
 */

// Güvenlik headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

session_start();
require_once 'functions.php';

if ($_SERVER['REQUEST_METHOD'] != 'POST') {
    header('Location: index.php');
    exit;
}

// CSRF Token doğrulaması
if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
    header('Location: index.php?error=' . urlencode('Güvenlik hatası! Lütfen tekrar deneyin.'));
    exit;
}

$username = trim($_POST['username']);
$password = $_POST['password'];

// Rate limiting check
$rateLimitResult = checkRateLimit('login', $_SERVER['REMOTE_ADDR'] ?? 'unknown', 5, 900); // 5 attempts per 15 minutes
if (!$rateLimitResult['allowed']) {
    logSecurityEvent('LOGIN_RATE_LIMITED', [
        'username' => $username,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ], 'WARNING');
    header('Location: index.php?error=' . urlencode('Fazla deneme yapıldı. ' . ceil($rateLimitResult['retry_after'] / 60) . ' dakika sonra tekrar deneyin.'));
    exit;
}

if (empty($username) || empty($password)) {
    header('Location: index.php?error=' . urlencode('Kullanıcı adı ve şifre gerekli!'));
    exit;
}

$user = loginUser($username, $password);

if ($user) {
    // Check if user is active
    if (isset($user['status']) && $user['status'] !== 'active') {
        logSecurityEvent('LOGIN_INACTIVE_USER', ['username' => $username], 'WARNING');
        header('Location: index.php?error=' . urlencode('Hesabınız deaktif durumda!'));
        exit;
    }

    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['user_role'] = $user['role_id'] ?? null;

    // Güvenli session başlat
    initializeSecureSession($user['id']);

    // Giriş sonrası yeni CSRF token oluştur
    refreshCSRFToken();

    logSecurityEvent('LOGIN_SUCCESS', ['username' => $username]);
    header('Location: dashboard.php');
} else {
    logSecurityEvent('LOGIN_FAILED', [
        'username' => $username,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ], 'WARNING');
    header('Location: index.php?error=' . urlencode('Kullanıcı adı veya şifre hatalı!'));
}
exit;
