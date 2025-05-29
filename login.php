<?php
/**
 * Kullanıcı Giriş İşlemi
 * @author A. Kerem Gök
 */

session_start();
require_once 'functions.php';

if ($_SERVER['REQUEST_METHOD'] != 'POST') {
    header('Location: index.php');
    exit;
}

$username = trim($_POST['username']);
$password = $_POST['password'];

if (empty($username) || empty($password)) {
    header('Location: index.php?error=' . urlencode('Kullanıcı adı ve şifre gerekli!'));
    exit;
}

$user = loginUser($username, $password);

if ($user) {
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    header('Location: dashboard.php');
} else {
    header('Location: index.php?error=' . urlencode('Kullanıcı adı veya şifre hatalı!'));
}
exit;
?> 