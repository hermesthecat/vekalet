<?php

/**
 * Kullanıcı Çıkış İşlemi
 * @author A. Kerem Gök
 */

session_start();

// Session verilerini temizle
$_SESSION = array();

// Session cookie'sini sil
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Session'u yok et
session_destroy();

// Yeni session başlat (güvenlik için)
session_start();
session_regenerate_id(true);

header('Location: index.php?success=' . urlencode('Başarıyla çıkış yaptınız!'));
exit;
