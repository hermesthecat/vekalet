<?php

/**
 * Kullanıcı Çıkış İşlemi
 * @author A. Kerem Gök
 */

session_start();
session_destroy();
header('Location: index.php?success=' . urlencode('Başarıyla çıkış yaptınız!'));
exit;
