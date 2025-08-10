<?php

/**
 * Kullanıcı Kayıt Sayfası
 * @author A. Kerem Gök
 */

// Güvenlik headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:');

session_start();
require_once 'functions.php';

// Eğer kullanıcı zaten giriş yapmışsa dashboard'a yönlendir
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // CSRF Token doğrulaması
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Güvenlik hatası! Lütfen tekrar deneyin.';
    } else {
        $username = trim($_POST['username']);
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];

        // Rate limiting check
        $rateLimitResult = checkRateLimit('register', $_SERVER['REMOTE_ADDR'] ?? 'unknown', 3, 600); // 3 attempts per 10 minutes
        if (!$rateLimitResult['allowed']) {
            $error = 'Fazla deneme yapıldı. ' . ceil($rateLimitResult['retry_after'] / 60) . ' dakika sonra tekrar deneyin.';
        }
        // Güçlendirilmiş validasyon
        elseif (empty($username) || empty($password) || empty($confirm_password)) {
            $error = 'Tüm alanları doldurun!';
        } elseif ($password !== $confirm_password) {
            $error = 'Şifreler eşleşmiyor!';
        } else {
            // Username validation
            $usernameValidation = validateUsername($username);
            if (!$usernameValidation['valid']) {
                $error = $usernameValidation['error'];
            } else {
                // Password validation
                $passwordValidation = validatePassword($password);
                if (!$passwordValidation['valid']) {
                    $error = $passwordValidation['error'];
                } elseif (userExists($username)) {
                    $error = 'Bu kullanıcı adı zaten kullanılıyor!';
                    // Kullanıcıyı kaydet
                    if (registerUser($username, $password)) {
                        $success = 'Kayıt başarılı! Giriş yapabilirsiniz.';
                        // Başarılı kayıt sonrası yeni token oluştur
                        refreshCSRFToken();
                    } else {
                        $error = 'Kayıt sırasında hata oluştu!';
                    }
                }
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="tr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kullanıcı Kayıt</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
    <div class="container">
        <div class="form-container">
            <h2>Kullanıcı Kayıt</h2>

            <?php if ($error): ?>
                <div class="alert alert-error">
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success">
                    <?php echo htmlspecialchars($success); ?>
                </div>
            <?php endif; ?>

            <form method="POST">
                <?php echo getCSRFField(); ?>
                <div class="form-group">
                    <label for="username">Kullanıcı Adı:</label>
                    <input type="text" id="username" name="username" value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>" required>
                </div>

                <div class="form-group">
                    <label for="password">Şifre:</label>
                    <input type="password" id="password" name="password" required>
                </div>

                <div class="form-group">
                    <label for="confirm_password">Şifre Tekrar:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>

                <button type="submit" class="btn btn-primary">Kayıt Ol</button>
            </form>

            <div class="form-footer">
                <p>Zaten hesabınız var mı? <a href="index.php">Giriş yapın</a></p>
            </div>
        </div>
    </div>
</body>

</html>