<?php
/**
 * Kullanıcı Dashboard
 * @author A. Kerem Gök
 */

session_start();
require_once 'functions.php';

// Giriş kontrolü
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$currentUser = getUserById($_SESSION['user_id']);
$myDelegations = getUserDelegations($_SESSION['user_id']);
$receivedDelegations = getUserReceivedDelegations($_SESSION['user_id']);
$allUsers = getAllUsers();

// Aktif yetki kontrolü - hangi kullanıcı adına işlem yapılıyor
$activeAsUser = $_SESSION['user_id']; // Varsayılan: kendi adına
$activeAsUsername = $_SESSION['username'];

if (isset($_POST['switch_user']) && !empty($_POST['delegate_as'])) {
    $delegateAsId = $_POST['delegate_as'];
    // Bu yetkinin gerçekten bu kullanıcıya ait olup olmadığını kontrol et
    foreach ($receivedDelegations as $delegation) {
        if ($delegation['from_user_id'] === $delegateAsId) {
            $activeAsUser = $delegateAsId;
            $activeAsUsername = $delegation['from_username'];
            $_SESSION['active_as_user'] = $activeAsUser;
            $_SESSION['active_as_username'] = $activeAsUsername;
            break;
        }
    }
} elseif (isset($_POST['switch_to_self'])) {
    $activeAsUser = $_SESSION['user_id'];
    $activeAsUsername = $_SESSION['username'];
    unset($_SESSION['active_as_user']);
    unset($_SESSION['active_as_username']);
}

// Session'dan aktif kullanıcıyı al
if (isset($_SESSION['active_as_user'])) {
    $activeAsUser = $_SESSION['active_as_user'];
    $activeAsUsername = $_SESSION['active_as_username'];
}

$error = '';
$success = '';

// Yetki devri işlemi - aktif kullanıcı adına
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] == 'delegate') {
        $toUsername = trim($_POST['to_username']);
        $expiryDate = $_POST['expiry_date'];
        $description = trim($_POST['description']);
        
        if (empty($toUsername) || empty($expiryDate)) {
            $error = 'Tüm gerekli alanları doldurun!';
        } elseif ($toUsername === $activeAsUsername) {
            $error = 'Aynı kullanıcıya yetki devredemezsiniz!';
        } elseif (strtotime($expiryDate) <= strtotime(date('Y-m-d'))) {
            $error = 'Bitiş tarihi bugünden sonra olmalı!';
        } elseif (!getUserByUsername($toUsername)) {
            $error = 'Belirtilen kullanıcı bulunamadı!';
        } else {
            $result = delegateAuthority($activeAsUser, $toUsername, $expiryDate, $description);
            if (is_array($result) && isset($result['error'])) {
                // Hata durumu
                $error = $result['error'];
            } elseif ($result) {
                // Başarılı
                $success = ($activeAsUser !== $_SESSION['user_id'] ? $activeAsUsername . ' adına ' : '') . 'Yetki başarıyla devredildi!';
                $myDelegations = getUserDelegations($_SESSION['user_id']); // Listeyi güncelle
            } else {
                $error = 'Yetki devri sırasında hata oluştu!';
            }
        }
    } elseif ($_POST['action'] == 'revoke') {
        $delegationId = $_POST['delegation_id'];
        if (revokeDelegation($delegationId, $activeAsUser)) {
            $success = 'Yetki devri iptal edildi!';
            $myDelegations = getUserDelegations($_SESSION['user_id']); // Listeyi güncelle
        } else {
            $error = 'Yetki devri iptal edilemedi!';
        }
    }
}

// Aktif kullanıcının delegasyonlarını al
$activeDelegations = getUserDelegations($activeAsUser);
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Yetki Sistemi</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Hoş Geldiniz, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
            <a href="logout.php" class="btn btn-secondary">Çıkış Yap</a>
        </div>
        
        <?php if ($activeAsUser !== $_SESSION['user_id']): ?>
            <div class="alert alert-info">
                <strong>Dikkat:</strong> Şu anda <strong><?php echo htmlspecialchars($activeAsUsername); ?></strong> adına işlem yapıyorsunuz.
                <form method="POST" style="display:inline; margin-left: 10px;">
                    <input type="hidden" name="switch_to_self" value="1">
                    <button type="submit" class="btn btn-small" style="background: white; color: #333; padding: 5px 10px;">
                        Kendi Adıma Dön
                    </button>
                </form>
            </div>
        <?php endif; ?>
        
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
        
        <div class="dashboard-container">
            <!-- Yetki Kullanımı -->
            <?php if (!empty($receivedDelegations)): ?>
            <div class="card">
                <h3>Yetki Kullanımı</h3>
                <p>Size devredilen yetkilerle başka kullanıcı adına işlem yapabilirsiniz:</p>
                <form method="POST">
                    <div class="form-group">
                        <label for="delegate_as">Hangi Kullanıcı Adına İşlem Yapmak İstiyorsunuz:</label>
                        <select id="delegate_as" name="delegate_as" required>
                            <option value="">Kullanıcı Seçin</option>
                            <?php foreach ($receivedDelegations as $delegation): ?>
                                <option value="<?php echo $delegation['from_user_id']; ?>" 
                                    <?php echo ($activeAsUser === $delegation['from_user_id']) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($delegation['from_username']); ?>
                                    (<?php echo formatDate($delegation['expiry_date']); ?> tarihine kadar)
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <button type="submit" name="switch_user" class="btn btn-primary">Bu Kullanıcı Adına Geç</button>
                </form>
            </div>
            <?php endif; ?>
            
            <!-- Yetki Devri Formu -->
            <div class="card">
                <h3>Yetki Devret 
                    <?php if ($activeAsUser !== $_SESSION['user_id']): ?>
                        <span style="color: #667eea; font-size: 14px;">(<?php echo htmlspecialchars($activeAsUsername); ?> adına)</span>
                    <?php endif; ?>
                </h3>
                <form method="POST">
                    <input type="hidden" name="action" value="delegate">
                    
                    <div class="form-group">
                        <label for="to_username">Yetki Devredilecek Kullanıcı:</label>
                        <select id="to_username" name="to_username" required>
                            <option value="">Kullanıcı Seçin</option>
                            <?php foreach ($allUsers as $user): ?>
                                <?php if ($user['username'] !== $activeAsUsername): ?>
                                    <option value="<?php echo htmlspecialchars($user['username']); ?>">
                                        <?php echo htmlspecialchars($user['username']); ?>
                                    </option>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="expiry_date">Bitiş Tarihi:</label>
                        <input type="date" id="expiry_date" name="expiry_date" min="<?php echo date('Y-m-d', strtotime('+1 day')); ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="description">Açıklama (Opsiyonel):</label>
                        <textarea id="description" name="description" rows="3" placeholder="Yetki devri hakkında kısa açıklama..."></textarea>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Yetki Devret</button>
                </form>
            </div>
            
            <!-- Verdiğim Yetkiler -->
            <div class="card">
                <h3>Verdiğim Yetkiler 
                    <?php if ($activeAsUser !== $_SESSION['user_id']): ?>
                        <span style="color: #667eea; font-size: 14px;">(<?php echo htmlspecialchars($activeAsUsername); ?> adına)</span>
                    <?php endif; ?>
                </h3>
                <?php if (empty($activeDelegations)): ?>
                    <p class="no-data">Henüz yetki devredilmemiş.</p>
                <?php else: ?>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Kullanıcı</th>
                                <th>Bitiş Tarihi</th>
                                <th>Açıklama</th>
                                <th>Oluşturulma</th>
                                <th>İşlem</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($activeDelegations as $delegation): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($delegation['to_username']); ?></td>
                                    <td><?php echo formatDate($delegation['expiry_date']); ?></td>
                                    <td><?php echo htmlspecialchars($delegation['description'] ?: '-'); ?></td>
                                    <td><?php echo formatDateTime($delegation['created_at']); ?></td>
                                    <td>
                                        <form method="POST" style="display:inline;">
                                            <input type="hidden" name="action" value="revoke">
                                            <input type="hidden" name="delegation_id" value="<?php echo $delegation['id']; ?>">
                                            <button type="submit" class="btn btn-danger btn-small" 
                                                onclick="return confirm('Bu yetki devrini iptal etmek istediğinizden emin misiniz?')">
                                                İptal Et
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
            
            <!-- Aldığım Yetkiler -->
            <div class="card">
                <h3>Aldığım Yetkiler</h3>
                <?php if (empty($receivedDelegations)): ?>
                    <p class="no-data">Size devredilen aktif yetki bulunmuyor.</p>
                <?php else: ?>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Yetkiyi Veren</th>
                                <th>Bitiş Tarihi</th>
                                <th>Açıklama</th>
                                <th>Oluşturulma</th>
                                <th>Durum</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($receivedDelegations as $delegation): ?>
                                <tr <?php echo ($activeAsUser === $delegation['from_user_id']) ? 'style="background: #e3f2fd;"' : ''; ?>>
                                    <td>
                                        <?php echo htmlspecialchars($delegation['from_username']); ?>
                                        <?php if ($activeAsUser === $delegation['from_user_id']): ?>
                                            <span class="status status-active" style="margin-left: 10px; font-size: 10px;">AKTİF</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?php echo formatDate($delegation['expiry_date']); ?></td>
                                    <td><?php echo htmlspecialchars($delegation['description'] ?: '-'); ?></td>
                                    <td><?php echo formatDateTime($delegation['created_at']); ?></td>
                                    <td>
                                        <span class="status status-active">Geçerli</span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html> 