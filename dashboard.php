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

$error = '';
$success = '';

// Yetki devri işlemi
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] == 'delegate') {
        $toUsername = trim($_POST['to_username']);
        $expiryDate = $_POST['expiry_date'];
        $description = trim($_POST['description']);
        
        if (empty($toUsername) || empty($expiryDate)) {
            $error = 'Tüm gerekli alanları doldurun!';
        } elseif ($toUsername === $_SESSION['username']) {
            $error = 'Kendinize yetki devredemezsiniz!';
        } elseif (strtotime($expiryDate) <= strtotime(date('Y-m-d'))) {
            $error = 'Bitiş tarihi bugünden sonra olmalı!';
        } elseif (!getUserByUsername($toUsername)) {
            $error = 'Belirtilen kullanıcı bulunamadı!';
        } else {
            if (delegateAuthority($_SESSION['user_id'], $toUsername, $expiryDate, $description)) {
                $success = 'Yetki başarıyla devredildi!';
                $myDelegations = getUserDelegations($_SESSION['user_id']); // Listeyi güncelle
            } else {
                $error = 'Yetki devri sırasında hata oluştu!';
            }
        }
    } elseif ($_POST['action'] == 'revoke') {
        $delegationId = $_POST['delegation_id'];
        if (revokeDelegation($delegationId, $_SESSION['user_id'])) {
            $success = 'Yetki devri iptal edildi!';
            $myDelegations = getUserDelegations($_SESSION['user_id']); // Listeyi güncelle
        } else {
            $error = 'Yetki devri iptal edilemedi!';
        }
    }
}
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
            <!-- Yetki Devri Formu -->
            <div class="card">
                <h3>Yetki Devret</h3>
                <form method="POST">
                    <input type="hidden" name="action" value="delegate">
                    
                    <div class="form-group">
                        <label for="to_username">Yetki Devredilecek Kullanıcı:</label>
                        <select id="to_username" name="to_username" required>
                            <option value="">Kullanıcı Seçin</option>
                            <?php foreach ($allUsers as $user): ?>
                                <?php if ($user['username'] !== $_SESSION['username']): ?>
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
                <h3>Verdiğim Yetkiler</h3>
                <?php if (empty($myDelegations)): ?>
                    <p class="no-data">Henüz yetki devretmediniz.</p>
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
                            <?php foreach ($myDelegations as $delegation): ?>
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
                                <tr>
                                    <td><?php echo htmlspecialchars($delegation['from_username']); ?></td>
                                    <td><?php echo formatDate($delegation['expiry_date']); ?></td>
                                    <td><?php echo htmlspecialchars($delegation['description'] ?: '-'); ?></td>
                                    <td><?php echo formatDateTime($delegation['created_at']); ?></td>
                                    <td>
                                        <span class="status status-active">Aktif</span>
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