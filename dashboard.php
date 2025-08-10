<?php

/**
 * Kullanıcı Dashboard
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

// Giriş kontrolü ve session güvenliği
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

// Session hijacking korunması
if (!validateSessionSignature($_SESSION['user_id'])) {
    // Geçersiz session, çıkış yap
    session_destroy();
    header('Location: index.php?error=' . urlencode('Güvenlik nedeniyle oturumunuz sonlandırıldı.'));
    exit;
}

$currentUser = getUserById($_SESSION['user_id']);
$myDelegations = getUserDelegations($_SESSION['user_id']);
$receivedDelegations = getUserReceivedDelegations($_SESSION['user_id']);
$allUsers = getAllUsers();

// PERFORMANS: Bulk loading ile N+1 sorunu çözümü
$allPermissionsMap = loadAllPermissionsMap();
$allUsersMap = loadAllUsersMap();

// Delegasyonlarda kullanılacak user ID'leri topla
$userIdsToResolve = [];
foreach ($myDelegations as $delegation) {
    $userIdsToResolve[] = $delegation['to_user_id'];
}
foreach ($receivedDelegations as $delegation) {
    $userIdsToResolve[] = $delegation['from_user_id'];
}
$userIdsToResolve = array_unique($userIdsToResolve);

// Bulk user name resolution
$resolvedUserNames = resolveUserNames($userIdsToResolve);

// Performans için received delegations lookup map oluştur + username optimize
$receivedDelegationsMap = [];
foreach ($receivedDelegations as &$delegation) {
    // Bulk resolved username kullan
    if (isset($resolvedUserNames[$delegation['from_user_id']])) {
        $delegation['from_username'] = $resolvedUserNames[$delegation['from_user_id']];
    }
    $receivedDelegationsMap[$delegation['from_user_id']] = $delegation;
}

// MyDelegations için de aynısını yap
foreach ($myDelegations as &$delegation) {
    if (isset($resolvedUserNames[$delegation['to_user_id']])) {
        $delegation['to_username'] = $resolvedUserNames[$delegation['to_user_id']];
    }
}

// Sistem sağlık kontrolü (periyodik)
if (rand(1, 100) === 1) { // %1 şans ile çalıştır
    systemHeartbeat();
}

// Kullanıcının mevcut yetkilerini al
$userPermissions = getUserPermissions($_SESSION['user_id']);
$availablePermissions = getAllPermissions();

$error = '';
$success = '';

// ÖNCE Yetki değiştirme işlemi - CSRF korumalı
if ($_SERVER['REQUEST_METHOD'] == 'POST' && (isset($_POST['switch_user']) || isset($_POST['switch_to_self']))) {
    // CSRF Token doğrulaması
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Güvenlik hatası! Lütfen sayfayı yenileyin ve tekrar deneyin.';
    } else {
        if (isset($_POST['switch_user']) && !empty($_POST['delegate_as'])) {
            $delegateAsId = $_POST['delegate_as'];

            // ID formatı doğrulaması
            if (!preg_match('/^[a-zA-Z0-9]+$/', $delegateAsId)) {
                $error = 'Geçersiz kullanıcı ID formatı!';
            } else {
                // Bu yetkinin gerçekten bu kullanıcıya ait olup olmadığını kontrol et (optimized)
                $validDelegation = false;
                if (isset($receivedDelegationsMap[$delegateAsId])) {
                    $delegation = $receivedDelegationsMap[$delegateAsId];
                    // Delegasyonun hala aktif olup olmadığını kontrol et
                    $expiryTime = strtotime($delegation['expiry_date'] . ' 23:59:59 UTC');
                    if ($expiryTime >= time()) {
                        $_SESSION['active_as_user'] = $delegateAsId;
                        $_SESSION['active_as_username'] = $delegation['from_username'];
                        refreshCSRFToken(); // Yetki değişimi sonrası yeni token
                        $validDelegation = true;
                    } else {
                        $error = 'Bu yetki delegasyonunun süresi dolmuş!';
                    }
                }
                if (!$validDelegation && !$error) {
                    $error = 'Geçersiz yetki delegasyonu!';
                }
            }
        } elseif (isset($_POST['switch_to_self'])) {
            unset($_SESSION['active_as_user']);
            unset($_SESSION['active_as_username']);
            refreshCSRFToken(); // Yetki değişimi sonrası yeni token
        }
    }
}

// Aktif yetki kontrolü - hangi kullanıcı adına işlem yapılıyor
$activeAsUser = $_SESSION['user_id']; // Varsayılan: kendi adına
$activeAsUsername = $_SESSION['username'];

// Session'dan aktif kullanıcıyı al ve validate et
if (isset($_SESSION['active_as_user'])) {
    $activeAsUser = $_SESSION['active_as_user'];
    $activeAsUsername = $_SESSION['active_as_username'];

    // Session'daki aktif yetki hala geçerli mi kontrol et
    $validDelegation = false;
    foreach ($receivedDelegations as $delegation) {
        if ($delegation['from_user_id'] === $activeAsUser) {
            $expiryTime = strtotime($delegation['expiry_date'] . ' 23:59:59 UTC');
            if ($expiryTime >= time() && $delegation['is_active']) {
                $validDelegation = true;
                break;
            }
        }
    }

    // Eğer yetki geçersiz ise session'dan temizle
    if (!$validDelegation) {
        unset($_SESSION['active_as_user']);
        unset($_SESSION['active_as_username']);
        $activeAsUser = $_SESSION['user_id'];
        $activeAsUsername = $_SESSION['username'];
        $error = 'Aktif yetki delegasyonunuz süresi dolduğu için kendi hesabınıza döndünüz.';
    }
}

// Yetki devri işlemi - aktif kullanıcı adına
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {

    // CSRF Token doğrulaması
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Güvenlik hatası! Lütfen sayfayı yenileyin ve tekrar deneyin.';
    } else {
        if ($_POST['action'] == 'delegate') {
            $toUsername = trim($_POST['to_username']);
            $expiryDate = $_POST['expiry_date'];
            $description = trim($_POST['description']);
            $selectedPermissions = $_POST['permissions'] ?? [];

            // Gelişmiş input validasyonu
            if (empty($toUsername) || empty($expiryDate)) {
                $error = 'Tüm gerekli alanları doldurun!';
            } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $toUsername)) {
                $error = 'Geçersiz kullanıcı adı formatı!';
            } elseif ($toUsername === $activeAsUsername) {
                $error = 'Aynı kullanıcıya yetki devredemezsiniz!';
            } elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $expiryDate)) {
                $error = 'Geçersiz tarih formatı!';
            } elseif (isDelegationExpired($expiryDate) || strtotime($expiryDate . ' 00:00:00 UTC') <= getCurrentUTCTime()) {
                $error = 'Bitiş tarihi bugünden sonra olmalı!';
            } elseif (strtotime($expiryDate) > strtotime('+1 year')) {
                $error = 'Bitiş tarihi en fazla 1 yıl sonrası olabilir!';
            } elseif (strlen($description) > 500) {
                $error = 'Açıklama en fazla 500 karakter olabilir!';
            } elseif (!getUserByUsername($toUsername)) {
                $error = 'Belirtilen kullanıcı bulunamadı!';
            } elseif (empty($selectedPermissions)) {
                $error = 'En az bir yetki seçmelisiniz!';
            } else {
                // Seçilen izinleri validate et
                $userPermissions = getUserPermissions($activeAsUser);
                $validPermissions = array_intersect($selectedPermissions, $userPermissions);

                if (empty($validPermissions)) {
                    $error = 'Seçtiğiniz yetkilere sahip değilsiniz!';
                } else {
                    $result = delegateAuthority($activeAsUser, $toUsername, $expiryDate, $description, $validPermissions);
                }
                if (is_array($result) && isset($result['error'])) {
                    // Hata durumu
                    $error = $result['error'];
                } elseif ($result) {
                    // Başarılı
                    $success = ($activeAsUser !== $_SESSION['user_id'] ? $activeAsUsername . ' adına ' : '') . 'Yetki başarıyla devredildi!';
                    $myDelegations = getUserDelegations($_SESSION['user_id']); // Listeyi güncelle
                    // Başarılı işlem sonrası yeni token oluştur
                    refreshCSRFToken();
                } else {
                    $error = 'Yetki devri sırasında hata oluştu!';
                }
            }
        } elseif ($_POST['action'] == 'revoke') {
            $delegationId = trim($_POST['delegation_id']);

            // Delegation ID formatını validate et
            if (!preg_match('/^[a-zA-Z0-9]+$/', $delegationId)) {
                $error = 'Geçersiz delegasyon ID formatı!';
            } else {
                // Eğer başka biri adına işlem yapıyorsa, yetki kontrolü
                if ($activeAsUser !== $_SESSION['user_id']) {
                    // Sadece kendi verdiği delegasyonları iptal edebilir
                    $canRevoke = false;
                    if (isset($receivedDelegationsMap[$activeAsUser])) {
                        $delegation = $receivedDelegationsMap[$activeAsUser];
                        $expiryTime = strtotime($delegation['expiry_date'] . ' 23:59:59 UTC');
                        if ($expiryTime >= time() && $delegation['is_active']) {
                            $canRevoke = true;
                        }
                    }

                    if (!$canRevoke) {
                        $error = 'Bu kullanıcı adına yetki devri iptal etme yetkiniz yok!';
                    }
                }

                if (!$error && revokeDelegation($delegationId, $activeAsUser)) {
                    $success = ($activeAsUser !== $_SESSION['user_id'] ? $activeAsUsername . ' adına ' : '') . 'Yetki devri iptal edildi!';
                    $myDelegations = getUserDelegations($_SESSION['user_id']); // Listeyi güncelle
                    // Başarılı işlem sonrası yeni token oluştur
                    refreshCSRFToken();
                } elseif (!$error) {
                    $error = 'Yetki devri iptal edilemedi! (Yetkisiz erişim veya bulunamadı)';
                }
            }
        }
    }
}

// Aktif kullanıcının delegasyonlarını al - tutarlılık için aynı kaynaktan
$activeDelegations = getUserDelegations($activeAsUser);
$myDelegations = $activeDelegations; // Tutarlılık için aynı data kullan

// Kullanıcının kendi adına işlem yapma kontrolü
$userActionStatus = canUserPerformActions($_SESSION['user_id']);
$isBlocked = !$userActionStatus['allowed'] && $activeAsUser === $_SESSION['user_id'];

// Eğer kullanıcı kendi adına işlem yapmaya çalışıyor ama aktif yetkisi varsa TÜM işlemleri engelle
if ($isBlocked && ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']))) {
    $error = $userActionStatus['message'];
    // Hiçbir işleme izin verme
}

// İşlem bazlı yetki kontrolleri
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    $activeUserId = $activeAsUser !== $_SESSION['user_id'] ? $activeAsUser : $_SESSION['user_id'];

    if ($_POST['action'] == 'delegate') {
        if (!hasPermission($_SESSION['user_id'], 'delegation_create', $activeUserId)) {
            $error = 'Yetki devri oluşturma için yetkiniz yok!';
        }
    } elseif ($_POST['action'] == 'revoke') {
        if (!hasPermission($_SESSION['user_id'], 'delegation_revoke', $activeUserId)) {
            $error = 'Yetki devri iptal etme için yetkiniz yok!';
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
            <div>
                <?php if (hasPermission($_SESSION['user_id'], 'user_management') || hasPermission($_SESSION['user_id'], 'role_management')): ?>
                    <a href="admin.php" class="btn btn-primary">Admin Panel</a>
                <?php endif; ?>
                <a href="logout.php" class="btn btn-secondary">Çıkış Yap</a>
            </div>
        </div>

        <?php if ($activeAsUser !== $_SESSION['user_id']): ?>
            <div class="alert alert-info">
                <strong>Dikkat:</strong> Şu anda <strong><?php echo htmlspecialchars($activeAsUsername); ?></strong> adına işlem yapıyorsunuz.
                <form method="POST" style="display:inline; margin-left: 10px;">
                    <?php echo getCSRFField(); ?>
                    <input type="hidden" name="switch_to_self" value="1">
                    <button type="submit" class="btn btn-small" style="background: white; color: #333; padding: 5px 10px;">
                        Kendi Adıma Dön
                    </button>
                </form>
            </div>
        <?php endif; ?>

        <?php if ($isBlocked): ?>
            <div class="alert alert-error">
                <strong>İşlem Engellendi:</strong> <?php echo htmlspecialchars($userActionStatus['message']); ?>
                <form method="POST" style="display:inline; margin-left: 15px;">
                    <?php echo getCSRFField(); ?>
                    <input type="hidden" name="action" value="revoke">
                    <input type="hidden" name="delegation_id" value="<?php echo $userActionStatus['delegation']['id']; ?>">
                    <button type="submit" class="btn btn-small" style="background: white; color: #d32f2f; padding: 5px 15px; font-weight: bold;"
                        onclick="return confirm('Aktif yetki devrinizi sonlandırmak istediğinizden emin misiniz?')">
                        Yetkiyi Sonlandır
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
                        <?php echo getCSRFField(); ?>
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

                <?php if ($isBlocked): ?>
                    <div class="form-disabled-overlay">
                        <p><strong>Bu bölüm devre dışı:</strong> Kendi adınıza işlem yapmak için önce mevcut yetki devrinizi sonlandırın.</p>
                    </div>
                <?php else: ?>
                    <form method="POST">
                        <?php echo getCSRFField(); ?>
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
                            <label>Devredilecek Yetkiler:</label>
                            <div style="max-height: 200px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #f9f9f9;">
                                <?php
                                $categories = [];
                                foreach ($availablePermissions as $permission) {
                                    if (in_array($permission['name'], $userPermissions)) {
                                        $categories[$permission['category']][] = $permission;
                                    }
                                }

                                foreach ($categories as $categoryName => $permissions): ?>
                                    <div style="margin-bottom: 15px;">
                                        <strong><?php echo ucfirst(htmlspecialchars($categoryName)); ?> Yetkileri:</strong>
                                        <div style="margin-left: 15px; margin-top: 5px;">
                                            <?php foreach ($permissions as $permission): ?>
                                                <label style="display: block; margin-bottom: 5px; font-weight: normal;">
                                                    <input type="checkbox" name="permissions[]" value="<?php echo htmlspecialchars($permission['name']); ?>"
                                                        style="margin-right: 8px;">
                                                    <?php echo htmlspecialchars($permission['display_name']); ?>
                                                    <small style="color: #666; display: block; margin-left: 20px;">
                                                        <?php echo htmlspecialchars($permission['description']); ?>
                                                    </small>
                                                </label>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            <small style="color: #666; margin-top: 5px; display: block;">
                                İpucu: Sadece sahip olduğunuz yetkileri devredebilirsiniz.
                            </small>
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
                <?php endif; ?>
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
                                <th>Devredilen Yetkiler</th>
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
                                    <td>
                                        <?php
                                        if (isset($delegation['delegated_permissions']) && !empty($delegation['delegated_permissions'])) {
                                            // PERFORMANS: Bulk permission resolution
                                            $permNames = resolvePermissionNames($delegation['delegated_permissions']);
                                            echo '<small>' . htmlspecialchars(implode(', ', $permNames)) . '</small>';
                                        } else {
                                            echo '<em>Tüm yetkiler</em>';
                                        }
                                        ?>
                                    </td>
                                    <td><?php echo htmlspecialchars($delegation['description'] ?: '-'); ?></td>
                                    <td><?php echo formatDateTime($delegation['created_at']); ?></td>
                                    <td>
                                        <form method="POST" style="display:inline;">
                                            <?php echo getCSRFField(); ?>
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
                                <th>Aldığınız Yetkiler</th>
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
                                    <td>
                                        <?php
                                        if (isset($delegation['delegated_permissions']) && !empty($delegation['delegated_permissions'])) {
                                            // PERFORMANS: Bulk permission resolution
                                            $permNames = resolvePermissionNames($delegation['delegated_permissions']);
                                            echo '<small>' . htmlspecialchars(implode(', ', $permNames)) . '</small>';
                                        } else {
                                            echo '<em>Tüm yetkiler</em>';
                                        }
                                        ?>
                                    </td>
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