<?php

/**
 * Admin Panel - Kullanıcı ve Rol Yönetimi
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

// Giriş kontrolü
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

// Admin yetkisi kontrolü
$currentUser = getUserById($_SESSION['user_id']);
if (!hasPermission($_SESSION['user_id'], 'user_management') && !hasPermission($_SESSION['user_id'], 'role_management')) {
    header('Location: dashboard.php?error=' . urlencode('Bu sayfaya erişim yetkiniz yok!'));
    exit;
}

$error = '';
$success = '';

// Kullanıcı rol güncelleme işlemi
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {

    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Güvenlik hatası! Lütfen sayfayı yenileyin ve tekrar deneyin.';
    } else {

        if ($_POST['action'] == 'update_user_role') {
            if (!hasPermission($_SESSION['user_id'], 'user_management')) {
                $error = 'Bu işlem için yetkiniz yok!';
            } else {
                $userId = trim($_POST['user_id']);
                $newRoleId = trim($_POST['role_id']);

                if (updateUserRole($userId, $newRoleId)) {
                    $success = 'Kullanıcı rolü başarıyla güncellendi!';
                    refreshCSRFToken();
                } else {
                    $error = 'Kullanıcı rolü güncellenirken hata oluştu!';
                }
            }
        } elseif ($_POST['action'] == 'toggle_user_status') {
            if (!hasPermission($_SESSION['user_id'], 'user_management')) {
                $error = 'Bu işlem için yetkiniz yok!';
            } else {
                $userId = trim($_POST['user_id']);
                $newStatus = trim($_POST['status']);

                if (updateUserStatus($userId, $newStatus)) {
                    $success = 'Kullanıcı durumu başarıyla güncellendi!';
                    refreshCSRFToken();
                } else {
                    $error = 'Kullanıcı durumu güncellenirken hata oluştu!';
                }
            }
        }
    }
}

// Verileri getir
$allUsers = getAllUsers();
$allRoles = getAllRoles();
$allPermissions = getAllPermissions();

// Kullanıcıları rollerle birleştir
foreach ($allUsers as &$user) {
    if (isset($user['role_id'])) {
        $role = getRoleById($user['role_id']);
        $user['role_name'] = $role ? $role['display_name'] : 'Bilinmeyen Rol';
    } else {
        $user['role_name'] = 'Rol Atanmamış';
    }
}
?>

<!DOCTYPE html>
<html lang="tr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - Yetki Sistemi</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .admin-nav {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 2rem;
        }

        .admin-nav ul {
            list-style: none;
            margin: 0;
            padding: 0;
            display: flex;
            gap: 1rem;
        }

        .admin-nav a {
            color: white;
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: 5px;
            transition: background 0.3s;
        }

        .admin-nav a:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        .users-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }

        .users-table th,
        .users-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        .users-table th {
            background: #f8f9fa;
            font-weight: bold;
        }

        .status-active {
            color: #28a745;
            font-weight: bold;
        }

        .status-inactive {
            color: #dc3545;
            font-weight: bold;
        }

        .permissions-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }

        .permission-category {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 1rem;
            background: #f8f9fa;
        }

        .permission-category h4 {
            margin: 0 0 0.5rem 0;
            color: #333;
        }

        .permission-item {
            padding: 0.25rem 0;
            font-size: 0.9rem;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="header">
            <h1>Admin Panel</h1>
            <div>
                <a href="dashboard.php" class="btn btn-secondary">Ana Sayfa</a>
                <a href="logout.php" class="btn btn-secondary">Çıkış</a>
            </div>
        </div>

        <nav class="admin-nav">
            <ul>
                <li><a href="#users">Kullanıcı Yönetimi</a></li>
                <li><a href="#roles">Rol Yönetimi</a></li>
                <li><a href="#permissions">İzin Görüntüleme</a></li>
            </ul>
        </nav>

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

        <!-- Kullanıcı Yönetimi -->
        <div class="card" id="users">
            <h3>Kullanıcı Yönetimi</h3>

            <?php if (hasPermission($_SESSION['user_id'], 'user_management')): ?>
                <table class="users-table">
                    <thead>
                        <tr>
                            <th>Kullanıcı Adı</th>
                            <th>Rol</th>
                            <th>Durum</th>
                            <th>Kayıt Tarihi</th>
                            <th>İşlemler</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($allUsers as $user): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($user['username']); ?></td>
                                <td><?php echo htmlspecialchars($user['role_name']); ?></td>
                                <td>
                                    <span class="status-<?php echo $user['status'] ?? 'active'; ?>">
                                        <?php echo ucfirst($user['status'] ?? 'active'); ?>
                                    </span>
                                </td>
                                <td><?php echo formatDateTime($user['created_at']); ?></td>
                                <td>
                                    <form method="POST" style="display: inline-block; margin-right: 10px;">
                                        <?php echo getCSRFField(); ?>
                                        <input type="hidden" name="action" value="update_user_role">
                                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                        <select name="role_id" onchange="this.form.submit()">
                                            <option value="">Rol Seç</option>
                                            <?php foreach ($allRoles as $role): ?>
                                                <option value="<?php echo $role['id']; ?>"
                                                    <?php echo ($user['role_id'] ?? '') == $role['id'] ? 'selected' : ''; ?>>
                                                    <?php echo htmlspecialchars($role['display_name']); ?>
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </form>

                                    <form method="POST" style="display: inline-block;">
                                        <?php echo getCSRFField(); ?>
                                        <input type="hidden" name="action" value="toggle_user_status">
                                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                        <input type="hidden" name="status" value="<?php echo ($user['status'] ?? 'active') == 'active' ? 'inactive' : 'active'; ?>">
                                        <button type="submit" class="btn <?php echo ($user['status'] ?? 'active') == 'active' ? 'btn-danger' : 'btn-primary'; ?> btn-small">
                                            <?php echo ($user['status'] ?? 'active') == 'active' ? 'Devre Dışı' : 'Aktifleştir'; ?>
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p class="alert alert-info">Kullanıcı yönetimi için yetkiniz yok.</p>
            <?php endif; ?>
        </div>

        <!-- Rol Yönetimi -->
        <div class="card" id="roles">
            <h3>Rol Yönetimi</h3>

            <?php if (hasPermission($_SESSION['user_id'], 'role_management')): ?>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Rol Adı</th>
                            <th>Açıklama</th>
                            <th>İzin Sayısı</th>
                            <th>İzinler</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($allRoles as $role): ?>
                            <tr>
                                <td><strong><?php echo htmlspecialchars($role['display_name']); ?></strong></td>
                                <td><?php echo htmlspecialchars($role['description']); ?></td>
                                <td>
                                    <?php
                                    if (in_array('*', $role['permissions'])) {
                                        echo 'Tüm İzinler';
                                    } else {
                                        echo count($role['permissions']) . ' izin';
                                    }
                                    ?>
                                </td>
                                <td>
                                    <?php
                                    if (in_array('*', $role['permissions'])) {
                                        echo '<em>Süper Yönetici - Tüm İzinler</em>';
                                    } else {
                                        $permNames = [];
                                        foreach ($role['permissions'] as $permName) {
                                            $perm = getPermissionByName($permName);
                                            $permNames[] = $perm ? $perm['display_name'] : $permName;
                                        }
                                        echo implode(', ', $permNames);
                                    }
                                    ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p class="alert alert-info">Rol yönetimi için yetkiniz yok.</p>
            <?php endif; ?>
        </div>

        <!-- İzin Görüntüleme -->
        <div class="card" id="permissions">
            <h3>Sistem İzinleri</h3>

            <div class="permissions-grid">
                <?php
                $categories = [];
                foreach ($allPermissions as $permission) {
                    $categories[$permission['category']][] = $permission;
                }

                foreach ($categories as $categoryName => $permissions): ?>
                    <div class="permission-category">
                        <h4><?php echo ucfirst(htmlspecialchars($categoryName)); ?> İzinleri</h4>
                        <?php foreach ($permissions as $permission): ?>
                            <div class="permission-item">
                                <strong><?php echo htmlspecialchars($permission['display_name']); ?></strong><br>
                                <small><?php echo htmlspecialchars($permission['description']); ?></small>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <script>
        // Smooth scrolling for navigation
        document.querySelectorAll('.admin-nav a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
    </script>
</body>

</html>