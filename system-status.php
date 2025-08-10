<?php

/**
 * Sistem Durum ve Performans İzleme
 * @author A. Kerem Gök
 */

// Güvenlik headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

session_start();
require_once 'functions.php';

// Giriş ve yetki kontrolü
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

if (!hasPermission($_SESSION['user_id'], 'system_settings')) {
    header('Location: dashboard.php?error=' . urlencode('Bu sayfaya erişim yetkiniz yok!'));
    exit;
}

// Manual heartbeat trigger
if (isset($_GET['action']) && $_GET['action'] === 'heartbeat') {
    $heartbeatResult = systemHeartbeat();
    $success = 'Sistem kontrolü tamamlandı. ' . $heartbeatResult['cleaned_delegations'] . ' süresi dolmuş delegasyon temizlendi.';
}

// System metrics
$systemStats = [
    'php_version' => PHP_VERSION,
    'memory_usage' => checkMemoryUsage(),
    'cache_status' => [
        'apcu_enabled' => extension_loaded('apcu') && apcu_enabled(),
        'cache_info' => extension_loaded('apcu') ? apcu_cache_info() : null
    ],
    'file_permissions' => [
        'data_dir' => is_writable(dirname(USERS_FILE)),
        'users_file' => file_exists(USERS_FILE) && is_readable(USERS_FILE),
        'delegations_file' => file_exists(DELEGATIONS_FILE) && is_readable(DELEGATIONS_FILE)
    ]
];

// Data integrity check
$integrityIssues = checkDataIntegrity();

// Recent security events (last 24 hours)
$securityLog = [];
$logFile = dirname(USERS_FILE) . '/security.log';
if (file_exists($logFile)) {
    $lines = file($logFile, FILE_IGNORE_NEW_LINES);
    $recentEvents = array_slice($lines, -50); // Son 50 event

    foreach ($recentEvents as $line) {
        $event = json_decode($line, true);
        if ($event && strtotime($event['timestamp']) > (time() - 86400)) {
            $securityLog[] = $event;
        }
    }
}

// Statistics
$users = readJsonFile(USERS_FILE);
$delegations = readJsonFile(DELEGATIONS_FILE);
$activeDelegations = array_filter($delegations, function ($d) {
    return $d['is_active'] && !isDelegationExpired($d['expiry_date']);
});

$stats = [
    'total_users' => count($users),
    'active_users' => count(array_filter($users, function ($u) {
        return ($u['status'] ?? 'active') === 'active';
    })),
    'total_delegations' => count($delegations),
    'active_delegations' => count($activeDelegations),
    'expired_delegations' => count($delegations) - count($activeDelegations)
];

?>

<!DOCTYPE html>
<html lang="tr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistem Durumu - Yetki Sistemi</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 10px;
            text-align: center;
        }

        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 0.5rem 0;
        }

        .status-good {
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
        }

        .status-warning {
            background: linear-gradient(135deg, #FF9800 0%, #F57C00 100%);
        }

        .status-error {
            background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%);
        }

        .log-table {
            font-size: 0.9em;
            max-height: 400px;
            overflow-y: auto;
        }

        .log-level-INFO {
            color: #2196F3;
        }

        .log-level-WARNING {
            color: #FF9800;
        }

        .log-level-CRITICAL {
            color: #f44336;
            font-weight: bold;
        }

        .system-info {
            background: #f5f5f5;
            padding: 1rem;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.9em;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="header">
            <h1>Sistem Durumu</h1>
            <div>
                <a href="dashboard.php" class="btn btn-secondary">Ana Sayfa</a>
                <a href="admin.php" class="btn btn-secondary">Admin Panel</a>
                <a href="?action=heartbeat" class="btn btn-primary">Sistem Kontrolü</a>
            </div>
        </div>

        <?php if (isset($success)): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <!-- Metrics Grid -->
        <div class="metrics-grid">
            <div class="metric-card">
                <h3>Toplam Kullanıcı</h3>
                <div class="metric-value"><?php echo $stats['total_users']; ?></div>
                <small>Aktif: <?php echo $stats['active_users']; ?></small>
            </div>
            <div class="metric-card">
                <h3>Aktif Delegasyon</h3>
                <div class="metric-value"><?php echo $stats['active_delegations']; ?></div>
                <small>Toplam: <?php echo $stats['total_delegations']; ?></small>
            </div>
            <div class="metric-card <?php echo $systemStats['memory_usage']['current_mb'] > 64 ? 'status-warning' : 'status-good'; ?>">
                <h3>Bellek Kullanımı</h3>
                <div class="metric-value"><?php echo $systemStats['memory_usage']['current_mb']; ?>MB</div>
                <small>Peak: <?php echo $systemStats['memory_usage']['peak_mb']; ?>MB</small>
            </div>
            <div class="metric-card <?php echo $systemStats['cache_status']['apcu_enabled'] ? 'status-good' : 'status-warning'; ?>">
                <h3>Cache Durumu</h3>
                <div class="metric-value"><?php echo $systemStats['cache_status']['apcu_enabled'] ? 'APCu' : 'File'; ?></div>
                <small><?php echo $systemStats['cache_status']['apcu_enabled'] ? 'Aktif' : 'Fallback'; ?></small>
            </div>
        </div>

        <!-- System Information -->
        <div class="card">
            <h3>Sistem Bilgileri</h3>
            <div class="system-info">
                <div><strong>PHP Version:</strong> <?php echo $systemStats['php_version']; ?></div>
                <div><strong>Memory Limit:</strong> <?php echo ini_get('memory_limit'); ?></div>
                <div><strong>Max Execution Time:</strong> <?php echo ini_get('max_execution_time'); ?>s</div>
                <div><strong>Data Directory Writable:</strong> <?php echo $systemStats['file_permissions']['data_dir'] ? 'Yes' : 'No'; ?></div>
                <div><strong>Cache Type:</strong> <?php echo $systemStats['cache_status']['apcu_enabled'] ? 'APCu (Optimized)' : 'File-based (Fallback)'; ?></div>
                <?php if ($systemStats['cache_status']['apcu_enabled'] && $systemStats['cache_status']['cache_info']): ?>
                    <div><strong>APCu Cache Size:</strong> <?php echo round($systemStats['cache_status']['cache_info']['mem_size'] / 1024 / 1024, 2); ?>MB</div>
                    <div><strong>APCu Cache Hits:</strong> <?php echo number_format($systemStats['cache_status']['cache_info']['num_hits'] ?? 0); ?></div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Data Integrity -->
        <div class="card">
            <h3>Veri Bütünlüğü
                <span class="<?php echo empty($integrityIssues) ? 'status-active' : 'status-inactive'; ?>" style="font-size: 14px; margin-left: 10px;">
                    <?php echo empty($integrityIssues) ? 'OK' : count($integrityIssues) . ' Sorun'; ?>
                </span>
            </h3>

            <?php if (empty($integrityIssues)): ?>
                <p class="alert alert-success">Veri bütünlüğü kontrolü başarılı. Herhangi bir sorun tespit edilmedi.</p>
            <?php else: ?>
                <div class="alert alert-error">
                    <strong>Tespit edilen sorunlar:</strong>
                    <ul>
                        <?php foreach ($integrityIssues as $issue): ?>
                            <li><?php echo htmlspecialchars($issue); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
        </div>

        <!-- Security Log -->
        <div class="card">
            <h3>Güvenlik Olayları (Son 24 Saat)</h3>

            <?php if (empty($securityLog)): ?>
                <p class="no-data">Son 24 saatte kayıtlı güvenlik olayı bulunmuyor.</p>
            <?php else: ?>
                <div class="log-table">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Zaman</th>
                                <th>Olay</th>
                                <th>Kullanıcı</th>
                                <th>IP</th>
                                <th>Seviye</th>
                                <th>Detay</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach (array_reverse($securityLog) as $event): ?>
                                <tr>
                                    <td><?php echo formatDateTime($event['timestamp']); ?></td>
                                    <td><?php echo htmlspecialchars($event['event']); ?></td>
                                    <td><?php echo htmlspecialchars($event['user_id']); ?></td>
                                    <td><?php echo htmlspecialchars($event['ip']); ?></td>
                                    <td class="log-level-<?php echo $event['level']; ?>">
                                        <?php echo $event['level']; ?>
                                    </td>
                                    <td>
                                        <small><?php echo htmlspecialchars(json_encode($event['details'], JSON_PRETTY_PRINT)); ?></small>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        // Auto-refresh every 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
    </script>
</body>

</html>