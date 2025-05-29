<?php
/**
 * Sistem Fonksiyonları
 * @author A. Kerem Gök
 */

// JSON dosyalarının yolları
define('USERS_FILE', 'data/users.json');
define('DELEGATIONS_FILE', 'data/delegations.json');

/**
 * JSON dosyasını güvenli şekilde okur
 */
function readJsonFile($filename) {
    if (!file_exists($filename)) {
        // Eğer data klasörü yoksa oluştur
        $dir = dirname($filename);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        // Boş array ile dosyayı oluştur
        file_put_contents($filename, json_encode([]));
        return [];
    }
    
    $content = file_get_contents($filename);
    $data = json_decode($content, true);
    return $data === null ? [] : $data;
}

/**
 * JSON dosyasına güvenli şekilde yazar
 */
function writeJsonFile($filename, $data) {
    $dir = dirname($filename);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    return file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

/**
 * Kullanıcının var olup olmadığını kontrol eder
 */
function userExists($username) {
    $users = readJsonFile(USERS_FILE);
    foreach ($users as $user) {
        if ($user['username'] === $username) {
            return true;
        }
    }
    return false;
}

/**
 * Yeni kullanıcı kaydeder
 */
function registerUser($username, $password) {
    $users = readJsonFile(USERS_FILE);
    
    // Yeni kullanıcı bilgisi
    $newUser = [
        'id' => uniqid(),
        'username' => $username,
        'password' => $password, // Plain text olarak saklanıyor
        'created_at' => date('Y-m-d H:i:s')
    ];
    
    $users[] = $newUser;
    return writeJsonFile(USERS_FILE, $users);
}

/**
 * Kullanıcı girişi yapar
 */
function loginUser($username, $password) {
    $users = readJsonFile(USERS_FILE);
    foreach ($users as $user) {
        if ($user['username'] === $username && $user['password'] === $password) {
            return $user;
        }
    }
    return false;
}

/**
 * Kullanıcı ID'sine göre kullanıcı bilgisi getirir
 */
function getUserById($userId) {
    $users = readJsonFile(USERS_FILE);
    foreach ($users as $user) {
        if ($user['id'] === $userId) {
            return $user;
        }
    }
    return false;
}

/**
 * Kullanıcı adına göre kullanıcı bilgisi getirir
 */
function getUserByUsername($username) {
    $users = readJsonFile(USERS_FILE);
    foreach ($users as $user) {
        if ($user['username'] === $username) {
            return $user;
        }
    }
    return false;
}

/**
 * Tüm kullanıcıları getirir (şifre hariç)
 */
function getAllUsers() {
    $users = readJsonFile(USERS_FILE);
    $result = [];
    foreach ($users as $user) {
        $result[] = [
            'id' => $user['id'],
            'username' => $user['username'],
            'created_at' => $user['created_at']
        ];
    }
    return $result;
}

/**
 * Kullanıcının belirli bir kişiye zaten aktif yetkisi olup olmadığını kontrol eder
 */
function hasActiveDelegationTo($fromUserId, $toUserId) {
    $delegations = readJsonFile(DELEGATIONS_FILE);
    
    foreach ($delegations as $delegation) {
        if ($delegation['from_user_id'] === $fromUserId && 
            $delegation['to_user_id'] === $toUserId && 
            $delegation['is_active']) {
            // Tarihi kontrol et
            if (strtotime($delegation['expiry_date']) >= strtotime(date('Y-m-d'))) {
                return $delegation; // Aktif delegasyon var
            }
        }
    }
    
    return false; // Aktif delegasyon yok
}

/**
 * Yetki devreder
 */
function delegateAuthority($fromUserId, $toUsername, $expiryDate, $description = '') {
    $toUser = getUserByUsername($toUsername);
    if (!$toUser) {
        return false;
    }
    
    // Aynı kullanıcıya zaten aktif yetki var mı kontrol et
    $existingDelegation = hasActiveDelegationTo($fromUserId, $toUser['id']);
    if ($existingDelegation) {
        return ['error' => 'Bu kullanıcıya zaten aktif bir yetki devriniz bulunuyor! (Bitiş: ' . formatDate($existingDelegation['expiry_date']) . ')'];
    }
    
    $delegations = readJsonFile(DELEGATIONS_FILE);
    
    $delegation = [
        'id' => uniqid(),
        'from_user_id' => $fromUserId,
        'to_user_id' => $toUser['id'],
        'expiry_date' => $expiryDate,
        'description' => $description,
        'created_at' => date('Y-m-d H:i:s'),
        'is_active' => true
    ];
    
    $delegations[] = $delegation;
    return writeJsonFile(DELEGATIONS_FILE, $delegations);
}

/**
 * Kullanıcının aktif yetki devrelerini getirir (verdiği)
 */
function getUserDelegations($userId) {
    $delegations = readJsonFile(DELEGATIONS_FILE);
    $result = [];
    
    foreach ($delegations as $delegation) {
        if ($delegation['from_user_id'] === $userId && $delegation['is_active']) {
            // Tarihi kontrol et
            if (strtotime($delegation['expiry_date']) >= strtotime(date('Y-m-d'))) {
                $toUser = getUserById($delegation['to_user_id']);
                $delegation['to_username'] = $toUser ? $toUser['username'] : 'Bilinmeyen Kullanıcı';
                $result[] = $delegation;
            } else {
                // Süresi dolmuş delegasyonu pasif yap
                deactivateDelegation($delegation['id']);
            }
        }
    }
    
    return $result;
}

/**
 * Kullanıcının sahip olduğu aktif yetkileri getirir (aldığı)
 */
function getUserReceivedDelegations($userId) {
    $delegations = readJsonFile(DELEGATIONS_FILE);
    $result = [];
    
    foreach ($delegations as $delegation) {
        if ($delegation['to_user_id'] === $userId && $delegation['is_active']) {
            // Tarihi kontrol et
            if (strtotime($delegation['expiry_date']) >= strtotime(date('Y-m-d'))) {
                $fromUser = getUserById($delegation['from_user_id']);
                $delegation['from_username'] = $fromUser ? $fromUser['username'] : 'Bilinmeyen Kullanıcı';
                $result[] = $delegation;
            } else {
                // Süresi dolmuş delegasyonu pasif yap
                deactivateDelegation($delegation['id']);
            }
        }
    }
    
    return $result;
}

/**
 * Yetki devrini pasif yapar
 */
function deactivateDelegation($delegationId) {
    $delegations = readJsonFile(DELEGATIONS_FILE);
    
    foreach ($delegations as &$delegation) {
        if ($delegation['id'] === $delegationId) {
            $delegation['is_active'] = false;
            break;
        }
    }
    
    return writeJsonFile(DELEGATIONS_FILE, $delegations);
}

/**
 * Yetki devrini iptal eder
 */
function revokeDelegation($delegationId, $userId) {
    $delegations = readJsonFile(DELEGATIONS_FILE);
    
    foreach ($delegations as &$delegation) {
        if ($delegation['id'] === $delegationId && $delegation['from_user_id'] === $userId) {
            $delegation['is_active'] = false;
            writeJsonFile(DELEGATIONS_FILE, $delegations);
            return true;
        }
    }
    
    return false;
}

/**
 * Tarihi formatlar
 */
function formatDate($date) {
    return date('d.m.Y', strtotime($date));
}

/**
 * Tarih ve saati formatlar
 */
function formatDateTime($datetime) {
    return date('d.m.Y H:i', strtotime($datetime));
}
?> 