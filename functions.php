<?php

/**
 * Sistem Fonksiyonları
 * @author A. Kerem Gök
 */

// JSON dosyalarının yolları
define('USERS_FILE', 'data/users.json');
define('DELEGATIONS_FILE', 'data/delegations.json');
define('ROLES_FILE', 'data/roles.json');
define('PERMISSIONS_FILE', 'data/permissions.json');

// Gelişmiş cache sistemi (APCu + Fallback)
define('CACHE_TTL', 300); // 5 dakika cache
define('CACHE_PREFIX', 'vekalet_v1_'); // Versioning için

// Legacy static cache (fallback)
static $usersCache = null;
static $usersCacheTime = 0;
static $delegationsCache = null;
static $delegationsCacheTime = 0;
static $rolesCache = null;
static $rolesCacheTime = 0;
static $permissionsCache = null;
static $permissionsCacheTime = 0;

/**
 * Thread-safe cache get operation
 */
function getCacheValue($key, $fallbackCallback = null)
{
    $fullKey = CACHE_PREFIX . $key;
    
    // APCu cache (thread-safe)
    if (extension_loaded('apcu') && apcu_enabled()) {
        $cached = apcu_fetch($fullKey, $success);
        if ($success) {
            return $cached;
        }
        
        // Cache miss - generate value
        if ($fallbackCallback && is_callable($fallbackCallback)) {
            $value = $fallbackCallback();
            apcu_store($fullKey, $value, CACHE_TTL);
            return $value;
        }
        
        return false;
    }
    
    // Fallback to file cache
    $cacheFile = sys_get_temp_dir() . '/vekalet_cache_' . md5($key) . '.json';
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < CACHE_TTL) {
        $content = file_get_contents($cacheFile);
        if ($content !== false) {
            $data = json_decode($content, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return $data;
            }
        }
    }
    
    // Cache miss - generate value
    if ($fallbackCallback && is_callable($fallbackCallback)) {
        $value = $fallbackCallback();
        file_put_contents($cacheFile, json_encode($value), LOCK_EX);
        return $value;
    }
    
    return false;
}

/**
 * Thread-safe cache set operation
 */
function setCacheValue($key, $value, $ttl = CACHE_TTL)
{
    $fullKey = CACHE_PREFIX . $key;
    
    if (extension_loaded('apcu') && apcu_enabled()) {
        return apcu_store($fullKey, $value, $ttl);
    }
    
    // Fallback to file cache
    $cacheFile = sys_get_temp_dir() . '/vekalet_cache_' . md5($key) . '.json';
    $result = file_put_contents($cacheFile, json_encode($value), LOCK_EX);
    return $result !== false;
}

/**
 * Cache invalidation
 */
function invalidateCache($pattern = null)
{
    if (extension_loaded('apcu') && apcu_enabled()) {
        if ($pattern) {
            // Pattern-based invalidation
            $fullPattern = CACHE_PREFIX . $pattern;
            $info = apcu_cache_info();
            foreach ($info['cache_list'] as $entry) {
                if (strpos($entry['info'], $fullPattern) === 0) {
                    apcu_delete($entry['info']);
                }
            }
        } else {
            // Clear all cache
            apcu_clear_cache();
        }
    }
    
    // File cache cleanup
    $tempDir = sys_get_temp_dir();
    $files = glob($tempDir . '/vekalet_cache_*.json');
    foreach ($files as $file) {
        if ($pattern === null || strpos(basename($file), $pattern) !== false) {
            unlink($file);
        }
    }
}

/**
 * JSON dosyasını güvenli şekilde okur
 */
function readJsonFile($filename)
{
    if (!file_exists($filename)) {
        // Eğer data klasörü yoksa oluştur
        $dir = dirname($filename);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true); // Güvenli izinler
        }
        // Boş array ile dosyayı oluştur
        file_put_contents($filename, json_encode([]), LOCK_EX);
        chmod($filename, 0600); // Sadece owner erişebilir
        return [];
    }

    // Dosya kilitleme ile güvenli okuma
    $handle = fopen($filename, 'r');
    if (!$handle) {
        error_log("JSON dosyası okunamıyor: $filename");
        return [];
    }
    
    if (flock($handle, LOCK_SH)) { // Shared lock for reading
        $content = fread($handle, filesize($filename));
        flock($handle, LOCK_UN); // Unlock
        fclose($handle);
        
        if ($content === false) {
            error_log("JSON dosyası içeriği okunamıyor: $filename");
            return [];
        }
        
        $data = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("JSON parsing hatası ($filename): " . json_last_error_msg());
            return [];
        }
        
        return $data === null ? [] : $data;
    } else {
        fclose($handle);
        error_log("JSON dosyası kilitlenemiyor: $filename");
        return [];
    }
}

/**
 * JSON dosyasına güvenli şekilde yazar
 */
function writeJsonFile($filename, $data)
{
    $dir = dirname($filename);
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true); // Daha güvenli izinler
    }
    
    // Dosya kilitleme ile güvenli yazma
    $tempFile = $filename . '.tmp';
    $result = file_put_contents($tempFile, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
    
    if ($result !== false) {
        chmod($tempFile, 0600); // Sadece owner okuyabilir/yazabilir
        rename($tempFile, $filename);
        return $result;
    }
    
    return false;
}

/**
 * Kullanıcının var olup olmadığını kontrol eder
 */
function userExists($username)
{
    $users = readJsonFile(USERS_FILE);
    foreach ($users as $user) {
        if ($user['username'] === $username) {
            return true;
        }
    }
    return false;
}

/**
 * Yeni kullanıcı kaydeder (default role ile)
 */
function registerUser($username, $password, $roleId = 'role004')
{
    $users = readJsonFile(USERS_FILE);

    // Yeni kullanıcı bilgisi
    $newUser = [
        'id' => uniqid(),
        'username' => $username,
        'password' => password_hash($password, PASSWORD_DEFAULT), // Güvenli hash
        'role_id' => $roleId, // Varsayılan: normal kullanıcı
        'status' => 'active',
        'created_at' => gmdate('Y-m-d H:i:s') // UTC zaman
    ];

    $users[] = $newUser;
    $result = writeJsonFile(USERS_FILE, $users);
    if ($result) {
        clearCache(); // Yeni kullanıcı eklenince cache'i temizle
    }
    return $result;
}

/**
 * Kullanıcı girişi yapar
 */
function loginUser($username, $password)
{
    $users = readJsonFile(USERS_FILE);
    foreach ($users as $user) {
        if ($user['username'] === $username && password_verify($password, $user['password'])) {
            return $user;
        }
    }
    return false;
}

/**
 * Kullanıcı ID'sine göre kullanıcı bilgisi getirir (optimized cache)
 */
function getUserById($userId)
{
    $cacheKey = 'user_by_id_' . $userId;
    
    return getCacheValue($cacheKey, function() use ($userId) {
        // Cache miss - load from file
        $users = readJsonFile(USERS_FILE);
        foreach ($users as $user) {
            if ($user['id'] === $userId) {
                return $user;
            }
        }
        return false;
    });
}

/**
 * Kullanıcı adına göre kullanıcı bilgisi getirir (optimized cache)
 */
function getUserByUsername($username)
{
    $cacheKey = 'user_by_username_' . md5($username);
    
    return getCacheValue($cacheKey, function() use ($username) {
        // Cache miss - load from file
        $users = readJsonFile(USERS_FILE);
        foreach ($users as $user) {
            if ($user['username'] === $username) {
                return $user;
            }
        }
        return false;
    });
}

/**
 * Tüm kullanıcıları getirir (şifre hariç)
 */
function getAllUsers()
{
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
function hasActiveDelegationTo($fromUserId, $toUserId)
{
    $delegations = readJsonFile(DELEGATIONS_FILE);

    foreach ($delegations as $delegation) {
        if (
            $delegation['from_user_id'] === $fromUserId &&
            $delegation['to_user_id'] === $toUserId &&
            $delegation['is_active']
        ) {
            // Tarihi kontrol et (UTC standardized)
            if (!isDelegationExpired($delegation['expiry_date'])) {
                return $delegation; // Aktif delegasyon var
            }
        }
    }

    return false; // Aktif delegasyon yok
}

/**
 * Yetki devreder (atomic ve güvenli)
 */
function delegateAuthority($fromUserId, $toUsername, $expiryDate, $description = '', $permissions = [])
{
    $toUser = getUserByUsername($toUsername);
    if (!$toUser) {
        return false;
    }

    // Aynı kullanıcıya zaten aktif yetki var mı kontrol et
    $existingDelegation = hasActiveDelegationTo($fromUserId, $toUser['id']);
    if ($existingDelegation) {
        // Güvenlik için detaylı bilgi log'a yazılır, kullanıcıya genel mesaj gösterilir
        error_log("Duplicate delegation attempt: User $fromUserId to " . $toUser['id'] . ", existing expires: " . $existingDelegation['expiry_date']);
        return ['error' => 'Bu kullanıcıya zaten aktif bir yetki devriniz bulunuyor!'];
    }

    $delegations = readJsonFile(DELEGATIONS_FILE);

    // ATOMIC OPERATION: Lock dosyası ile güvenli işlem
    $lockFile = dirname(DELEGATIONS_FILE) . '/delegation.lock';
    $lockHandle = fopen($lockFile, 'c+');
    
    if (!$lockHandle || !flock($lockHandle, LOCK_EX)) {
        if ($lockHandle) fclose($lockHandle);
        return ['error' => 'Sistem yoğunluğu nedeniyle işlem gerçekleştirilemiyor. Lütfen tekrar deneyin.'];
    }
    
    try {
        // STEP 1: Fresh permission validation (atomic)
        if (empty($permissions)) {
            $permissions = getUserDelegatablePermissions($fromUserId);
        }
        
        // STEP 2: Real-time permission check
        $userPerms = getUserPermissions($fromUserId);
        $validPermissions = array_intersect($permissions, $userPerms);
        
        if (empty($validPermissions)) {
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
            return ['error' => 'Devredebileceğiniz geçerli yetki bulunamadı!'];
        }
        
        // STEP 3: Circular delegation check
        if (hasCircularDelegation($fromUserId, $toUser['id'])) {
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
            return ['error' => 'Döngüsel yetki devri tespit edildi! Bu işlem gerçekleştirilemez.'];
        }
        
        // STEP 4: Existing delegation check (atomic)
        $existingDelegation = hasActiveDelegationTo($fromUserId, $toUser['id']);
        if ($existingDelegation) {
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
            error_log("Duplicate delegation attempt: User $fromUserId to " . $toUser['id'] . ", existing expires: " . $existingDelegation['expiry_date']);
            return ['error' => 'Bu kullanıcıya zaten aktif bir yetki devriniz bulunuyor!'];
        }

    $delegation = [
        'id' => uniqid(),
        'from_user_id' => $fromUserId,
        'to_user_id' => $toUser['id'],
        'expiry_date' => $expiryDate,
        'description' => $description,
        'delegated_permissions' => $validPermissions,
        'created_at' => getCurrentUTCDateTime(), // UTC standardized
        'is_active' => true
    ];

        $delegations[] = $delegation;
        $result = writeJsonFile(DELEGATIONS_FILE, $delegations);
        
        // STEP 6: Cache invalidation
        if ($result) {
            clearCache();
        }
        
        flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
        
        return $result;
        
    } catch (Exception $e) {
        // Error handling
        flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
        error_log("Delegation creation error: " . $e->getMessage());
        return ['error' => 'Yetki devri sırasında beklenmeyen hata oluştu.'];
    }
}

/**
 * Kullanıcının aktif yetki devrelerini getirir (verdiği)
 */
function getUserDelegations($userId)
{
    $delegations = readJsonFile(DELEGATIONS_FILE);
    $result = [];

    foreach ($delegations as $delegation) {
        if ($delegation['from_user_id'] === $userId && $delegation['is_active']) {
            // Tarihi kontrol et (UTC standardized)
            if (!isDelegationExpired($delegation['expiry_date'])) {
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
function getUserReceivedDelegations($userId)
{
    $delegations = readJsonFile(DELEGATIONS_FILE);
    $result = [];

    foreach ($delegations as $delegation) {
        if ($delegation['to_user_id'] === $userId && $delegation['is_active']) {
            // Tarihi kontrol et (UTC standardized)
            if (!isDelegationExpired($delegation['expiry_date'])) {
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
 * Yetki devrini pasif yapar (atomic operation)
 */
function deactivateDelegation($delegationId)
{
    // Atomic operation için retry mekanizması
    $maxRetries = 3;
    $retryCount = 0;
    
    while ($retryCount < $maxRetries) {
        $delegations = readJsonFile(DELEGATIONS_FILE);
        $found = false;
        
        foreach ($delegations as &$delegation) {
            if ($delegation['id'] === $delegationId && $delegation['is_active']) {
                $delegation['is_active'] = false;
                $found = true;
                break;
            }
        }
        
        if ($found && writeJsonFile(DELEGATIONS_FILE, $delegations)) {
            return true;
        }
        
        $retryCount++;
        usleep(100000); // 100ms bekle
    }
    
    error_log("deactivateDelegation failed after $maxRetries retries for ID: $delegationId");
    return false;
}

/**
 * Yetki devrini iptal eder (atomic operation)
 */
function revokeDelegation($delegationId, $userId)
{
    // Atomic operation için retry mekanizması
    $maxRetries = 3;
    $retryCount = 0;
    
    while ($retryCount < $maxRetries) {
        $delegations = readJsonFile(DELEGATIONS_FILE);
        $found = false;
        
        foreach ($delegations as &$delegation) {
            if ($delegation['id'] === $delegationId && 
                $delegation['from_user_id'] === $userId && 
                $delegation['is_active']) {
                $delegation['is_active'] = false;
                $found = true;
                break;
            }
        }
        
        if ($found && writeJsonFile(DELEGATIONS_FILE, $delegations)) {
            return true;
        } elseif (!$found) {
            // Delegasyon bulunamadı veya zaten pasif
            return false;
        }
        
        $retryCount++;
        usleep(100000); // 100ms bekle
    }
    
    error_log("revokeDelegation failed after $maxRetries retries for ID: $delegationId");
    return false;
}

/**
 * Tarihi formatlar (güvenli)
 */
function formatDate($date)
{
    // Tarih formatını validate et
    if (empty($date) || !is_string($date)) {
        return 'Geçersiz tarih';
    }
    
    $timestamp = strtotime($date);
    if ($timestamp === false) {
        return 'Geçersiz tarih formatı';
    }
    
    // UTC zaman ile formatla
    return gmdate('d.m.Y', $timestamp);
}

/**
 * Tarih ve saati formatlar (güvenli)
 */
function formatDateTime($datetime)
{
    // DateTime formatını validate et
    if (empty($datetime) || !is_string($datetime)) {
        return 'Geçersiz tarih/saat';
    }
    
    $timestamp = strtotime($datetime);
    if ($timestamp === false) {
        return 'Geçersiz tarih/saat formatı';
    }
    
    // UTC zaman ile formatla
    return gmdate('d.m.Y H:i', $timestamp) . ' UTC';
}

/**
 * Session signature oluşturur (hijacking korunması)
 */
function generateSessionSignature($userId, $activeAsUserId = null)
{
    $data = $userId . '|' . ($activeAsUserId ?? $userId) . '|' . ($_SESSION['login_time'] ?? time());
    $secret = $_SESSION['session_secret'] ?? bin2hex(random_bytes(32));
    return hash_hmac('sha256', $data, $secret);
}

/**
 * Session signature doğrular
 */
function validateSessionSignature($userId, $activeAsUserId = null)
{
    $expected = generateSessionSignature($userId, $activeAsUserId);
    $provided = $_SESSION['session_signature'] ?? '';
    return hash_equals($expected, $provided);
}

/**
 * Güvenli session başlatma
 */
function initializeSecureSession($userId)
{
    $_SESSION['session_secret'] = bin2hex(random_bytes(32));
    $_SESSION['login_time'] = time();
    $_SESSION['session_signature'] = generateSessionSignature($userId);
}

/**
 * CSRF Token oluşturur (daha güvenli)
 */
function generateCSRFToken()
{
    if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time']) || 
        (time() - $_SESSION['csrf_token_time']) > 3600) { // 1 saat geçerlilik
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32)) . '_' . time() . '_' . uniqid();
        $_SESSION['csrf_token_time'] = time();
    }
    return $_SESSION['csrf_token'];
}

/**
 * CSRF Token doğrular
 */
function validateCSRFToken($token)
{
    if (!isset($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Yeni CSRF Token oluşturur (delayed refresh)
 */
function refreshCSRFToken($delay = false)
{
    if (!$delay) {
        // Anlık yenileme
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32)) . '_' . time() . '_' . uniqid();
        $_SESSION['csrf_token_time'] = time();
    } else {
        // Gecikmeli yenileme için flag set et
        $_SESSION['csrf_refresh_pending'] = true;
    }
    return $_SESSION['csrf_token'];
}

/**
 * CSRF korumalı form başlangıcı (per-form tokens)
 */
function getCSRFField($formName = 'default')
{
    $token = generateCSRFToken();
    $formToken = hash_hmac('sha256', $formName, $token);
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">' .
           '<input type="hidden" name="form_name" value="' . htmlspecialchars($formName) . '">';
}

/**
 * Form-specific CSRF token validation
 */
function validateFormCSRFToken($token, $formName = 'default')
{
    if (!isset($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    
    $expectedFormToken = hash_hmac('sha256', $formName, $_SESSION['csrf_token']);
    $providedFormToken = hash_hmac('sha256', $formName, $token);
    
    return hash_equals($expectedFormToken, $providedFormToken);
}

/**
 * Cache'i temizler (thread-safe)
 */
function clearCache($pattern = null)
{
    // Legacy static cache clear
    global $usersCache, $usersCacheTime, $delegationsCache, $delegationsCacheTime;
    global $rolesCache, $rolesCacheTime, $permissionsCache, $permissionsCacheTime;
    
    $usersCache = null;
    $usersCacheTime = 0;
    $delegationsCache = null;
    $delegationsCacheTime = 0;
    $rolesCache = null;
    $rolesCacheTime = 0;
    $permissionsCache = null;
    $permissionsCacheTime = 0;
    
    // Modern cache clear
    invalidateCache($pattern);
}

/**
 * Tarih formatını validate eder
 */
function validateDateFormat($date, $format = 'Y-m-d')
{
    if (empty($date) || !is_string($date)) {
        return false;
    }
    
    $dateTime = DateTime::createFromFormat($format, $date);
    return $dateTime && $dateTime->format($format) === $date;
}

/**
 * Tarih aralığını kontrol eder (UTC standardized)
 */
function validateDateRange($date, $minDate = null, $maxDate = null)
{
    $timestamp = strtotime($date . ' UTC');
    if ($timestamp === false) {
        return false;
    }
    
    if ($minDate) {
        $minTimestamp = strtotime($minDate . ' UTC');
        if ($timestamp < $minTimestamp) {
            return false;
        }
    }
    
    if ($maxDate) {
        $maxTimestamp = strtotime($maxDate . ' UTC');
        if ($timestamp > $maxTimestamp) {
            return false;
        }
    }
    
    return true;
}

/**
 * UTC zaman için helper fonksiyonlar
 */
function getCurrentUTCTime()
{
    return time(); // PHP'de time() zaten UTC
}

function getCurrentUTCDate()
{
    return gmdate('Y-m-d');
}

function getCurrentUTCDateTime()
{
    return gmdate('Y-m-d H:i:s');
}

/**
 * Delegasyon expiry check - UTC standardized
 */
function isDelegationExpired($expiryDate)
{
    $expiryTime = strtotime($expiryDate . ' 23:59:59 UTC');
    return $expiryTime < getCurrentUTCTime();
}

/**
 * Delegasyon expiry time calculator
 */
function getDelegationExpiryTime($expiryDate)
{
    return strtotime($expiryDate . ' 23:59:59 UTC');
}

// =====================================
// GÜÇLÜ INPUT VALIDATION
// =====================================

/**
 * Güçlü kullanıcı adı validasyonu
 */
function validateUsername($username)
{
    if (empty($username)) {
        return ['valid' => false, 'error' => 'Kullanıcı adı boş olamaz!'];
    }
    
    if (strlen($username) < 3 || strlen($username) > 20) {
        return ['valid' => false, 'error' => 'Kullanıcı adı 3-20 karakter arasında olmalı!'];
    }
    
    // Whitelist approach - sadece izin verilen karakterler
    if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$/', $username)) {
        return ['valid' => false, 'error' => 'Kullanıcı adı sadece harf, rakam, nokta, tire ve alt çizgi içerebilir!'];
    }
    
    // Reserved keywords kontrolü
    $reserved = ['admin', 'root', 'system', 'api', 'null', 'undefined', 'guest'];
    if (in_array(strtolower($username), $reserved)) {
        return ['valid' => false, 'error' => 'Bu kullanıcı adı kullanılamaz!'];
    }
    
    return ['valid' => true];
}

/**
 * Güçlü şifre validasyonu
 */
function validatePassword($password)
{
    if (empty($password)) {
        return ['valid' => false, 'error' => 'Şifre boş olamaz!'];
    }
    
    if (strlen($password) < 8) {
        return ['valid' => false, 'error' => 'Şifre en az 8 karakter olmalı!'];
    }
    
    if (strlen($password) > 128) {
        return ['valid' => false, 'error' => 'Şifre en fazla 128 karakter olabilir!'];
    }
    
    // Complexity requirements
    $patterns = [
        '/[a-z]/' => 'en az bir küçük harf',
        '/[A-Z]/' => 'en az bir büyük harf',
        '/[0-9]/' => 'en az bir rakam',
        '/[!@#$%^&*(),.?":{}|<>]/' => 'en az bir özel karakter'
    ];
    
    $missing = [];
    foreach ($patterns as $pattern => $requirement) {
        if (!preg_match($pattern, $password)) {
            $missing[] = $requirement;
        }
    }
    
    if (!empty($missing)) {
        return ['valid' => false, 'error' => 'Şifre ' . implode(', ', $missing) . ' içermelidir!'];
    }
    
    // Common password check
    $commonPasswords = ['12345678', 'password', 'qwerty123', 'admin123', '123456789'];
    if (in_array(strtolower($password), $commonPasswords)) {
        return ['valid' => false, 'error' => 'Bu şifre çok yaygın, lütfen daha güvenli bir şifre seçin!'];
    }
    
    return ['valid' => true];
}

/**
 * Tarih formatı validasyonu
 */
function validateDateInput($date)
{
    if (empty($date)) {
        return ['valid' => false, 'error' => 'Tarih boş olamaz!'];
    }
    
    // Strict format check
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
        return ['valid' => false, 'error' => 'Geçersiz tarih formatı! (YYYY-MM-DD)'];
    }
    
    // Valid date check
    $dateParts = explode('-', $date);
    if (!checkdate($dateParts[1], $dateParts[2], $dateParts[0])) {
        return ['valid' => false, 'error' => 'Geçersiz tarih!'];
    }
    
    // Future date check
    if (strtotime($date . ' UTC') <= getCurrentUTCTime()) {
        return ['valid' => false, 'error' => 'Bitiş tarihi bugünden sonra olmalı!'];
    }
    
    // Max 1 year limit
    if (strtotime($date . ' UTC') > strtotime('+1 year', getCurrentUTCTime())) {
        return ['valid' => false, 'error' => 'Bitiş tarihi en fazla 1 yıl sonrası olabilir!'];
    }
    
    return ['valid' => true];
}

/**
 * ID formatı validasyonu
 */
function validateId($id)
{
    if (empty($id)) {
        return ['valid' => false, 'error' => 'ID boş olamaz!'];
    }
    
    // Alphanumeric only
    if (!preg_match('/^[a-zA-Z0-9]{5,}$/', $id)) {
        return ['valid' => false, 'error' => 'Geçersiz ID formatı!'];
    }
    
    return ['valid' => true];
}

/**
 * Açıklama validasyonu
 */
function validateDescription($description)
{
    if (strlen($description) > 500) {
        return ['valid' => false, 'error' => 'Açıklama en fazla 500 karakter olabilir!'];
    }
    
    // XSS prevention - basic
    if (preg_match('/<[^>]*script/i', $description) || preg_match('/javascript:/i', $description)) {
        return ['valid' => false, 'error' => 'Girişte güvenlik riski tespit edildi!'];
    }
    
    return ['valid' => true];
}

/**
 * Rate limiting (simple implementation)
 */
function checkRateLimit($action, $identifier, $maxAttempts = 5, $timeWindow = 300)
{
    $cacheKey = "rate_limit_{$action}_{$identifier}";
    $attempts = getCacheValue($cacheKey, function() { return ['count' => 0, 'first_attempt' => getCurrentUTCTime()]; });
    
    // Reset if time window passed
    if (getCurrentUTCTime() - $attempts['first_attempt'] > $timeWindow) {
        $attempts = ['count' => 0, 'first_attempt' => getCurrentUTCTime()];
    }
    
    if ($attempts['count'] >= $maxAttempts) {
        return ['allowed' => false, 'retry_after' => $timeWindow - (getCurrentUTCTime() - $attempts['first_attempt'])];
    }
    
    // Increment counter
    $attempts['count']++;
    setCacheValue($cacheKey, $attempts, $timeWindow);
    
    return ['allowed' => true, 'remaining' => $maxAttempts - $attempts['count']];
}

// =====================================
// ERROR HANDLING VE EDGE CASES
// =====================================

/**
 * Güvenli hata loglama
 */
function logSecurityEvent($event, $details = [], $level = 'INFO')
{
    $logEntry = [
        'timestamp' => getCurrentUTCDateTime(),
        'event' => $event,
        'user_id' => $_SESSION['user_id'] ?? 'anonymous',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'details' => $details,
        'level' => $level
    ];
    
    $logFile = dirname(USERS_FILE) . '/security.log';
    $logLine = json_encode($logEntry) . PHP_EOL;
    
    file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
    
    // Critical events ayrıca error log'a
    if ($level === 'CRITICAL' || $level === 'WARNING') {
        error_log("Security Event [$level]: $event - " . json_encode($details));
    }
}

/**
 * Database integrity check
 */
function checkDataIntegrity()
{
    $issues = [];
    
    // Users integrity
    $users = readJsonFile(USERS_FILE);
    $userIds = [];
    
    foreach ($users as $user) {
        if (empty($user['id']) || empty($user['username'])) {
            $issues[] = 'Invalid user record found';
        }
        
        if (in_array($user['id'], $userIds)) {
            $issues[] = 'Duplicate user ID: ' . $user['id'];
        }
        
        $userIds[] = $user['id'];
    }
    
    // Delegations integrity
    $delegations = readJsonFile(DELEGATIONS_FILE);
    
    foreach ($delegations as $delegation) {
        if (empty($delegation['id']) || empty($delegation['from_user_id']) || empty($delegation['to_user_id'])) {
            $issues[] = 'Invalid delegation record found';
        }
        
        // Check if users exist
        if (!in_array($delegation['from_user_id'], $userIds)) {
            $issues[] = 'Delegation references non-existent from_user: ' . $delegation['from_user_id'];
        }
        
        if (!in_array($delegation['to_user_id'], $userIds)) {
            $issues[] = 'Delegation references non-existent to_user: ' . $delegation['to_user_id'];
        }
        
        // Self-delegation check
        if ($delegation['from_user_id'] === $delegation['to_user_id']) {
            $issues[] = 'Self-delegation detected: ' . $delegation['id'];
        }
    }
    
    // Roles integrity
    $roles = readJsonFile(ROLES_FILE);
    $roleIds = [];
    
    foreach ($roles as $role) {
        if (empty($role['id']) || empty($role['name'])) {
            $issues[] = 'Invalid role record found';
        }
        
        $roleIds[] = $role['id'];
    }
    
    // Check user role references
    foreach ($users as $user) {
        if (isset($user['role_id']) && !in_array($user['role_id'], $roleIds)) {
            $issues[] = 'User references non-existent role: ' . $user['username'] . ' -> ' . $user['role_id'];
        }
    }
    
    if (!empty($issues)) {
        logSecurityEvent('DATA_INTEGRITY_ISSUES', ['issues' => $issues], 'WARNING');
    }
    
    return $issues;
}

/**
 * Auto-cleanup expired delegations
 */
function cleanupExpiredDelegations()
{
    $delegations = readJsonFile(DELEGATIONS_FILE);
    $cleaned = 0;
    
    foreach ($delegations as &$delegation) {
        if ($delegation['is_active'] && isDelegationExpired($delegation['expiry_date'])) {
            $delegation['is_active'] = false;
            $cleaned++;
            
            logSecurityEvent('DELEGATION_EXPIRED', [
                'delegation_id' => $delegation['id'],
                'from_user' => $delegation['from_user_id'],
                'to_user' => $delegation['to_user_id'],
                'expiry_date' => $delegation['expiry_date']
            ]);
        }
    }
    
    if ($cleaned > 0) {
        writeJsonFile(DELEGATIONS_FILE, $delegations);
        clearCache('delegation');
    }
    
    return $cleaned;
}

/**
 * Memory usage monitoring
 */
function checkMemoryUsage()
{
    $usage = [
        'current' => memory_get_usage(true),
        'peak' => memory_get_peak_usage(true),
        'limit' => ini_get('memory_limit')
    ];
    
    // Convert to MB
    $usage['current_mb'] = round($usage['current'] / 1024 / 1024, 2);
    $usage['peak_mb'] = round($usage['peak'] / 1024 / 1024, 2);
    
    // Warning if over 80% of limit
    $limitBytes = return_bytes($usage['limit']);
    if ($usage['peak'] > ($limitBytes * 0.8)) {
        logSecurityEvent('HIGH_MEMORY_USAGE', $usage, 'WARNING');
    }
    
    return $usage;
}

/**
 * Helper function to convert memory limit string to bytes
 */
function return_bytes($val) {
    $val = trim($val);
    $last = strtolower($val[strlen($val)-1]);
    $val = intval($val);
    switch($last) {
        case 'g': $val *= 1024;
        case 'm': $val *= 1024;
        case 'k': $val *= 1024;
    }
    return $val;
}

/**
 * Heartbeat function - çalıştırılmalı
 */
function systemHeartbeat()
{
    // Cleanup expired delegations
    $cleanedCount = cleanupExpiredDelegations();
    
    // Check data integrity
    $integrityIssues = checkDataIntegrity();
    
    // Memory check
    $memoryUsage = checkMemoryUsage();
    
    // Log heartbeat
    logSecurityEvent('SYSTEM_HEARTBEAT', [
        'cleaned_delegations' => $cleanedCount,
        'integrity_issues_count' => count($integrityIssues),
        'memory_usage_mb' => $memoryUsage['current_mb']
    ]);
    
    return [
        'status' => 'ok',
        'cleaned_delegations' => $cleanedCount,
        'integrity_issues' => count($integrityIssues),
        'memory_usage' => $memoryUsage
    ];
}

// =====================================
// ROL VE YETKİ YÖNETİMİ FONKSİYONLARI
// =====================================

/**
 * Rol bilgisini ID'ye göre getirir
 */
function getRoleById($roleId)
{
    global $rolesCache, $rolesCacheTime;
    
    if ($rolesCache === null || (time() - $rolesCacheTime) > CACHE_TTL) {
        $rolesCache = readJsonFile(ROLES_FILE);
        $rolesCacheTime = time();
    }
    
    foreach ($rolesCache as $role) {
        if ($role['id'] === $roleId) {
            return $role;
        }
    }
    
    return false;
}

/**
 * Tüm rolleri getirir
 */
function getAllRoles()
{
    global $rolesCache, $rolesCacheTime;
    
    if ($rolesCache === null || (time() - $rolesCacheTime) > CACHE_TTL) {
        $rolesCache = readJsonFile(ROLES_FILE);
        $rolesCacheTime = time();
    }
    
    return $rolesCache;
}

/**
 * İzin bilgisini name'e göre getirir
 */
function getPermissionByName($permissionName)
{
    global $permissionsCache, $permissionsCacheTime;
    
    if ($permissionsCache === null || (time() - $permissionsCacheTime) > CACHE_TTL) {
        $permissionsCache = readJsonFile(PERMISSIONS_FILE);
        $permissionsCacheTime = time();
    }
    
    foreach ($permissionsCache as $permission) {
        if ($permission['name'] === $permissionName) {
            return $permission;
        }
    }
    
    return false;
}

/**
 * Tüm izinleri getirir
 */
function getAllPermissions()
{
    global $permissionsCache, $permissionsCacheTime;
    
    if ($permissionsCache === null || (time() - $permissionsCacheTime) > CACHE_TTL) {
        $permissionsCache = readJsonFile(PERMISSIONS_FILE);
        $permissionsCacheTime = time();
    }
    
    return $permissionsCache;
}

/**
 * Kullanıcının sahip olduğu tüm izinleri getirir (rol + delegasyon)
 */
function getUserPermissions($userId, $activeAsUserId = null)
{
    $user = getUserById($userId);
    if (!$user) {
        return [];
    }
    
    $permissions = [];
    
    // 1. Kullanıcının kendi rol izinlerini al
    if (isset($user['role_id'])) {
        $role = getRoleById($user['role_id']);
        if ($role && isset($role['permissions'])) {
            if (in_array('*', $role['permissions'])) {
                // Super admin - tüm izinler
                $allPerms = getAllPermissions();
                foreach ($allPerms as $perm) {
                    $permissions[] = $perm['name'];
                }
            } else {
                $permissions = array_merge($permissions, $role['permissions']);
            }
        }
    }
    
    // 2. Eğer başka biri adına işlem yapıyorsa, delegasyon izinlerini al
    if ($activeAsUserId && $activeAsUserId !== $userId) {
        $delegationPerms = getDelegatedPermissions($userId, $activeAsUserId);
        $permissions = $delegationPerms; // Delegasyon sadece belirlenen izinler
    }
    
    return array_unique($permissions);
}

/**
 * Kullanıcının belirli bir izni var mı kontrol eder
 */
function hasPermission($userId, $permission, $activeAsUserId = null)
{
    $userPermissions = getUserPermissions($userId, $activeAsUserId);
    return in_array($permission, $userPermissions);
}

/**
 * Delegasyondan gelen izinleri getirir
 */
function getDelegatedPermissions($userId, $fromUserId)
{
    $delegations = readJsonFile(DELEGATIONS_FILE);
    
    foreach ($delegations as $delegation) {
        if ($delegation['to_user_id'] === $userId && 
            $delegation['from_user_id'] === $fromUserId && 
            $delegation['is_active']) {
            
            // Tarihi kontrol et
            $expiryTime = strtotime($delegation['expiry_date'] . ' 23:59:59 UTC');
            if ($expiryTime >= time()) {
                return $delegation['delegated_permissions'] ?? [];
            }
        }
    }
    
    return [];
}

/**
 * Kullanıcının devredebileceği izinleri getirir
 */
function getUserDelegatablePermissions($userId)
{
    // Kullanıcı sadece sahip olduğu izinleri devredebilir
    return getUserPermissions($userId);
}

/**
 * İzin kontrolü middleware
 */
function requirePermission($userId, $permission, $activeAsUserId = null)
{
    if (!hasPermission($userId, $permission, $activeAsUserId)) {
        http_response_code(403);
        die(json_encode([
            'error' => 'Bu işlem için yeterli yetkiniz bulunmamaktadır.',
            'required_permission' => $permission
        ]));
    }
    return true;
}

/**
 * Döngüsel delegasyon kontrolü (A→B→A)
 */
function hasCircularDelegation($fromUserId, $toUserId, $visited = []) 
{
    // Sonsuz döngü korunması
    if (count($visited) > 20) {
        return true; // Çok derin delegasyon zinciri
    }
    
    // Circular dependency check
    if (in_array($fromUserId, $visited)) {
        return true; // Döngü tespit edildi
    }
    
    $visited[] = $fromUserId;
    
    // $toUserId'nin aktif delegasyonlarını kontrol et
    $delegations = readJsonFile(DELEGATIONS_FILE);
    
    foreach ($delegations as $delegation) {
        if ($delegation['from_user_id'] === $toUserId && $delegation['is_active']) {
            // Tarihi kontrol et
            $expiryTime = strtotime($delegation['expiry_date'] . ' 23:59:59 UTC');
            if ($expiryTime >= time()) {
                // Bu kullanıcı başkasına yetki devrediyor, ona da bak
                if (hasCircularDelegation($delegation['to_user_id'], $fromUserId, $visited)) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

// =====================================
// PERFORMANS OPTİMİZASYONU FONKSİYONLARI
// =====================================

/**
 * Tüm permissions'ları map olarak yükler (N+1 çözümü)
 */
function loadAllPermissionsMap()
{
    static $permMap = null;
    static $loadTime = 0;
    
    if ($permMap === null || (time() - $loadTime) > CACHE_TTL) {
        $permMap = [];
        $perms = getAllPermissions();
        foreach ($perms as $perm) {
            $permMap[$perm['name']] = $perm;
        }
        $loadTime = time();
    }
    
    return $permMap;
}

/**
 * Tüm users'ları map olarak yükler
 */
function loadAllUsersMap()
{
    static $userMap = null;
    static $loadTime = 0;
    
    if ($userMap === null || (time() - $loadTime) > CACHE_TTL) {
        $userMap = [];
        $users = readJsonFile(USERS_FILE);
        foreach ($users as $user) {
            $userMap[$user['id']] = $user;
        }
        $loadTime = time();
    }
    
    return $userMap;
}

/**
 * Bulk permission name resolution (N+1 çözümü)
 */
function resolvePermissionNames($permissionNames)
{
    if (empty($permissionNames)) {
        return [];
    }
    
    $permMap = loadAllPermissionsMap();
    $resolved = [];
    
    foreach ($permissionNames as $permName) {
        if (isset($permMap[$permName])) {
            $resolved[] = $permMap[$permName]['display_name'];
        } else {
            $resolved[] = $permName;
        }
    }
    
    return $resolved;
}

/**
 * Bulk user name resolution
 */
function resolveUserNames($userIds)
{
    if (empty($userIds)) {
        return [];
    }
    
    $userMap = loadAllUsersMap();
    $resolved = [];
    
    foreach ($userIds as $userId) {
        if (isset($userMap[$userId])) {
            $resolved[$userId] = $userMap[$userId]['username'];
        } else {
            $resolved[$userId] = 'Bilinmeyen Kullanıcı';
        }
    }
    
    return $resolved;
}

/**
 * Kullanıcının rolünü günceller
 */
function updateUserRole($userId, $roleId)
{
    $users = readJsonFile(USERS_FILE);
    $updated = false;
    
    foreach ($users as &$user) {
        if ($user['id'] === $userId) {
            $user['role_id'] = $roleId;
            $user['updated_at'] = gmdate('Y-m-d H:i:s');
            $updated = true;
            break;
        }
    }
    
    if ($updated && writeJsonFile(USERS_FILE, $users)) {
        clearCache();
        return true;
    }
    
    return false;
}

/**
 * Kullanıcının durumunu günceller
 */
function updateUserStatus($userId, $status)
{
    $users = readJsonFile(USERS_FILE);
    $updated = false;
    
    foreach ($users as &$user) {
        if ($user['id'] === $userId) {
            $user['status'] = $status;
            $user['updated_at'] = gmdate('Y-m-d H:i:s');
            $updated = true;
            break;
        }
    }
    
    if ($updated && writeJsonFile(USERS_FILE, $users)) {
        clearCache();
        return true;
    }
    
    return false;
}

/**
 * Kullanıcının başkasına verdiği aktif yetki devri var mı kontrol eder
 */
function hasActiveOutgoingDelegation($userId)
{
    $delegations = readJsonFile(DELEGATIONS_FILE);

    foreach ($delegations as $delegation) {
        if ($delegation['from_user_id'] === $userId && $delegation['is_active']) {
            // Tarihi kontrol et (UTC standardized)
            if (!isDelegationExpired($delegation['expiry_date'])) {
                return $delegation; // Aktif giden delegasyon var
            }
        }
    }

    return false; // Aktif giden delegasyon yok
}

/**
 * Kullanıcının işlem yapmasına izin verilip verilmediğini kontrol eder
 */
function canUserPerformActions($userId)
{
    $activeDelegation = hasActiveOutgoingDelegation($userId);
    if ($activeDelegation) {
        $toUser = getUserById($activeDelegation['to_user_id']);
        // Güvenlik için detaylı bilgi log'a yazılır
        error_log("User $userId blocked due to active delegation to " . $activeDelegation['to_user_id'] . ", expires: " . $activeDelegation['expiry_date']);
        
        return [
            'allowed' => false,
            'message' => 'Aktif bir yetki delegasyonunuz bulunduğu için işlem yapamazsınız. Lütfen önce mevcut yetkiyi sonlandırın.',
            'delegation' => $activeDelegation
        ];
    }

    return ['allowed' => true];
}
