# Enterprise-Grade PHP Yetki Delegasyon Sistemi

**Yazar:** A. Kerem Gök  
**Versiyon:** 2.0 (Production-Ready)

## 🚀 Sistem Özellikleri

✅ **Role-Based Access Control (RBAC)**

- 4 seviyeli rol sistemi: Super Admin, Admin, Manager, User
- 11 ayrı yetki kategorisi (sistem, delegasyon, raporlar, profil)
- Seçici yetki devri: Kullanıcılar sadece istedikleri yetkileri devredebilir
- Yetki kalıtımı: Sadece sahip olunan yetkiler devredilebilir

✅ **Gelişmiş Güvenlik Sistemi**

- **Bcrypt Password Hashing:** Şifreler güvenli olarak hash'lenir
- **Session Hijacking Korunması:** İmza tabanlı session validasyonu
- **CSRF Koruması:** Her form için benzersiz token'lar
- **Rate Limiting:** Giriş ve kayıt denemelerine limit
- **Input Validation:** Kapsamlı girdi doğrulama ve sanitizasyon
- **Güvenlik Event Logging:** Tüm kritik işlemler loglanır

✅ **Atomic İşlem Sistemi**

- **File Locking:** Eş zamanlı işlemlerde veri bütünlüğü
- **Circular Delegation Prevention:** A→B→C→A döngüsü engellenir  
- **Transaction Safety:** Başarısız işlemlerde rollback
- **Data Integrity Checks:** Otomatik veri tutarlılık kontrolü

✅ **Performans ve Ölçeklenebilirlik**

- **Two-Tier Caching:** APCu in-memory + file fallback
- **N+1 Query Prevention:** Bulk loading patterns
- **Memory Monitoring:** %80 üzerinde uyarı sistemi
- **Auto-Cleanup:** Süresi dolan delegasyonlar otomatik temizlenir

✅ **Monitoring ve İzleme**

- **Real-time System Status:** Anlık sistem metrikleri
- **Security Dashboard:** Güvenlik olayları takibi
- **Data Integrity Monitoring:** Veri tutarlılık raporları
- **Performance Metrics:** Bellek kullanımı ve cache istatistikleri

✅ **Advanced Authority Management**

- **Authority Switching:** Başkası adına işlem yapabilme
- **Permission Inheritance:** Yetki zinciri yönetimi
- **Delegation Blocking:** Aktif delegasyon varsa kendi adına işlem engellenir
- **Expiry Management:** UTC tabanlı tarih yönetimi

## Kurulum

### Gereksinimler

- PHP 7.0 veya üzeri
- Web sunucu (Apache/Nginx)
- JSON dosyalarını yazabilecek klasör izinleri

### Kurulum Adımları

1. **Dosyaları web sunucunuza yükleyin**

```bash
# Proje dosyalarını web sunucu dizinine kopyalayın
cp -r vekalet/ /var/www/html/
```

2. **Klasör izinlerini ayarlayın**

```bash
# Data klasörü için yazma iznini verin
chmod 755 /var/www/html/vekalet/
chmod 777 /var/www/html/vekalet/data/
```

3. **Web tarayıcınızda açın**

```
http://localhost/vekalet/
```

## 🏗️ Sistem Mimarisi

```
vekalet/
├── index.php          # Ana giriş sayfası
├── register.php       # Kullanıcı kayıt sayfası  
├── login.php          # Giriş işlemi
├── logout.php         # Çıkış işlemi
├── dashboard.php      # Ana kontrol paneli (yetki yönetimi)
├── admin.php          # Admin paneli (kullanıcı/rol yönetimi)
├── system-status.php  # Sistem izleme dashboard'u
├── functions.php      # Core sistem fonksiyonları (1500+ satır)
├── style.css          # Modern CSS stilleri
├── CLAUDE.md          # Development guide for Claude Code
├── README.md          # Bu dosya
└── data/              # JSON veri storage (secure permissions)
    ├── users.json     # User accounts + role assignments
    ├── roles.json     # Role definitions + permissions  
    ├── permissions.json # Granular permission system
    ├── delegations.json # Authority delegation records
    └── security.log   # Security event logging
```

### 🔧 Core System Components

**Authentication Layer:**

- Bcrypt password hashing + session signature validation
- Rate limiting + CSRF protection
- Security event logging

**Authorization Engine:**  

- Role-based access control (RBAC)
- Granular permission system (11 permissions, 4 categories)
- Selective permission delegation

**Data Layer:**

- Atomic file operations with locking
- Two-tier caching (APCu + file fallback)
- Auto-cleanup + integrity checking

## Kullanım

### 1. 👤 Kullanıcı Yönetimi

**Kayıt (register.php):**

- Güçlü şifre gereksinimleri (8+ karakter, büyük/küçük harf, rakam, özel karakter)
- Kullanıcı adı benzersizlik kontrolü
- Rate limiting korunması

**Giriş (index.php → login.php):**

- Bcrypt şifre doğrulaması
- Session hijacking korunması
- Başarısız girişim logging'i

### 2. 🎯 Role-Based Yetki Sistemi

**Roller:**

- **Super Admin:** Tüm sistem yetkilerine sahip
- **Admin:** Kullanıcı yönetimi + genel admin yetkiler
- **Manager:** Takım yönetimi + rapor yetkiler
- **User:** Temel kullanıcı yetkiler + profil düzenleme

**Admin Panel (admin.php):**

- Kullanıcı rol atama/değiştirme
- Kullanıcı durumu yönetimi (aktif/pasif)
- Rol ve yetki matrisi görüntüleme

### 3. ⚡ Gelişmiş Yetki Delegasyonu

**Seçici Yetki Devri:**

- Sadece sahip olunan yetkiler devredilir
- Kategori bazında yetki seçimi (sistem, delegasyon, raporlar, profil)
- Yetki açıklama ve bitiş tarihi zorunlu

**Authority Switching:**

- Aldığınız yetkilerle başka kullanıcı adına işlem yapma
- Mavi uyarı ile aktif yetki gösterimi
- "Kendi Adıma Dön" ile hızlı geçiş

**Delegation Blocking:**

- Aktif yetki devri varsa kendi adına işlem engellenir
- Kırmızı uyarı + "Yetkiyi Sonlandır" butonu
- Form görsel devre dışı bırakma

### 4. 📊 Sistem İzleme (system-status.php)

**Real-time Metrics:**

- Kullanıcı ve delegasyon istatistikleri
- Bellek kullanımı ve cache durumu
- PHP ve sistem bilgileri

**Security Dashboard:**

- Son 24 saat güvenlik olayları
- Başarısız giriş denemeleri
- Kritik işlem logları

**Data Integrity:**

- Otomatik veri tutarlılık kontrolü
- Eksik referans tespiti
- Manual sistem kontrolü tetikleme

### 5. 🔧 Maintenance Operations

**System Heartbeat:**

- Süresi dolmuş delegasyonlar otomatik temizlenir
- Veri bütünlüğü kontrolü yapılır
- Bellek kullanımı monitör edilir
- Güvenlik olayları loglanır

## 📊 Data Schema

### users.json (Enhanced)

```json
[
    {
        "id": "user001",
        "username": "admin",
        "password": "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
        "role_id": "role001",
        "status": "active",
        "created_at": "2024-01-15 10:30:00"
    }
]
```

### roles.json (New)

```json
[
    {
        "id": "role001",
        "name": "super_admin",
        "display_name": "Sistem Yöneticisi",
        "description": "Tüm yetkilere sahip sistem yöneticisi",
        "permissions": ["*"],
        "created_at": "2024-01-01 00:00:00"
    }
]
```

### permissions.json (New)

```json
[
    {
        "id": "perm003",
        "name": "delegation_create",
        "display_name": "Yetki Devri Oluşturma",
        "description": "Yeni yetki devri oluşturabilme",
        "category": "delegation"
    }
]
```

### delegations.json (Enhanced)

```json
[
    {
        "id": "del001",
        "from_user_id": "user002",
        "to_user_id": "user003",
        "expiry_date": "2024-12-31",
        "description": "Yıl sonu işlemleri için yetki devri",
        "delegated_permissions": [
            "delegation_create",
            "delegation_view_own",
            "reports_view"
        ],
        "created_at": "2024-01-20 11:30:00",
        "is_active": true
    }
]
```

## 🔐 Production Security Features

✅ **IMPLEMENTED SECURITY CONTROLS:**

**Authentication Security:**

- ✅ **Bcrypt Password Hashing** - Güvenli şifre saklama
- ✅ **Session Signature Validation** - Hijacking korunması
- ✅ **Rate Limiting** - Brute force korunması
- ✅ **Account Status Control** - Pasif hesap engelleme

**Authorization Security:**

- ✅ **Role-Based Access Control** - Granüler yetki kontrolü
- ✅ **Permission Inheritance Validation** - Yetki escalation korunması
- ✅ **Real-time Permission Checks** - Her işlem öncesi doğrulama
- ✅ **Circular Delegation Prevention** - Döngüsel yetki korunması

**Input/Output Security:**

- ✅ **Comprehensive Input Validation** - Whitelist yaklaşımı
- ✅ **XSS Prevention** - htmlspecialchars() ile output encoding
- ✅ **CSRF Protection** - Form-specific token validation
- ✅ **File Path Validation** - Directory traversal korunması

**Data Security:**

- ✅ **Atomic File Operations** - Race condition korunması
- ✅ **File Locking Mechanisms** - Concurrent access control
- ✅ **Secure File Permissions** - 600/700 permissions
- ✅ **Data Integrity Monitoring** - Otomatik tutarlılık kontrolü

**Monitoring & Logging:**

- ✅ **Security Event Logging** - Tüm kritik işlemler
- ✅ **Failed Login Tracking** - Başarısız giriş takibi
- ✅ **System Health Monitoring** - Real-time metrics
- ✅ **Memory Usage Alerts** - Resource monitoring

**Operational Security:**

- ✅ **UTC Time Standardization** - Timezone attack korunması
- ✅ **Auto-cleanup Mechanisms** - Expired data removal
- ✅ **Error Handling** - Information disclosure korunması
- ✅ **Configuration Hardening** - Secure defaults

🚀 **PRODUCTION READY:** Bu sistem enterprise ortamda kullanılabilir seviyededir.

## ⚡ Technical Stack

**Backend:**

- **PHP 7.0+** - Core application logic (1500+ lines)
- **JSON File Storage** - No database required
- **APCu + File Caching** - Two-tier performance optimization
- **File Locking** - Atomic operations for data integrity

**Frontend:**

- **Modern CSS3** - Gradient design system
- **Responsive Layout** - Mobile-optimized interface
- **Progressive Enhancement** - Works without JavaScript

**Security Framework:**

- **bcrypt** - Password hashing
- **HMAC** - Token validation
- **File Permissions** - System-level security
- **Input Validation** - Comprehensive filtering

## 🚀 Performance Features

- **N+1 Query Prevention** - Bulk loading patterns
- **Memory Monitoring** - Resource usage alerts
- **Auto-cleanup** - Background maintenance
- **Static Caching** - In-memory data retention
- **Atomic Operations** - Race condition prevention

## 🔧 Development & Deployment

### Local Development

```bash
# Start PHP development server
php -S localhost:8000

# Monitor security logs
tail -f data/security.log

# Check system status
curl http://localhost:8000/system-status.php
```

### Production Deployment

```bash
# Set secure file permissions
chmod 755 /var/www/html/vekalet/
chmod 700 /var/www/html/vekalet/data/
chmod 600 /var/www/html/vekalet/data/*.json

# Configure web server (Apache example)
<Directory "/var/www/html/vekalet/data">
    Order Deny,Allow
    Deny from all
</Directory>
```

### Monitoring & Maintenance

- **System Status Dashboard:** `system-status.php`
- **Security Event Logs:** `data/security.log`
- **Data Integrity Checks:** Automated + manual triggers
- **Cache Statistics:** APCu metrics + file cache status

## 📈 Scalability Notes

**Current Architecture:**

- Handles ~1000 users efficiently
- File locking prevents corruption under load
- APCu caching reduces I/O overhead
- Memory usage monitoring prevents resource exhaustion

**Enterprise Scaling Options:**

- Replace JSON files with PostgreSQL/MySQL
- Add Redis for distributed caching
- Implement horizontal load balancing
- Add message queuing for background tasks

---
**Geliştirici:** A. Kerem Gök  
**Versiyon:** 2.0 (Production-Ready)  
**Tarih:** 2024

**Status:** ✅ Enterprise-grade security • ✅ Production-ready • ✅ Fully documented
