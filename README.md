# PHP JSON Tabanlı Kullanıcı Yetki Sistemi

**Yazar:** A. Kerem Gök

## Özellikler

✅ **Kullanıcı Kayıt ve Giriş Sistemi**

- Kullanıcı adı ve şifre ile güvenli giriş
- Kayıt sırasında kullanıcı adı tekrarı kontrolü
- Şifre plain text olarak saklanır (istenen özellik)

✅ **Yetki Devri Sistemi**

- Kullanıcılar yetkilerini diğer kullanıcılara devredebilir
- Yetki devri için bitiş tarihi belirlenir
- Opsiyonel açıklama alanı
- **Tek Aktif Yetki Kuralı:** Bir kullanıcı aynı kişiye aynı anda sadece bir aktif yetki verebilir

✅ **Yetki Yönetimi**

- Kullanıcılar verdiği yetkileri görüntüleyebilir ve iptal edebilir
- Kullanıcılar aldığı aktif yetkileri görüntüleyebilir
- Otomatik tarih kontrolü ve süresi dolan yetkilerin pasifleştirilmesi
- **Yetki Engelleme:** Aktif yetki devri olan kullanıcı önce yetkiyi sonlandırmalı

✅ **Modern Kullanıcı Arayüzü**

- Responsive tasarım
- Gradient renkler ve modern görünüm
- Hover efektleri ve animasyonlar

✅ **Güvenlik Özellikleri**

- **CSRF Koruması:** Tüm formlar Cross-Site Request Forgery saldırılarına karşı korumalı
- **Token Tabanlı Güvenlik:** Her form gönderiminde benzersiz güvenlik token'ı kontrolü
- **Otomatik Token Yenileme:** Başarılı işlemler sonrası token'lar otomatik yenilenir

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

## Dosya Yapısı

```
vekalet/
├── index.php          # Ana giriş sayfası
├── register.php       # Kullanıcı kayıt sayfası
├── login.php          # Giriş işlemi
├── logout.php         # Çıkış işlemi
├── dashboard.php      # Ana kontrol paneli
├── functions.php      # Sistem fonksiyonları
├── style.css          # CSS stilleri
├── README.md          # Bu dosya
└── data/              # JSON veri dosyaları (otomatik oluşur)
    ├── users.json     # Kullanıcı bilgileri
    └── delegations.json # Yetki devir bilgileri
```

## Kullanım

### 1. Kullanıcı Kaydı

- `register.php` sayfasından yeni kullanıcı oluşturun
- Kullanıcı adı tekrarı otomatik kontrol edilir
- Minimum 3 karakter kullanıcı adı, 6 karakter şifre gereklidir

### 2. Giriş Yapma

- Ana sayfadan kullanıcı adı ve şifre ile giriş yapın
- Başarılı girişte dashboard'a yönlendirilirsiniz

### 3. Yetki Devretme

- Dashboard'da "Yetki Devret" bölümünden:
  - Hedef kullanıcıyı seçin
  - Bitiş tarihi belirleyin (bugünden sonra olmalı)
  - İsteğe bağlı açıklama ekleyin
  - "Yetki Devret" butonuna tıklayın

### 4. Yetki Yönetimi

- **Verdiğim Yetkiler:** Devrettiğiniz aktif yetkileri görün ve iptal edin
- **Aldığım Yetkiler:** Size devredilen aktif yetkileri görün

### 5. Yetki Kullanımı (YENİ ÖZELLİK!)

- **Yetki Seçimi:** Size devredilen yetkilerden birini seçerek o kullanıcı adına işlem yapabilirsiniz
- **Yetki Değiştirme:** "Yetki Kullanımı" bölümünden hangi kullanıcı adına işlem yapmak istediğinizi seçin
- **Aktif Yetki:** Seçili yetki mavi bilgi kutusunda gösterilir
- **Kendi Adına Dönme:** İstediğiniz zaman "Kendi Adıma Dön" butonuyla kendi hesabınıza dönebilirsiniz
- **Yetki ile İşlemler:** Seçili yetki ile o kullanıcı adına yeni yetki devredebilir veya o kullanıcının verdiği yetkileri iptal edebilirsiniz

### 6. Yetki Engelleme Sistemi (YENİ ÖZELLİK!)

- **Otomatik Engelleme:** Başkasına aktif yetki devri yapmış kullanıcılar kendi adlarına işlem yapamazlar
- **Görsel Uyarı:** Kırmızı uyarı kutusu ile net bilgilendirme yapılır
- **Hızlı Sonlandırma:** "Yetkiyi Sonlandır" butonu ile tek tıkla yetki iptal edilebilir
- **Form Devre Dışı:** Yetki devri formu görsel olarak pasifleştirilir
- **Güvenlik:** Kullanıcı önce mevcut yetkiyi sonlandırmak zorundadır

### 7. Çıkış

- Sağ üst köşedeki "Çıkış Yap" butonunu kullanın

## Veri Yapısı

### users.json

```json
[
    {
        "id": "unique_id",
        "username": "kullanici_adi",
        "password": "plain_text_sifre",
        "created_at": "2024-01-01 12:00:00"
    }
]
```

### delegations.json

```json
[
    {
        "id": "unique_id",
        "from_user_id": "veren_kullanici_id",
        "to_user_id": "alan_kullanici_id",
        "expiry_date": "2024-12-31",
        "description": "Açıklama",
        "created_at": "2024-01-01 12:00:00",
        "is_active": true
    }
]
```

## Güvenlik Notları

✅ **Eklenen Güvenlik Özellikleri:**

- **CSRF Koruması:** Tüm formlar Cross-Site Request Forgery saldırılarına karşı korumalı
- **Token Tabanlı Doğrulama:** Benzersiz güvenlik token'ları ile form güvenliği

⚠️ **Önemli:** Bu sistem eğitim amaçlıdır. Üretim ortamında kullanmadan önce:

- Şifreleri hash'leyin (bcrypt kullanın)
- CSRF koruması ekleyin
- Input validasyonunu güçlendirin
- HTTPS kullanın
- Session güvenliğini artırın
- Rate limiting ekleyin
- SQL Injection koruması (veritabanı kullanıyorsanız)

## Teknik Özellikler

- **PHP:** Sunucu tarafı mantık
- **JSON:** Veri saklama (veritabanı gerekmez)
- **CSS3:** Modern görsel tasarım
- **Responsive:** Mobil uyumlu
- **Session:** Kullanıcı oturum yönetimi

## Özelleştirme

### Tema Değişikliği

`style.css` dosyasındaki gradient renklerini değiştirerek farklı temalar oluşturabilirsiniz:

```css
/* Ana gradient */
background: linear-gradient(135deg, #YENİ_RENK1 0%, #YENİ_RENK2 100%);
```

### Yeni Özellikler Ekleme

`functions.php` dosyasına yeni fonksiyonlar ekleyerek sistemi genişletebilirsiniz.

## Sorun Giderme

### Data klasörü oluşturulmuyor

```bash
mkdir data
chmod 777 data
```

### JSON dosyaları yazılamıyor

```bash
chmod 777 data/
```

### Sayfa yüklenmiyor

- PHP'nin aktif olduğundan emin olun
- Web sunucu loglarını kontrol edin

## Katkıda Bulunma

Bu proje eğitim amaçlı geliştirilmiştir. Önerilerinizi ve geliştirmelerinizi paylaşabilirsiniz.

---
**Geliştirici:** A. Kerem Gök  
**Versiyon:** 1.0  
**Tarih:** 2024
