# Ücretsiz Gelir Gider Takip Programı

Windows ve Linux için ücretsiz, kişisel gelir-gider ve bütçe takip uygulaması. Gelir ve giderleri izler; fatura, fiş veya şirket muhasebesi işlemleri yapmaz.

## SON SÜRÜM v3.0.0 — WINDOWS VE LINUX İNDİR

- [WINDOWS sürümünü indir (ZIP)](https://github.com/sarmasaicode/basit-ev-muhasebe/releases/download/v3.0.0/Basit-Ev-Muhasebe-WINDOWS-v3.0.0.zip)
- [LINUX sürümünü indir (ZIP)](https://github.com/sarmasaicode/basit-ev-muhasebe/releases/download/v3.0.0/Basit-Ev-Muhasebe-LINUX-v3.0.0.zip)

Eski beta indirmeleri tamamlanmamış oldukları için kaldırılmıştır. ZIP'i tamamen ve yazma izni olan bir klasöre çıkartın. Windows'ta `CALISTIR\CALISTIR.exe`, Linux'ta `CALISTIR_LINUX.sh` ile açın. İlk kullanımda yönetici hesabını oluşturun. Windows ZIP'indeki `KISAYOL_OLUSTUR.vbs` masaüstü kısayolu oluşturur.

## Özellikler

- Gelir ve gider ekleme, kayıtları düzenleme ve filtreleme
- Kategoriler oluşturma ve yönetme
- Gelir-gider özeti, bakiye ve kategori grafikleri
- Günlük, aylık ve yıllık raporlar; A4 PDF çıktısı
- Kişilerim ve bağışçı listeleri; bağışçı bilgilerini düzeltme veya silme
- Kişi bilgilerini düzenleme ve kişiyi listeden kaldırma
- Sabit bağışçılar için 12 aylık ödeme takibi
- Yönetici hesabı ve en fazla **5 ek kullanıcı** oluşturma
- Kullanıcı başına görüntüleme, yeni kayıt, düzeltme ve silme izinleri
- Kullanıcı yetkilerini değiştirme veya hesabı kaldırma
- Yedekleme ve yedekten geri yükleme
- Boşta kalınca oturum kilidi ve kurtarma kodu
- Yerel muhasebe kayıtları için AES-GCM şifreleme

## Kaynak kodunu çalıştırma

Python 3.10 veya üzeri ve Tkinter gerekir:

```bash
python -m pip install -r requirements.txt
python basit_ev_muhasebe.py
```

## Kayıt güvenliği

Program kayıtları uygulamanın yanındaki `veriler/` klasöründe tutar ve şifreler. Güncellemeden önce **Yedek Al** kullanın; güncellemede `veriler/` klasörünü koruyun. Gerçek kayıt dosyalarını GitHub'a yüklemeyin. Bu proje logosuz ve genel kullanıma yönelik sürümdür.

## Lisans

MIT License. Kullanıcı eklediği görsellerin ve içeriklerin haklarını ayrıca doğrulamalıdır.
