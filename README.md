# Basit Ev Muhasebe Programı

Ev ve kişisel bütçesini takip etmek isteyenler için Türkçe masaüstü uygulaması. Gelir ve giderleri kaydeder, özetler, raporlar ve çıktı alınmasını sağlar. **Fatura veya fiş kesmez; şirket muhasebesi ya da vergi beyanı yazılımı değildir.**

## Windows V2'yi indir

Windows'ta Python kurmadan kullanmak için [V2 Windows taşınabilir sürümünü indir](https://github.com/sarmasaicode/basit-ev-muhasebe/releases/tag/v2.0.0-beta.1). Açılan sayfada **Temiz.yedek.muhasebe.v2.zip** dosyasını indirin. ZIP'i tamamen çıkartın ve içindeki **CALISTIR/CALISTIR.exe** dosyasını çalıştırın. CALISTIR klasöründeki diğer dosyaları EXE'den ayırmayın.

**Önemli:** Yayın sayfasındaki “Source code (zip)” ve “Source code (tar.gz)” bağlantıları GitHub tarafından kaynak kodu için otomatik oluşturulur; Windows'ta doğrudan çalıştırılan uygulama paketi değildir.

## Linux V2'yi indir

[Linux taşınabilir paketini indir](https://github.com/sarmasaicode/basit-ev-muhasebe/releases/download/v2.0.0-beta.2/Basit-Ev-Muhasebe-Linux-v2.0.0-beta.2.zip). ZIP'i yazma izniniz olan bir klasöre çıkartın ve **CALISTIR_LINUX.sh** dosyasını çalıştırın. Dosya yöneticisi çalıştırmayı engellerse terminalde **./CALISTIR_LINUX.sh** komutunu kullanın.

Bu paket Ubuntu 22.04 x86_64 üzerinde derlendi. Açılışı CachyOS x86_64 üzerinde doğrulandı. İlk açılışta kendi kullanıcı hesabınızı oluşturun. Veriler, çalıştırılan programın yanındaki **veriler/** klasörüne yazılır. PDF raporları kaydedilir; fiziksel yazdırma için PDF görüntüleyicisini kullanın.

**Not:** Yayın sayfasındaki “Source code” dosyaları Linux uygulama paketi değildir.

Sorular ve iletişim: **sarmas.aicode@gmail.com**

## Özellikler

- Gelir ve gider ekleme, kayıtları düzenleme ve tarihe göre filtreleme
- Kategoriler oluşturma ve yönetme
- Gelir-gider genel bakışı, bakiye ve kategori dağılımı grafikleri
- Günlük, aylık ve yıllık dönem raporları
- A4 PDF raporu oluşturma; Windows'ta yazıcı veya PDF, Linux'ta PDF kaydetme
- Kişi ve iletişim bilgileri listesi; isteğe bağlı bağışçı ve aylık bağış takibi
- Kişi listesinden seçili e-posta adresleriyle Gmail taslağı açma; uygulama e-posta göndermez
- Verileri yedekleme ve yedekten geri yükleme
- Parolalı giriş, boşta kalınca kilitlenme ve kurtarma kodu
- Yerel kayıt dosyaları için AES-GCM şifreleme
- İsteğe bağlı açılış kapak görseli; bu kaynak paketinde logo veya marka görseli bulunmaz

## Kaynak kodunu çalıştırma

Python 3.10 veya üzeri ve Tkinter gerekir. Bağımlılıkları kurup uygulamayı çalıştırın:

    python -m pip install -r requirements.txt
    python basit_ev_muhasebe.py

## Kayıt güvenliği

Kayıtlar uygulama klasöründeki **veriler/** dizininde tutulur ve AES-GCM ile şifrelenir. Parolanızı ve kurtarma kodunuzu güvenli yerde saklayın. Şifreli kayıtların yedeğini düzenli alın. **veriler/** klasörü ve gerçek kullanıcı verileri GitHub'a yüklenmemelidir.

## Lisans

MIT License. Lisans program koduna uygulanır. Kullanıcı eklediği görsellerin veya içeriklerin haklarını ayrıca doğrulamalıdır.
