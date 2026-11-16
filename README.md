# Basit Ev Muhasebe Programı

Ev ve kişisel bütçesini takip etmek isteyenler için Türkçe masaüstü uygulaması. Gelir ve giderleri kaydeder, özetler, raporlar ve çıktı alınmasını sağlar. **Fatura veya fiş kesmez; şirket muhasebesi ya da vergi beyanı yazılımı değildir.**

Sorular ve iletişim: **sarmas.aicode@gmail.com**

## Özellikler

- Gelir ve gider ekleme, kayıtları düzenleme ve tarihe göre filtreleme
- Kategoriler oluşturma ve yönetme
- Gelir-gider genel bakışı, bakiye ve kategori dağılımı grafikleri
- Günlük, aylık ve yıllık dönem raporları
- A4 PDF raporu oluşturma ve Windows yazdırma penceresinden yazıcı veya PDF seçme
- Kişi ve iletişim bilgileri listesi; isteğe bağlı bağışçı ve aylık bağış takibi
- Kişi listesinden seçili e-posta adresleriyle Gmail taslağı açma; uygulama e-posta göndermez
- Verileri yedekleme ve yedekten geri yükleme
- Parolalı giriş, boşta kalınca kilitlenme ve kurtarma kodu
- Yerel kayıt dosyaları için AES-GCM şifreleme
- İsteğe bağlı açılış kapak görseli; bu kaynak paketinde logo veya marka görseli bulunmaz

## Platform durumu

Bu kaynak Windows için geliştirilmiştir. Linux uyarlaması ve Linux yazdırma akışı henüz doğrulanmış değildir; Linux desteği hazır ve test edilmiş gibi değerlendirilmemelidir.

## Windows'ta çalıştırma

Python 3.10 veya üzeri ve Tkinter gerekir. Bağımlılıkları kurup uygulamayı çalıştırın:

```powershell
python -m pip install -r requirements.txt
python basit_ev_muhasebe.py
```

## Kayıt güvenliği

Kayıtlar uygulama klasöründeki `veriler/` dizininde tutulur ve bu kaynakta AES-GCM ile şifrelenir. Parolanızı ve kurtarma kodunuzu güvenli yerde saklayın. Şifreli kayıtların yedeğini düzenli alın. `veriler/` klasörü ve gerçek kullanıcı verileri GitHub'a yüklenmemelidir.

## Lisans

MIT License. Lisans program koduna uygulanır. Kullanıcı eklediği görsellerin veya içeriklerin haklarını ayrıca doğrulamalıdır.
