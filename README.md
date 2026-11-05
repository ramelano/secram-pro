# SecRam-Pro

[![Linux tests](https://github.com/ramelano/secram-pro/actions/workflows/tests.yml/badge.svg)](https://github.com/ramelano/secram-pro/actions/workflows/tests.yml)

**Linux için çevrimdışı Red Team, Blue Team ve Purple Team güvenlik değerlendirme platformu.**

SecRam-Pro; Python/PySide6 grafik arayüzü, SQLite kalıcılığı, gerçek Nmap TCP keşfi, HTTP/TLS gözlemleri, yerel Blue telemetrisi, Purple korelasyonu, kontrollü Lab ve raporlama işlevlerini tek Linux uygulamasında birleştirir.

> **Sürüm:** v0.4.0 Linux geliştirme sürümü. Windows desteği yoktur. Bu proje üretim güvenlik ürünü, exploit-safe sandbox veya tam saldırı platformu değildir.

## Ne işe yarar?

- Yetkili tek IP ve izinli TCP portlarında Nmap connect keşfi yapar.
- Red Team v0.1 akışında açık portları ve izinli HTTP/TLS kontrollerini raporlar.
- Salt okunur Host, süreç, ağ ve seçilmiş log gözlemleri sağlar.
- Purple zaman çizelgesi ve MITRE ATT&CK T1046 eşlemesi üretir.
- JSON, Markdown, HTML, CSV ve PDF rapor çıkarır.
- Kendi loopback Lab’ında kontrollü uçtan uca demo çalıştırır.
- Temel işlevlerde ücretli API, bulut hesabı veya abonelik gerektirmez.

## İndir ve ilk kez çalıştır

### 1. İndir

[**GitHub Release v0.4.0**](https://github.com/ramelano/secram-pro/releases/tag/v0.4.0)

Doğrudan dosyalar:

- [AppImage](https://github.com/ramelano/secram-pro/releases/latest/download/SecRam-Pro-v0.4.0-x86_64.AppImage)
- [Portable tarball](https://github.com/ramelano/secram-pro/releases/latest/download/SecRam-Pro-v0.4.0-portable-x86_64.tar.gz)
- [SHA256SUMS](https://github.com/ramelano/secram-pro/releases/latest/download/SHA256SUMS)

### 2. Doğrula ve çalıştır

```bash
chmod +x SecRam-Pro-v0.4.0-x86_64.AppImage
wget https://github.com/ramelano/secram-pro/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
./SecRam-Pro-v0.4.0-x86_64.AppImage --self-check
./SecRam-Pro-v0.4.0-x86_64.AppImage
```

### 3. İlk güvenli demo

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --lab-demo
```

Bu demo yalnız SecRam-Pro’nun oluşturduğu loopback Lab’ını kullanır; internetteki veya başka bir bilgisayardaki hedefi taramaz.

AppImage açılmazsa FUSE’suz çalıştırmayı deneyin:

```bash
APPIMAGE_EXTRACT_AND_RUN=1 ./SecRam-Pro-v0.4.0-x86_64.AppImage
```

## Grafik arayüzü

Programı açtıktan sonra:

1. **Değerlendirmeler** bölümünde yetkili bir kapsam oluşturun.
2. Hedef IP, izinli portlar, izin süresi ve işlemleri açıkça seçin.
3. **Operasyonlar → Red Team** sekmesini açın.
4. **Yetkili Red Team keşfini başlat** düğmesine basın.
5. Sonuçları **Görevler**, **Bulgular**, **Blue**, **Purple** ve **Raporlar** sekmelerinde inceleyin.

Gerçek hedeflerde yalnız size ait veya yazılı izin aldığınız sistemleri kullanın.

## Red Team v0.1

Red Team v0.1 gerçek olarak şunları yapar:

- Tek literal IP’de yalnızca yetkilendirilmiş TCP portlarını tarar.
- Açık portları listeler.
- Açıkça verilen HTTP/HTTPS/TLS ipuçlarına göre takip kontrolü yapar.
- Kanıtları raporlar ve **T1046 — Network Service Scanning** ile eşleştirir.

Sonuç profili `red_team_v0.1_scoped` olarak işaretlenir. Gerçek hedef verisi içermeyen örnek çıktı: [red-team-sample-report.json](docs/examples/red-team-sample-report.json).

Bu sürümde parola saldırısı, credential theft, phishing, malware/C2, kalıcılık, gizlenme/evasion, exploit veya sınırsız shell yoktur. Açık port tek başına zafiyet kanıtı değildir; bulgular gözlem ve aday bulgu niteliğindedir.

## Yetki sınırı

`approved_by` ve `evidence_reference` alanları serbest metindir. **Denetim izi sağlar, yetkiyi doğrulamaz.**

Uygulama her görevde değerlendirme kimliğini, işlemi, literal hedefi, portu ve yetki süresini yeniden kontrol eder. Kapsam dışı, izin verilmeyen veya süresi bitmiş görevler reddedilir.

## Güvenlik sınırları

- Linux-only; Windows desteği yoktur.
- Nmap profili `-sT` TCP connect keşfiyle sınırlıdır.
- DNS/hostname, toplu CIDR taraması, UDP, NSE ve serbest Nmap argümanları yoktur.
- AppImage tam VM/konteyner izolasyonu değildir.
- Veritabanı ve raporlar şifreli değildir; hassas dosyaları GitHub’a yüklemeyin.
- Rootless Lab kernel ve dosya sistemi host ile paylaşır; güvenilmeyen exploit veya zararlı yazılım çalıştırmak için değildir.

## Test durumu

GitHub Actions Linux workflow’u Ubuntu host üzerinde Ubuntu, Fedora ve Debian kullanıcı alanlarını test eder. Rootless namespace yetkisi olmayan ortamlarda Lab testleri açık gerekçeyle atlanır; bu atlama başarı kanıtı değildir. Ayrıntı: [test yöntemi](docs/testing.md).

Yerel ayrıntılı doğrulama ve uyumluluk belgeleri:

- [Kurulum](docs/installation.md)
- [Komut satırı kullanımı](docs/cli.md)
- [Sorun giderme](docs/troubleshooting.md)
- [Uyumluluk matrisi](docs/compatibility-matrix.md)
- [Son sürüm raporu](docs/release-report.md)
- [Gereksinim matrisi](docs/requirements-matrix.md)
- [Kod tabanlı güvenlik incelemesi](docs/security-review.md)
- [Güvenlik politikası](SECURITY.md)

## Lisans

Kaynak kodu [MIT](LICENSE) lisanslıdır.

Yalnızca sahip olduğunuz veya açıkça yetkilendirildiğiniz sistemlerde kullanın.
