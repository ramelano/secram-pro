# SecRam-Pro

**Linux için çevrimdışı güvenlik değerlendirme programı.**

Bu programın grafik arayüzü vardır. Terminalden de kullanılabilir.

SecRam-Pro ile şunları yapabilirsiniz:

- Bilgisayarınızın temel durumunu görebilirsiniz.
- Yetkili olduğunuz bir IP adresindeki izinli TCP portlarını Nmap ile kontrol edebilirsiniz.
- HTTP/TLS başlıklarını ve sertifika bilgilerini inceleyebilirsiniz.
- Süreç, ağ ve seçtiğiniz log dosyalarını izleyebilirsiniz.
- Bulguları JSON, Markdown, HTML, CSV ve PDF olarak dışa aktarabilirsiniz.
- Programın kendi güvenli eğitim Lab’ında örnek bir uçtan uca test çalıştırabilirsiniz.

> **Önemli:** Bu program yalnızca size ait veya yazılı izin aldığınız sistemlerde kullanılmalıdır. Program Windows için değildir; bu sürüm Linux içindir.

## En kolay kullanım: AppImage

AppImage, kurulum gerektirmeyen tek dosyalık Linux paketidir.

### 1. AppImage dosyasını indirin

Şu dosyaya ihtiyacınız var:

```text
SecRam-Pro-v0.4.0-x86_64.AppImage
```

Dosyayı bilgisayarınızda örneğin `İndirilenler` klasörüne koyun.

### 2. Terminali açın

Terminali açın ve dosyanın bulunduğu klasöre gidin. Dosya `İndirilenler` klasöründeyse:

```bash
cd ~/İndirilenler
```

Klasörünüzün adı farklıysa o klasöre gidin.

### 3. Dosyaya çalıştırma izni verin

```bash
chmod +x SecRam-Pro-v0.4.0-x86_64.AppImage
```

Bu komut yalnızca dosyanın çalıştırılabilmesini sağlar.

### 4. Bilgisayarın uygun olup olmadığını kontrol edin

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
```

Bu komut tarama yapmaz. Sadece Python, Nmap, `ip`, `unshare` ve benzeri gereksinimleri kontrol eder.

### 5. Programı açın

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage
```

Grafik arayüz açılacaktır.

### 6. İlk denemeyi yapın

Önce programın kendi eğitim Lab’ını çalıştırın:

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --lab-demo
```

Bu komut yalnızca SecRam-Pro’nun kendi geçici `127.0.0.1` Lab’ını kullanır. İnternetteki veya başka bir bilgisayardaki hedefi taramaz.

## AppImage açılmazsa

Bazı Linux sistemlerinde FUSE kapalı olabilir. Bu durumda şu komutu deneyin:

```bash
APPIMAGE_EXTRACT_AND_RUN=1 ./SecRam-Pro-v0.4.0-x86_64.AppImage
```

Aynı yöntemle test komutları da çalıştırılabilir:

```bash
APPIMAGE_EXTRACT_AND_RUN=1 ./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
```

## Portable tarball ile kullanım

AppImage yerine `.tar.gz` dosyasını kullanmak isterseniz:

```bash
tar -xzf SecRam-Pro-v0.4.0-portable-x86_64.tar.gz
cd SecRam-Pro.AppDir
./AppRun --doctor
./AppRun --self-check
./AppRun
```

Programı kapatmak için grafik pencereyi normal şekilde kapatın.

## Programın grafik arayüzünde ne yapacağım?

Program açıldıktan sonra genel sıra şöyledir:

1. **Değerlendirmeler** bölümünü açın.
2. Yeni bir değerlendirme oluşturun.
3. Hedef IP adresini yazın.
4. Yalnızca izin verdiğiniz portları seçin.
5. Yetkili kişi ve izin kanıtını yazın.
6. İzin süresini belirleyin.
7. İşlemleri seçin.
8. Değerlendirmeyi başlatın.
9. Sonuçları **Görevler**, **Bulgular**, **Blue**, **Purple** ve **Raporlar** bölümlerinden inceleyin.

Bir hedefi taramak için hedef sahibi olmanız veya açık yazılı izniniz olması gerekir. Programın kapsam ve süre kontrollerini kapatmayın.

## Terminalden temel komutlar

Aşağıdaki örneklerde AppImage adı kullanılmıştır. Kaynaktan kurulum yaptıysanız aynı yere `secram-pro` yazabilirsiniz.

### Programı kontrol etme

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
```

Ne yapar: Bilgisayarda gerekli araçların bulunup bulunmadığını gösterir.

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --self-check
```

Ne yapar: SecRam-Pro’nun temel çekirdek işlevlerini kontrol eder. Hedef taramaz.

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --host-snapshot
```

Ne yapar: Kendi Linux bilgisayarınızın salt okunur durum özetini çıkarır. Sistem ayarlarını değiştirmez.

### Grafik arayüzünü açma

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage
```

### Kendi eğitim Lab’ını çalıştırma

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --lab-demo > lab-sonucu.json
```

Sonucu görmek için:

```bash
cat lab-sonucu.json
```

Komutun çıkış kodunu görmek için:

```bash
echo $?
```

`0` başarılı, `1` hata anlamına gelir. Lab için gerekli Linux namespace izni yoksa program bunu açıkça bildirir; sahte başarı üretmez.

## Yetkili bir hedefi kontrol etme

Önce örnek profili kopyalayın:

```bash
cp examples/assessment-local.json /tmp/benim-degerlendirmem.json
```

Dosyayı düzenleyin:

```bash
nano /tmp/benim-degerlendirmem.json
```

Dosyada en az şu bilgileri doğru yazın:

- `target`: Kontrol edilecek IP adresi.
- `cidrs`: İzin verilen ağ veya IP aralığı.
- `ports`: Kontrol edilmesine izin verilen portlar.
- `approved_by`: İzni veren kişi.
- `evidence_reference`: İzin belgesi, ticket veya kayıt numarası.
- `allowed_operations`: Yapılmasına izin verilen işlemler.

Basit örnek:

```json
{
  "title": "Kendi test sunucum",
  "cidrs": ["127.0.0.1/32"],
  "approved_by": "Sistem sahibi",
  "evidence_reference": "izin-kaydi-123",
  "expires_hours": 1,
  "allowed_operations": ["orchestrator.run", "nmap.tcp_scan"],
  "ports": [8000],
  "target": "127.0.0.1"
}
```

Profili çalıştırın:

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage \
  --run-assessment /tmp/benim-degerlendirmem.json \
  > degerlendirme-sonucu.json
```

Sonucu okuyun:

```bash
cat degerlendirme-sonucu.json
```

> Örnek dosyadaki `127.0.0.1` ve `8000` değerlerini değiştirmeden başka bir hedefi kontrol etmeyin.

## Değerlendirmeleri listeleme

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --list-assessments
```

Çıktıda her değerlendirme için bir kimlik bulunur. Bu kimlik rapor almak için kullanılır.

## Rapor oluşturma

Önce rapor klasörü oluşturun:

```bash
mkdir -p private-export
```

`ASSESSMENT_ID` yerine değerlendirme listesinden aldığınız gerçek kimliği yazın:

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage \
  --export ASSESSMENT_ID \
  --output-dir ./private-export
```

Oluşan dosyaları görün:

```bash
find private-export -maxdepth 1 -type f -printf '%f\n' | sort
```

Raporlar hassas bilgiler içerebilir. `private-export` klasörünü GitHub’a yüklemeyin.

## OSV verisi içe aktarma

Elinizde yerel bir OSV JSON snapshot’ı varsa:

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage \
  --import-osv /dosya/yolu/osv.json
```

Bu komut internetten veri indirmez. OSV dosyasının güvenilirliğini, tarihini ve kaynağını kendiniz kontrol edin.

## Kaynak koddan kurulum

Bu yöntem geliştiriciler içindir. Python 3.12 veya daha yeni sürüm ve Linux gerekir.

### Fedora

```bash
sudo dnf install python3 python3-pip nmap util-linux iproute \
  mesa-libGL mesa-libEGL libxkbcommon fontconfig dbus-libs glib2 dejavu-sans-fonts
```

### Debian veya Ubuntu

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip nmap util-linux iproute2 \
  libgl1 libegl1 libxkbcommon0 libfontconfig1 libdbus-1-3 \
  libglib2.0-0t64 fonts-dejavu-core
```

### Python ortamını oluşturma

SecRam-Pro klasörüne gidin:

```bash
cd secram-pro
```

Sanal Python ortamı oluşturun:

```bash
python3 -m venv .venv
```

Ortamı etkinleştirin:

```bash
source .venv/bin/activate
```

Programı kurun:

```bash
python -m pip install -e .
```

Kurulumu kontrol edin:

```bash
secram-pro --doctor
```

Programı açın:

```bash
secram-pro
```

> `sudo secram-pro` kullanmayın. Programı normal kullanıcı hesabıyla çalıştırın.

## Program nerede veri saklar?

Varsayılan veri klasörü genellikle şuradadır:

```text
~/.local/share/secram-pro
```

İsterseniz başka bir klasör belirleyebilirsiniz:

```bash
mkdir -p "$HOME/secram-verileri"
./SecRam-Pro-v0.4.0-x86_64.AppImage \
  --data-dir "$HOME/secram-verileri"
```

Aynı veri klasörünü aynı anda iki SecRam-Pro programında kullanmayın.

Veritabanı ve raporlar şifreli değildir. Hassas sistemlerde dosya izinleri ve disk şifrelemesi kullanın.

## Sorun olursa

Önce şu komutları çalıştırın:

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
./SecRam-Pro-v0.4.0-x86_64.AppImage --self-check
```

### `nmap bulunamadı` diyorsa

Fedora:

```bash
sudo dnf install nmap
```

Debian/Ubuntu:

```bash
sudo apt install nmap
```

### AppImage çalışmıyorsa

```bash
APPIMAGE_EXTRACT_AND_RUN=1 ./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
```

### Lab çalışmıyorsa

Linux sistemi rootless user/network namespace kullanımına izin vermiyor olabilir. Bu durumda `--lab-demo` çalışmaz. Bu bir tarama başarısı değildir; izin verilen kendi hedefleriniz için diğer modülleri ayrıca kullanabilirsiniz.

### Grafik arayüzü açılmıyorsa

Başka bir terminalde şu kontrolü yapın:

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
```

Headless test için:

```bash
QT_QPA_PLATFORM=offscreen \
  ./SecRam-Pro-v0.4.0-x86_64.AppImage --smoke-test
```

Daha ayrıntılı sorun giderme için [`docs/troubleshooting.md`](docs/troubleshooting.md) dosyasına bakın.

## Güvenlik sınırları

Bu sürüm gerçek Nmap TCP kontrolü, HTTP/TLS gözlemi, yerel Blue telemetrisi, Purple korelasyonu ve raporlama yapar. Ancak tam saldırı platformu değildir.

Aşağıdakiler bu sürümde yoktur:

- Windows desteği.
- Nuclei, ZAP, Metasploit veya SQLmap entegrasyonu.
- UDP, NSE, DNS/ARP keşfi veya toplu ağ taraması.
- Genel CVE/CVSS/CPE motoru.
- VM veya tam konteyner izolasyonu.
- Güvenilmeyen exploit çalıştırma güvenliği.

AppImage ve portable tarball Python/Qt dosyalarını taşır. Nmap, `ip`, `unshare`, Linux kernel yetenekleri ve grafik sürücüleri bilgisayarınızdan gelir.

## Test durumu

Son doğrulama sonuçları:

- Ubuntu sandbox: `180 passed`.
- Fedora 43: `176 passed`, 4 Lab testi namespace izni nedeniyle atlandı.
- Debian 13: `176 passed`, 4 Lab testi namespace izni nedeniyle atlandı.
- AppImage: `--doctor` ve `--self-check` başarılı.
- Portable tarball: `--doctor` ve `--self-check` başarılı.

Ayrıntılar:

- [Portable kullanım rehberi](docs/portable.md)
- [Kurulum ve sorun giderme](docs/troubleshooting.md)
- [Test yöntemi](docs/testing.md)
- [Uyumluluk matrisi](docs/compatibility-matrix.md)
- [Son sürüm raporu](docs/release-report.md)
- [Gereksinim matrisi](docs/requirements-matrix.md)

## Lisans

Kaynak kodu MIT lisanslıdır: [`LICENSE`](LICENSE).

Yalnızca sahip olduğunuz veya açıkça yetkilendirildiğiniz sistemlerde kullanın.
