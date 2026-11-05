# SecRam-Pro

**v0.4.0 — Linux için çalışan geliştirme sürümü. Tam saldırı arsenali veya üretim sertifikalı platform değildir.**

Python/PySide6 tabanlı modüler güvenlik platformu: gerçek Nmap TCP taraması, HTTP/TLS gözlemleri, bağımsız yerel Blue telemetri, konservatif Purple korelasyonu, rootless eğitim Lab’ı ve raporlama. Kural tabanlı Orchestrator gerçek sonuçlara göre sonraki izinli işlemleri seçer. Tek kalıcı TaskEngine, SQLite, Pydantic ve asyncio kullanılır; zorunlu ücretli API, bulut hesabı veya abonelik yoktur.

Windows kapsamı kullanıcı kararıyla kaldırılmıştır. Fedora 43, Debian 13 ve Ubuntu kullanıcı alanı testleri yapılmıştır. Dağıtım rootfs testleri aynı kernel üzerinde çalışır; native kernel/SELinux/fiziksel masaüstü sertifikasyonu değildir. [Son uyumluluk kanıtı](docs/compatibility-matrix.md).

## Çalışan işlevler ve sınırlar

| Alan | Bu sürümde gerçek işlev |
|---|---|
| Yetkilendirme | CIDR/işlem/port/süre kapısı, yetki kaydı, iptal, timeout, atomik görev-audit yazımı |
| Host | CPU/RAM/depolama, sınırlı süreç/arayüz/bağlantı envanteri ve erişilebilir systemd servisleri |
| Red | Tek literal IP’de en fazla 32 izinli portla gerçek Nmap `-sT`; DNS/ARP keşfi kapalı |
| Web | Sabit `HEAD /`, güvenlik başlığı adayları, sertifika/tarih/güven/SAN ve görüşülen TLS bilgisi |
| Blue | Süreç/ağ gözlemleri, seçilen auth-log’un yeni satırları, dosya SHA-256 değişimi, kullanıcı IOC IP’leri |
| Purple | Gerçek zaman çizelgesi, T1046 eşlemesi; kanıt yetersizse oranlar `null` |
| Otonom | Nmap → bulguya bağlı izinli HTTP/TLS → Blue/Purple → rapor; LLM veya istismar değil |
| Lab | Sabit HTTP fixture, rootless user+network namespace ve yalnız loopback gateway |
| OSV | Yerel OSV JSON → yalnız çalıştırılan Python ortamının PyPI paket sürümleri |
| Rapor | JSON, Markdown, HTML, CSV, PDF ve SHA-256 manifesti |

**Nuclei/ZAP, Greenbone/Metasploit/SQLmap, PCAP/TShark, Suricata/Zeek, Sigma/YARA, Podman/KVM, NVD/CPE/CVSS/KEV henüz entegre değildir.** Tam özgün kapsam tamamlanmış gibi sunulmaz: [gereksinim matrisi](docs/requirements-matrix.md).

## Kurulum

### Portable Linux dağıtımı

Hazır x86_64 AppImage ve portable tarball için [`docs/portable.md`](docs/portable.md) dosyasına bakın. AppImage Python/Qt çalışma dosyalarını taşır; Nmap, `ip`, `unshare`, kernel namespace yeteneği ve grafik sistemini taşımaz.

```bash
# AppImage
chmod +x SecRam-Pro-v0.4.0-x86_64.AppImage
./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
./SecRam-Pro-v0.4.0-x86_64.AppImage --self-check

# Grafik arayüzü
./SecRam-Pro-v0.4.0-x86_64.AppImage

# FUSE kapalı sistemlerde alternatif
APPIMAGE_EXTRACT_AND_RUN=1 ./SecRam-Pro-v0.4.0-x86_64.AppImage
```

Tarball kullanımı:

```bash
tar -xzf SecRam-Pro-v0.4.0-portable-x86_64.tar.gz
cd SecRam-Pro.AppDir
./AppRun --doctor
./AppRun --self-check
./AppRun
```

`--doctor` çıktısı zorunlu ilk kontroldür. AppImage tam VM/konteyner izolasyonu değildir.

### Kaynaktan kurulum

Python **3.12+**, Linux ve Nmap gerekir. Uygulamayı normal kullanıcıyla başlatın; `sudo secram-pro` kullanmayın. Sistem paketlerini kendiniz kurun:

Fedora 43:

```bash
sudo dnf install python3 python3-pip nmap util-linux iproute \
  mesa-libGL mesa-libEGL libxkbcommon fontconfig dbus-libs glib2 dejavu-sans-fonts
```

Debian 13:

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv python3-pip nmap util-linux iproute2 \
  libgl1 libegl1 libxkbcommon0 libfontconfig1 libdbus-1-3 libglib2.0-0t64 fonts-dejavu-core
```

Kaynak dizininde:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
secram-pro --doctor
secram-pro
```

Tekrarlanabilir test sürümleri için `python -m pip install -r requirements-lock.txt` ardından `python -m pip install --no-deps -e .` kullanılabilir. Kilit dosyası sürüm kaydıdır, imzalı/hash doğrulamalı tedarik zinciri kilidi değildir.

İlk kurulum internet veya önceden hazırlanmış paketler gerektirir. Kurulum sonrası yerel analiz/izleme/Lab/raporlar offline çalışır; ağ testi için seçilen yetkili hedefe erişim gerekir. Qt `xcb` sorunları: [sorun giderme](docs/troubleshooting.md). `QT_QPA_PLATFORM=offscreen` yalnız headless test içindir.

## İlk gerçek gösterim — yalnız kendi geçici Lab’ınız

```bash
# Kaynak kurulumunda
secram-pro --lab-demo

# AppImage ile aynı senaryo
./SecRam-Pro-v0.4.0-x86_64.AppImage --lab-demo
```

Bu komut uygulamanın oluşturduğu `127.0.0.1` HTTP Lab’ını gerçek Nmap/HTTP ile değerlendirir, Blue gözlemlerini ve Purple sonucunu raporlar. Çıkışta Lab ve izleme durur. Rootless namespace kullanılamıyorsa açık hata verir; sahte/izolasyonsuz başarıya dönmez.

Arayüzden:

1. **Operasyonlar → Lab → Kontrollü rootless Lab oluştur.**
2. **Bu Lab için yetkili değerlendirme oluştur.** Yalnız oluşturulan gateway portu izinlidir.
3. **Otonom / Red → Yetkili otonom değerlendirmeyi başlat.**
4. **Görevler / Bulgular / Blue / Purple / Raporlar** ekranlarını inceleyin.

**Lab güvenlik sınırı:** Kernel ve dosya sistemi host ile paylaşılır; gateway namespace sınırını bilerek geçer. Yalnız sabit zararsız eğitim fixture’ıdır. Güvenilmeyen exploit/PoC/zararlı yazılım için güvenli VM veya konteyner değildir.

## Komut satırı kullanım senaryoları

Komutlar kaynak kurulumunda `secram-pro`, AppImage’da `./SecRam-Pro-v0.4.0-x86_64.AppImage`, tarball’da ise `./AppRun` ile çalıştırılabilir. Aşağıdaki örneklerde `secram-pro` kullanılmıştır.

### Bağımlılık ve çekirdek kontrolü

```bash
# Python, Nmap, ip, unshare, OSV ve Lab durumunu gösterir; tarama yapmaz.
secram-pro --doctor

# Yerel çekirdeğin temel uygulama sözleşmesini kontrol eder; hedefe ağ isteği yapmaz.
secram-pro --self-check

# Salt okunur Host snapshot alır; değişiklik yapmaz.
secram-pro --host-snapshot
```

`--doctor` başarılı görünse bile kernel namespace izni ayrıca değerlendirilir. `rootless_namespace_verified:false` sonucu Lab’ın henüz doğrulanmadığını gösterir; bunu başarı olarak yorumlamayın.

### Grafik arayüzünü başlatma

```bash
# Normal masaüstü oturumunda GUI’yi açar.
secram-pro

# Headless test veya CI için kısa GUI açılış/kapanış testi.
QT_QPA_PLATFORM=offscreen secram-pro --smoke-test
```

GUI içinde önce kapsam ve yetkilendirme oluşturun, sonra izinli işlemleri seçin. **Operasyonlar → Lab** yalnız kendi geçici Lab’ınızdır; gerçek hedeflerde doğrudan GUI’den kapsam, süre, port ve işlem izinlerini açıkça belirleyin.

### Kendi yerel Lab’ınızda gerçek uçtan uca test

```bash
secram-pro --lab-demo > lab-demo.json
echo $?
```

Bu komut yalnız uygulamanın oluşturduğu `127.0.0.1` HTTP fixture’ına gider ve JSON görev sonucunu stdout’a yazar. `0` çıkış kodu workflow’un tamamlandığını, `1` çıkış kodu Lab/namespace veya görev hatasını belirtir. Başka IP, port veya profil kabul etmez.

### JSON yetki profiliyle kontrollü değerlendirme

Önce örneği kopyalayın ve yalnız size ait hedef/port/izin değerlerini düzenleyin:

```bash
cp examples/assessment-local.json /tmp/my-assessment.json
$EDITOR /tmp/my-assessment.json
secram-pro --run-assessment /tmp/my-assessment.json > assessment-result.json
```

Profilde `cidrs`, `target`, `ports`, `approved_by`, `evidence_reference`, `allowed_operations` ve gerekiyorsa `web_services` alanlarını açıkça verin. Örnek:

```json
{
  "title": "Kendi loopback servisim",
  "cidrs": ["127.0.0.1/32"],
  "approved_by": "Yerel sistem sahibi",
  "evidence_reference": "ticket-or-written-authorization-123",
  "expires_hours": 1,
  "allowed_operations": ["orchestrator.run", "nmap.tcp_scan", "web.http_headers", "blue.monitor"],
  "ports": [8000],
  "target": "127.0.0.1",
  "web_services": {"8000": "http"}
}
```

Port üzerinde gerçekten servis yoksa başarılı HTTP sonucu beklemeyin. DNS/hostname, CIDR toplu taraması, UDP, NSE, serbest Nmap argümanları ve istismar desteklenmez. Her görev süresi, işlem ve port kapsamını yeniden kontrol eder.

### Değerlendirmeleri listeleme ve rapor dışa aktarma

```bash
# Kayıtlı değerlendirme ve UUID’lerini JSON olarak gösterir.
secram-pro --list-assessments > assessments.json

# ASSESSMENT_ID değerini yukarıdaki JSON’dan alın.
mkdir -p ./private-export
secram-pro --export ASSESSMENT_ID --output-dir ./private-export
find ./private-export -maxdepth 1 -type f -printf '%f\n' | sort
```

Export sonucu JSON, Markdown, HTML, CSV ve ReportLab PDF içerir. Raporlar hassas veri içerebilir; `private-export/` dizinini Git’e eklemeyin. `unavailable_formats` doluysa çıkış kodu `1` olur ve eksik dosya başarı gibi sunulmaz.

### Yerel OSV danışma verisi içe aktarma

```bash
secram-pro --import-osv /path/to/osv-snapshot.json
```

Bu işlem internetten veri çekmez. Snapshot’ın kaynağını, tarihini ve bütünlüğünü kendiniz doğrulayın. Eşleşme bulunmaması sistemin temiz olduğu anlamına gelmez; yalnız çalıştırılan Python ortamının PyPI paketleri desteklenir, RPM/DEB envanteri değildir.

### Ayrı veri diziniyle çalışma

```bash
mkdir -p "$HOME/secram-work"
secram-pro --data-dir "$HOME/secram-work" --doctor
secram-pro --data-dir "$HOME/secram-work" --list-assessments
```

Aynı `--data-dir` ile iki SecRam-Pro instance’ı açmayın. Veritabanı, auth log, rapor ve audit kayıtları şifreli değildir; hassas veri için dosya izinleri ve disk şifrelemesi ayrıca sağlanmalıdır.

## Kendi yetkili hedefiniz

**Değerlendirmeler** ekranında başlık, CIDR, yetkili kişi, kanıt referansı, süre, izinli işlemler ve portları girin. Orchestrator ve Nmap izinleri ayrı gereklidir; HTTP/TLS/Blue isteğe bağlıdır. Önceki değerlendirmelerin izinleri sessizce genişletilmez.

Yetkili LAN IP’leri desteklenir; ürün yalnız localhost’a kilitli değildir. Her görev tek literal IPv4/IPv6 hedefler: hostname/DNS, CIDR toplu tarama, UDP, NSE, serbest argüman veya istismar yoktur. Port tablosu servis adı banner/sürüm doğrulaması değildir. Açık port tek başına zafiyet değildir. Sonuçlandırılamayan kontroller `inconclusive` olur.

[Örnek yerel profil](examples/assessment-local.json) yalnız kendi kapsamınıza göre düzenlenmelidir; 8000 portunda kendi HTTP servisiniz yoksa bu örnek başarılı web sonucu üretmez.

```bash
secram-pro --run-assessment examples/assessment-local.json
secram-pro --list-assessments
secram-pro --export ASSESSMENT_ID --output-dir ./private-export
```

Özel HTTP portunda açık protokol ipucu verin: arayüzde `8000=http`, JSON’da `"web_services":{"8000":"http"}`. Bilinmeyen portlara kör HTTP/TLS testi uygulanmaz; en fazla ilk sekiz açık portta takip yapılır.

HTTPS başlık kontrolü CA ve literal IP doğrulaması kullanır; hata halinde doğrulanmamış HTTP’ye düşmez. Yönlendirme takip edilmez; body/Authorization/Set-Cookie değerleri tutulmaz. TLS sertifikası için açık izinli ek doğrulanmamış handshake yapılabilir; HTTP/kimlik bilgisi gönderilmez. Görüşülen TLS protokolü eski protokollerin kapalı olduğunun kanıtı değildir. HTTP/TLS bulguları `candidate` kalır; tekrar gözlem istismarı doğrulamaz.

## Blue, OSV ve raporlar

**Operasyonlar → Blue**: açıkça seçilen okunabilir auth-log, en fazla 16 bütünlük dosyası / dosya başına 4 MiB ve kendi IOC IP’lerinizi girin. Eski auth satırları başlangıçta alarm olarak tekrar oynatılmaz. Journal okuyucusu yoktur; Fedora’da yalnız journald varsa auth dosyası verisi bulunmayabilir. Polling paket yakalama/IDS kapsamı değildir. Hash/süreç/IOC gözlemi tek başına zararlılık kanıtı değildir. Yetki bitince izleme durur.

Purple endpoint/zaman ilişkisini nedensellik veya kesin tespit saymaz. Tam güvenilir sensör kapsamı, açık görev bağlantısı ve uygun kural kanıtı yoksa tespit oranı bilinmez. Etiketli negatif veri yoksa yanlış alarm oranı bilinmez. [Ölçüm yöntemi](docs/purple-methodology.md).

```bash
secram-pro --import-osv /path/osv.json
```

OSV üretim verisi birlikte gelmez; yalnız PyPI desteklenir, RPM/DEB envanteri değildir. `OSV-TEST-*` kayıtları test fixture’ıdır, gerçek CVE değildir. Eşleşme yokluğu snapshot kapsamı/tazeliği bilinmediğinden “sistem temiz” sayılmaz. [OSV biçimi](docs/advisory-format.md).

Raporlar varsayılan kullanıcı veri dizinindeki `reports/` altında oluşturulur. HTML kaçışlama, CSV formül nötralizasyonu ve bazı gizli anahtar alanlarının redaksiyonu vardır; bütün sır/kişisel bilgilerin otomatik temizlendiği garanti edilmez. **Veritabanı, rapor, auth log veya ham operasyon verisini GitHub’a yüklemeyin.** Manifest bütünlük snapshot’ıdır, imza değildir.

## Veriler ve çevrimdışı kurulum

Veri dizini `$XDG_DATA_HOME/secram-pro` veya `~/.local/share/secram-pro`; `--data-dir /path/private-data` ile değişir. Aynı dizini iki uygulama açamaz. SQLite şeması v1 korunmuştur. READY/RUNNING görevler yeniden açılışta FAILED olur; sessiz otomatik tekrar yoktur.

Veritabanı/raporlar **şifreli değildir**. Özel dosya izinleri tam disk şifrelemesinin yerini tutmaz; audit kurcalamaya dayanıklı imzalı kayıt değildir. Hassas veya üretim sistemlerinde kullanmadan önce güvenlik incelemesi gerekir.

İnternetli, hedefle aynı Python/ABI/mimariye sahip ortamda:

```bash
bash scripts/prepare_offline.sh
```

`wheelhouse/` ve `offline-source/` çevrimdışı makineye taşınır. Sistem paketleri/Nmap ayrıca hazırlanır. [Çevrimdışı kurulum](docs/offline-install.md).

## Test ve GitHub

```bash
source .venv/bin/activate
python -m pip install -e '.[dev]'
QT_QPA_PLATFORM=offscreen python -m pytest -q
python scripts/package_source.py SecRam-Pro-source.zip
```

[Son sürüm raporu](docs/release-report.md), [test yöntemi](docs/testing.md). GitHub Actions dosyası hazırlanmıştır; GitHub’da henüz çalıştırılmamıştır. CI’de namespace yoksa gerçek Lab testleri açık nedenle skip edilir; bu başarı kanıtı değildir. Dağıtım rootfs scripti yalnız kontrollü test makinesinde sudo/OCI/namespace araçları gerektirir, günlük kurulum aracı değildir.

Kaynak ZIP’i açın, GitHub’da boş repository oluşturun; veri/sır dosyalarını eklemeden:

```bash
git init
git add .
git commit -m "SecRam-Pro v0.4.0 working Linux development release"
git branch -M main
git remote add origin https://github.com/KULLANICI/SecRam-Pro.git
git push -u origin main
```

`KULLANICI` yerine kendi adınızı yazın; `git status --short` çıktısını önce kontrol edin. Bu sürümün kaynak kodu `ramelano/secram-pro` repository’sine `main` branch’inde push edilmiştir.

## Lisans ve güvenlik

Kaynak kodu [MIT](LICENSE); üçüncü taraflar kendi lisanslarıyla kalır, binary’leri kaynak ZIP’ine dahil değildir. [Bağımlılıklar](docs/dependencies.md), [güvenlik](SECURITY.md), [katkı](CONTRIBUTING.md), [değişiklikler](CHANGELOG.md).

Yalnız sahip olduğunuz veya açıkça yetkilendirildiğiniz sistemlerde kullanın. Kullanıcı beyanı yetkinin bağımsız doğrulaması değildir. Bu sürüm hedefin güvenli olduğunu veya tespit edilemeyen saldırı olmadığını garanti etmez.
