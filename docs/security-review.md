# Kod tabanlı güvenlik incelemesi

İnceleme tarihi: 2026-11-05

Bu belge statik kod incelemesidir; tam bağımlılık güncelliği, işletim sistemi sertifikasyonu veya bağımsız penetration test değildir.

## Bulgular

### 1. Nmap çağrısı — düşük risk / kontrol mevcut

`src/secram/tools/adapters/nmap.py` içinde:

- Hedef `literal_network_target` ile literal IPv4/IPv6 olarak doğrulanır.
- Hostname, CIDR, zone ID, multicast, unspecified ve broadcast reddedilir.
- Portlar 1–65535 arası integer, benzersiz ve en fazla 32 adettir.
- Portlar assessment kapsamındaki `allowed_ports` kümesine karşı tekrar kontrol edilir.
- İşlem adı adapter tarafından `tcp_scan` ile sabitlenir.
- Nmap argümanları kod tarafından sabit üretilir: `--unprivileged`, `-sT`, `-Pn`, `-n`, `--disable-arp-ping`, oran/retry/timeout sınırları ve XML stdout.
- Çağrı `asyncio.create_subprocess_exec(*argv, ...)` kullanır. `shell=True`, `os.system`, serbest kullanıcı argümanı veya shell string birleştirmesi yoktur.
- stdout/stderr boyutları sınırlanır; timeout/cancel durumunda process group sonlandırılır.

### 2. Rapor ve veritabanı izinleri — kontrol mevcut

- SQLite parent klasörleri eksikse `0700` ile oluşturulur.
- SQLite dosyası oluşturma sonrasında `0600` yapılır; mevcut dosyanın symlink olması reddedilir.
- Report bundle ve output klasörleri `0700` ile oluşturulur.
- Rapor dosyaları `O_CREAT | O_EXCL` ve `0600` ile yazılır.
- Rapor output path bileşenlerinde symlink reddedilir.
- Bu davranış `tests/test_reporting.py`, `tests/test_release_integration.py` ve symlink regresyon testleriyle kısmen doğrulanır.

### 3. HTML/PDF içerik kaçışlama — kontrol mevcut

- HTML raporu, untrusted snapshot’ın tamamını `html.escape(..., quote=True)` ile `<pre>` içinde yazar.
- PDF metinleri ReportLab’a verilmeden önce `xml.sax.saxutils.escape` kullanır; JSON gövdesi `Preformatted` olarak yerleştirilir.
- CSV hücrelerinde formül önekleri (`=`, `+`, `-`, `@`) nötralize edilir.
- Anahtar adına göre secret/password/token/private key/Authorization/Set-Cookie gibi alanlar redakte edilir.
- Redaksiyon tüm olası sırları yakalamayı garanti etmez; bu nedenle raporların GitHub’a yüklenmemesi gerekir.
- HTML injection regresyon testi mevcuttur; PDF için testler format/üretim ve PDF header doğrulaması yapar.

### 4. Veri klasörü eşzamanlı erişimi — kontrol mevcut, kapsam sınırlı

- `ApplicationService` aynı data directory’de `.instance.lock` dosyasını `O_NOFOLLOW` ve `0600` ile açar.
- `fcntl.flock(..., LOCK_EX | LOCK_NB)` ikinci instance’ı reddeder.
- Repository SQLite busy timeout ve thread/lifecycle/write lock kullanır.
- Bu, aynı host üzerinde çalışan SecRam-Pro instance’ları arasındaki çakışmayı sınırlar; ağ dosya sistemi veya kötü niyetli dış süreç için tam distributed lock değildir.

### 5. Bağımlılık lock dosyası — iyileştirme gerekli

`requirements-lock.txt` paket sürümlerini sabitler ancak `--hash=` kayıtları içermez. Bu nedenle dosya hash’li tedarik zinciri kilidi değildir. Bağımlılıkların güncel veya güvenlik açısından temiz olduğu web/advisory taraması yapılmadan doğrulanamaz.

Kurulumda daha güçlü tekrar üretilebilirlik için gelecekte hash’li wheelhouse veya güvenilir bir lock üretim süreci kullanılmalıdır. Mevcut dosya sürüm pin’i olarak değerlendirilmelidir, bütünlük imzası olarak değil.

## Sonuç

İncelenen Nmap, subprocess, rapor kaçışlama, dosya izinleri ve instance-lock kontrollerinde belirgin bir `shell=True` veya serbest Nmap argümanı bulunmadı. En önemli açık kalan tedarik zinciri konusu requirements lock dosyasının hash içermemesi ve bağımlılık güncelliğinin bu incelemede doğrulanmamış olmasıdır.
