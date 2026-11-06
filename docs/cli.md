# Komut satırı kullanımı

Aşağıdaki örneklerde AppImage adı kullanılmıştır. Kaynak kurulumunda aynı yere `secram-pro`, tarball’da `./AppRun` yazabilirsiniz.

AppImage, Linux’ta kurulum gerektirmeyen tek dosyalık program paketidir; Windows’taki `.exe` dosyasına benzer. Yalnız Linux x86_64 üzerinde çalışır.

## Yerel IP ve gateway bilgisini gösterme

Bu komut yalnızca bilgisayarın yerel ağ bilgilerini okur; tarama yapmaz:

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --show-network
```

GUI’de **IP ve ağ bilgisini otomatik doldur** düğmesi aynı bilgiyi forma yazar. Kullanıcı tarama düğmesine basmadıkça Nmap çalışmaz.

## İlk kontroller

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
./SecRam-Pro-v0.4.0-x86_64.AppImage --self-check
./SecRam-Pro-v0.4.0-x86_64.AppImage --host-snapshot
```

`--doctor` bağımlılıkları kontrol eder. `--self-check` hedefe ağ isteği yapmaz. `--host-snapshot` salt okunur yerel Host özetidir.

## Güvenli Lab demosu

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --lab-demo > lab-sonucu.json
echo $?
cat lab-sonucu.json
```

Bu komut yalnız uygulamanın oluşturduğu loopback Lab’ını kullanır. Rootless namespace yoksa açık hata verir; sahte başarı üretmez.

## Yetkili değerlendirme

En kısa terminal kullanımı tek IP ve port listesiyle şöyledir:

```bash
secram-pro \
  --scan-target 192.168.1.1 \
  --scan-ports 22,80,443 \
  --authorized \
  --scan-output ./tarama-sonucu.json
```

Komut tarama tamamlanınca sonucu terminale basar. `--scan-output` verilirse aynı sonuç 0600 izinli JSON dosyasına yazılır. `--authorized` açık yetki beyanı olmadan tarama başlatılmaz.

Önce profili kopyalayıp yalnız size ait hedef/port/izin bilgilerini girin:

```bash
cp examples/assessment-local.json /tmp/benim-degerlendirmem.json
nano /tmp/benim-degerlendirmem.json
./SecRam-Pro-v0.4.0-x86_64.AppImage \
  --run-assessment /tmp/benim-degerlendirmem.json \
  > degerlendirme-sonucu.json
```

Profilde `target`, `cidrs`, `ports`, `approved_by`, `evidence_reference`, `expires_hours` ve `allowed_operations` alanları bulunur. Her hedef literal IP olmalı; DNS/hostname, toplu CIDR taraması, UDP, NSE, serbest Nmap argümanı ve exploit yoktur.

`approved_by` ve `evidence_reference` denetim izi sağlar, yetkiyi doğrulamaz. Uygulama işlem, hedef, port, değerlendirme ve süre kapsamını yeniden kontrol eder.

## Değerlendirme ve rapor

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --list-assessments
mkdir -p private-export
./SecRam-Pro-v0.4.0-x86_64.AppImage \
  --export ASSESSMENT_ID \
  --output-dir ./private-export
find private-export -maxdepth 1 -type f -printf '%f\n' | sort
```

JSON, Markdown, HTML, CSV ve PDF üretilebilir. `private-export` içeriğini GitHub’a yüklemeyin.

## OSV snapshot

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage \
  --import-osv /dosya/yolu/osv.json
```

Bu işlem internetten veri çekmez. Snapshot’ın kaynağını ve tarihini ayrıca doğrulayın.

## GUI smoke testi

Headless test ortamında:

```bash
QT_QPA_PLATFORM=offscreen \
  ./SecRam-Pro-v0.4.0-x86_64.AppImage --smoke-test
```
