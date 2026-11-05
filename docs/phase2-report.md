# SecRam-Pro — Phase 2 Sonuç Raporu

## Kapsam ve durum

Kullanıcı Host + Nmap birleşik kapsamını **450 kredilik planlama zarfıyla** onayladı. Bu aşama tamamlandı; sonraki aşama başlatılmadı. Toplam bütçe planı 3.100, korunan rezerv en az 620 kredi. Windows kapsam dışı; Fedora ana hedef. Gerçek ortam doğrulaması Ubuntu sandbox'ta yapıldı.

## Gerçekleştirilen işlevler

**Host:** Salt okunur CPU/RAM/kök disk, en fazla 200 süreç kaydı, ağ arayüzleri ve erişilebilen en fazla 200 systemd servis kaydı. Eksik izin, eksik systemd, timeout ve kesilmiş çıktı açık raporlanır. Anlık bilgi toplama; güvenlik puanı veya sürekli izleme değil.

**Nmap:** Gerçek araç keşfi/sürümü, cache'li kullanılabilirlik, tek literal IP, 1–32 izinli TCP portu, sabit unprivileged connect profili, XML normalizasyonu, bounded stdout/stderr, timeout/iptal, ham çıktının ve SHA-256 özetinin görev sonucunda kalıcılığı.

**Entegrasyon:** Mevcut TaskEngine/Registry genişletildi; ikinci görev altyapısı oluşturulmadı. Gönderimde ve çalıştırma öncesinde hedef, zaman, işlem ve tüm portlar doğrulanır. Doğrudan adaptör çağrısı da değerlendirme bağlamı olmadan reddedilir. Mevcut değerlendirmelerin izinleri otomatik genişletilmez. Host ve LAN ekranları aynı servis/motor üzerinden çalışır.

## Dosyalar

### Yeni

- `src/secram/platforms/linux/host.py`
- `src/secram/tools/adapters/nmap.py`
- `tests/test_host.py`, `tests/test_nmap.py`
- `tests/test_nmap_safety.py`, `tests/test_phase2_integration.py`
- `scripts/validate_phase2.py`
- `docs/phase2-report.md`, test kayıtları ve `docs/phase2-evidence/*`

### Değiştirilen

- `tools/base.py`: ToolRequest'e değerlendirme bağlamı.
- `core/tasks.py`: işlem parametre doğrulama kapısı; waiter iptalinin çalışana yayılmaması.
- `services/application.py`: Host/Nmap kayıtları, açık izinler, uzun iş bekleme ve executor kapanışı.
- `ui/main_window.py`: Host/LAN sekmeleri, izin/port alanları ve gerçek sonuçlar.
- `app.py`: gerçek yerel Host CLI işlemi.
- `pyproject.toml`, `requirements-lock.txt`: sürüm 0.2.0 ve bağımlılıklar.
- `tests/test_core.py`, `test_ui.py`, `test_application.py`: davranış/sekme regresyon uyarlamaları.
- `README.md`: güncel kullanım ve sınırlar.

Phase 1 kaynak ZIP'i değiştirilmedi. SQLite şeması değiştirilmedi; eski kayıtlar aynı modellerle okunur. Çalışan çekirdek yeniden yazılmadı.

## Bağımlılıklar ve kurulum

- Python 3.12.3; PySide6 6.12.0; Pydantic 2.14.2; SQLAlchemy 2.1.6; pytest 9.2.0.
- Yeni: psutil 7.2.2, defusedxml 0.7.1.
- Gerçek sandbox Nmap: **7.94SVN**.
- Nmap yalnız sandbox'a apt üzerinden kuruldu. Kullanıcının Fedora sistemi, firewall veya servis ayarları değiştirilmedi.
- Web araştırması/ücretli API kullanılmadı. İlk paket kurulumu paket depolarına erişti; runtime internet/bulut hesabı gerektirmez.
- Nmap binary'si dağıtım arşivine eklenmedi. Araç/bağımlılık lisanslarının ürün yeniden dağıtımı için ayrı incelenmesi gerekir; bu aşamada güncel hukuki uygunluk doğrulanmış sayılmadı.

## Test sonuçları

Başlangıç regresyonu: **57 passed**.

Son birleşik koşu:

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q --junitxml=phase2-test-results.xml
```

**106 passed in 4.90s; hata/başarısız/atlanan test yok.**

Kapsam:

- Önceki çekirdek, kalıcılık, onay, iptal ve Qt testleri.
- Gerçek Host verisi; process limitleri, izin/procfs hataları ve systemd yokluğu/çıktı durumları.
- Gerçek loopback Nmap açık port tespiti.
- İzin dışı port, hostname/CIDR, hedef, raw argüman, boolean port, süre ve yanlış işlem reddi.
- XXE/entity/doctype, yanlış host/port/protokol ve bozuk XML reddi.
- Eksik/down/timedout sonuçlarda `inconclusive`; extraports özeti korunur, port gözlemi uydurulmaz.
- Nmap çıktı hafıza limiti, gerçek yerel alt süreç iptali ve timeout/reap.
- Eski kapsamın genişletilmemesi, gerçek UI → servis → Host/Nmap → DB akışı.
- Bekleme coroutine'i iptal edildiğinde çalışan operasyonun devam etmesi.

Host hata/systemd testlerinde kontrollü fixtures, bazı Nmap timeout/parsing testlerinde yerel test doubles kullanılır. Üründe bunlar gerçek sonuç yerine kullanılmaz. Gerçek Host, Nmap ve UI entegrasyon testleri ayrıca vardır.

## Gerçek kanıt üretimi

```bash
.venv/bin/python scripts/validate_phase2.py --output docs/phase2-evidence
```

Script yalnız sahip olunan geçici yerel test servisini kullanır. Bu koşuda:

| Doğrulama | Gerçek sonuç |
|---|---|
| Hedef | 127.0.0.1 |
| Açıkça izinli geçici TCP portu | 50555 |
| Host görev/snapshot durumu | succeeded / ok |
| Süreç kayıt sayısı | 151 |
| Ağ arayüz adres kaydı sayısı | 6 |
| systemd servis toplama durumu | ok |
| Nmap görev/tarama durumu | succeeded / complete |
| Port gözlemi | TCP 50555 open, reason syn-ack |
| Servis doğrulaması | false; sürüm/banner tespiti yapılmadı |
| Kanıt SHA-256 | 1da93dfbcdc1b8f5f11eeaf52ab105ef4c79a3229277330386c1ddbd08d1ab66 |

Port ve anlık kaynak değerleri başka koşuda değişir. Bunlar ürünün örnek/sabit sonuçları değildir. Ayrıntılı Host süreç/IP envanteri kamuya açık özet dosyasına konmadı; yerel görevin veritabanı sonucunda bulunur.

`nmap-loopback.xml`: gerçek ham Nmap çıktısı. `nmap-task.json`: gerçek görev ve normalize sonuç. `validation-summary.json`: gerçek Host özeti ve Nmap kanıt bağlantısı.

Ek doğrulama: `--host-snapshot` CLI succeeded/ok; headless Qt açılış/kapanışı exit 0; Python compileall başarılı. Qt offscreen `propagateSizeHints()` uyarısı test hatası oluşturmadı.

## Hatalar ve sınırlar

Entegrasyon koşularında başarısız test oluşmadı. Kod incelemesinde iki doğruluk sınırı güçlendirildi: eksik Nmap port kapsamı `inconclusive` yapıldı; OS-visible Host kaynaklarının cgroup/fiziksel makine kaynağı olmadığı belirtildi.

- Fedora/Debian native çalıştırma ve gerçek dış LAN cihazı test edilmedi. Yerel test başarısı bunların doğrulanması sayılmaz.
- IPv6 hedef doğrulaması/komut yolu var; gerçek IPv6 ağ taraması bu koşuda test edilmedi.
- Tek IP ve sınırlı TCP değerlendirmesi var; subnet toplu tarama, UDP, NSE, banner/sürüm/CVE/istismar yok.
- Host yalnız anlık kaynak/süreç/ağ/servis bilgisi; firewall, SSH, kullanıcı/izin, log ve dosya bütünlüğü denetimleri henüz yok.
- Host read-only thread'i zorla öldürülemez; bounded toplama tamamlanır. Nmap ayrı alt süreç olarak iptal edilir.
- Registry Integrated/Tested adaptör seviyesindedir; otonom Red Agent araç seçimi/yorumlama henüz uygulanmadı.
- Sürekli Blue izleme, Purple korelasyonu, Lab Manager, yerel AI ve profesyonel rapor üretimi yok.
- Nmap önbellekli probe; oturum içinde yeni kurulum sonrası yeniden başlatma gerekir.
- SQLite şifreli/tamper-proof değil; task/audit normal yazımı tek atomik transaction değil. Son paketleme ve migration henüz yok.

## Kredi kaydı ve sonraki kapı

| Kalem | Durum |
|---|---|
| Toplam plan | 3.100 kredi |
| Phase 2 onaylanan zarf | 450 kredi |
| Korunan entegrasyon/hata/test payı | En az 620 kredi |
| Gerçek Phase 2 tüketimi | Doğrulanabilir sayaç bu oturumda erişilebilir değil |
| Gerçek kalan bakiye | Hesaplanamadı; kesin değer uydurulmadı |
| Sonraki dar Blue başlangıcı ön tahmini | Yaklaşık 300 kredi; kapsam ve gerçek bakiye teyidinden sonra ayrı onay gerekir |

450 kredi harcandığı veya bakiye olarak belirli bir tutar kaldığı iddia edilmiyor. Yeni aşamaya geçilmedi; onay beklenecek.

Yalnızca yetkili ve yasal ortamlarda kullanın.
