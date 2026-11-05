# SecRam-Pro v0.4.0 — teslim raporu

**Çalışan bütünleşik geliştirme sürümü; özgün tam kapsam tamamlanmadı.** Nuclei/ZAP/ileri arsenal, paket IDS, VM/konteyner Lab ve genel CVE/CVSS/CPE yok. [Tam matris](requirements-matrix.md). GitHub push/workflow henüz çalıştırılmadı.

## Gerçek işlev ve test

| Ortam | Python | Passed | Failed/errors | Skipped | Qt exit |
|---|---|---:|---:|---:|---:|
| Ubuntu sandbox | 3.12.3 | 180 | 0 | 0 | 0 |
| Fedora Linux 43 (Container Image) | Python 3.14.8 | 176 | 0 | 4 | 0 |
| Debian GNU/Linux 13 (trixie) | Python 3.13.5 | 176 | 0 | 4 | 0 |

Owned rootless Lab → gerçek Nmap TCP → gerçek HEAD → actual lab request telemetry → Purple → beş format rapor zinciri `complete`. Süre: 0.983 s; aday bulgu: 4; Nmap XML SHA-256: `0d647fa2e9424a30566ef8f82f786f7336be8978490cc7f8c06c8c6b718349d9`.

Purple tespit/FPR: `None` / `None`: bilinmiyor; paket/IDS kapsamı ve etiketli negatif veri yokken sıfıra çevrilmedi. Kaynak ölçümü yalnız validation Python süreci lifetime highwater; çocuklar/host veya yalnız operasyon peak ölçümü değildir.

Gerçek XML/JSON/PDF kanıtı `release-evidence/`; [örnek gerçek PDF](release-evidence/example-lab-report.pdf). Qt giriş/kapanış ve CLI doctor/self-check kanıtı aynı klasörde. Native/gerçek LAN cihazında üretim sertifikasyonu yapılmadı.

## Dosyalar

`src/secram/` altında yeni/değişen çekirdek dosyaları:

- `agents/red.py`
- `agents/orchestrator.py`
- `services/operations.py`
- `services/application.py`
- `core/tasks.py`
- `storage/repository.py`
- `modules/blue/monitor.py`
- `modules/purple/correlation.py`
- `modules/vulnerability/advisories.py`
- `lab/manager.py`
- `lab/worker.py`
- `reporting/exporter.py`
- `ui/operations_panel.py`
- `ui/main_window.py`
- `app.py`

Testler: `test_blue`, `test_purple`, `test_lab`, `test_reporting`, `test_advisories`, `test_release_integration`, `test_release_hardening` ve güncellenen Qt testleri. Scripts: compatibility, source packaging, release validation/docs ve offline preparation. README, MIT LICENSE, SECURITY, CONTRIBUTING, CHANGELOG, docs, örnek profil ve `.github/workflows/tests.yml` eklendi/güncellendi.

## Düzeltilen hatalar ve sınırlar

- Controller alt görevleri aynı semaphore slotuna kilitlenmez; tek slotla gerçek test geçti.
- Task/audit birlikte transaction; audit hata enjeksiyonunda task değişimi rollback.
- DB symlink reddi; init hatasında instance lock cleanup; bool/ondalık expiry reddi.
- Devam eden işlem scope deadline’ında durdurulur; ayrı expiry regresyonu.
- Blue PID/network cache bounded; auth nofollow/nonblocking regular-file okuma; toplu auth satırları korunur; mixed integrity limited.
- Eski Lab telemetry yeni assessment’a replay edilmez.
- OSV sparse/no-match clean sayılmaz; unavailable analiz Purple’da executed-success sayılmaz.
- `.gitignore` root-anchored; Lab kaynak kodu runtime lab ile birlikte dışlanmaz.
- Son test kayıtlarında failure/error ve skip sayıları yukarıda; eski phase raporları tarihsel olarak kalır.

Lab kernel/filesystem paylaşır, untrusted exploit sandbox değildir. SQLite/raporlar şifreli değildir; manifest imza değildir. Export redaksiyonu tüm sırları garanti etmez. Yalnız owned/authorized hedefler; rol tabanlı planner LLM değildir.

## Kredi

Başlangıç plan bütçesi 3.100, minimum %20 reserve 620 kredidir. Önceden onaylanan 450-credit phase zarfları planlama sınırıdır, gerçek tüketim değildir. Gerçek toplam/kalan Manus kredisi bu oturumda doğrulanamıyor; tam kapsam veya bütçe korunması sayısal olarak garanti edilmedi. Yeni büyük arsenal/VM/IDS aşaması başlatılmadı; mevcut doğrulanmış sürüm ve açık eksikler teslim edilir.
