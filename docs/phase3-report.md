# SecRam-Pro — Phase 3 sonuç raporu

## Onaylanan kapsam

Fedora/Debian kullanıcı alanı uyumluluk testleri; yetkili tek IP/port için salt okunur HTTP/TLS kontrolleri; kanıtlı aday bulgu modeli, tekrar birleştirme, UI ve kalıcılık. Sürüm **0.3.0**. Phase 4 başlatılmadı.

## Gerçek uyumluluk matrisi

| Ortam | Python | Nmap | Son test sonucu | Test / GUI çıkışı |
|---|---|---|---|---|
| Ubuntu sandbox | 3.12.3 | 7.94SVN | 128 passed, 10.89 s | 0 / 0 |
| Fedora Linux 43 Container Image | 3.14.8 | 7.92 | 128 passed, 12.86 s | 0 / 0 |
| Debian GNU/Linux 13 trixie | 3.13.5 | 7.95 | 128 passed, 10.78 s | 0 / 0 |

Her son koşuda başarısız, hatalı veya atlanan test sayısı **0**. Testler gerçek Python, Qt, psutil, SQLite ve Nmap binary'leriyle çalıştı. Dağıtımlarda tam regresyon seti, gerçek yerel Nmap açık port testi, Host toplama, HTTP/TLS ve UI entegrasyonu dahil edildi. Headless uygulama başlangıç/kapanışı ayrıca exit 0 verdi.

Fedora/Debian ortamları resmî OCI rootfs'lerinden skopeo/umoci ile hazırlandı. Ayrı mount/PID/network namespace ve yalnız loopback kullanıldı. Paket hazırlığı internetten indirme yaptı; test çalışması ağ namespace'inde dış bağlantısızdı. Paylaşılan kernel **6.18.38+**.

**Bu sonuç native Fedora/Debian kernel, SELinux/AppArmor, PID 1 systemd, fiziksel GPU/Wayland/X11 masaüstü veya diğer dağıtım sürümleri doğrulaması değildir.** systemd yokluğu ve izin eksikleri, gerçek durumun açık raporlanması ve kontrollü hata testleriyle ele alındı; native servis yönetimi test edildiği iddia edilmedi.

İmaj digest'leri, kullanılan paketler, dağıtım/Python/Nmap sürümleri ve ham test kayıtları `docs/compat/` içinde; makine okunur matris `docs/compat/summary.json`.

## Eklenen gerçek işlevler

**HTTP (`web.http_headers`):** Tek literal IPv4/IPv6 ve açıkça izinli port. Sabit `HEAD /`, yönlendirme/body/kimlik bilgisi yok. HTTPS'te CA ve IP doğrulaması zorunlu; hata halinde doğrulanmamış HTTP isteği gönderilmez. Başlık alanı en fazla 64 KiB; seçilen değer ve süre sınırları var. Eksik/analiz edilemeyen yanıt `inconclusive`, bulgu listesi boş.

HTML/XHTML için CSP ve frame politikası yokluğu; uygun yanıtlarda nosniff/referrer politikası yokluğu gözlenir. CSP frame-ancestors mevcutken X-Frame-Options yokluğu yanlış eksik frame politikası sayılmaz. Bunlar bağlama bağlı yapılandırma adaylarıdır, exploit veya kesin zafiyet değildir.

**TLS (`web.tls_check`):** Doğrulanan bağlantı veya açık işlem izniyle yalnız sertifika toplamak için tek ek doğrulanmamış handshake. Sertifika hash/tarih/IP SAN/anahtar bilgisi, güven kontrolü ve görüşülen TLS/cipher kaydedilir. Süresi geçmiş, henüz geçerli olmayan, güven doğrulaması başarısız veya literal-IP isim uyuşmazlığı adayları üretilebilir. TLS kontrolünde HTTP gönderilmez. Modern görüşülen TLS, eski protokollerin kapalı olduğunu kanıtlamaz. Domain/SNI sanal host analizi yoktur.

**Bulgular:** Kararlı değerlendirme/IP/port/kural kimliği; önem, kanıt, kaynak görev, düzeltme, UTC zaman ve sınırlamalar. Varsayılan `candidate`; tekrarlar otomatik `verified` yapmaz. Farklı kapsamlar birleşmez. Bulgular mevcut SQLite görev sonuçlarında kalıcı; şema v1 korunur. Yeniden açılma ve tekrar birleştirme gerçek entegrasyon testleriyle doğrulandı.

**UI:** Ayrı HTTP/TLS izinleri, dokuz sekme, gerçek kontrol sonucu ve seçili değerlendirmeye ait kanıtlı aday bulgular.

## Yerel gerçek kanıt

```bash
python scripts/validate_phase3.py --output docs/phase3-evidence
```

Script kendi geçici loopback HTML ve TLS servislerini açtı. TLS servisinde gerçekten süresi geçmiş, kendinden imzalı test sertifikası kullanıldı. Gerçek HTTP/TLS görevleri `succeeded`; toplam **6 aday**: CSP/frame/nosniff/referrer yokluğu, güven doğrulaması yapılamayan ve süresi geçmiş sertifika.

Hepsi `candidate`; etkileri/istismar edilebilirliği doğrulanmadı. Test Set-Cookie değeri sonuçta saklanmadı. TLS özel anahtarı geçici dizinde temizlendi, kanıt veya ZIP'e eklenmedi. `docs/phase3-evidence/http-tls-validation.json` gerçek görev/gözlem/bulgu kaydıdır; sabit ürün çıktısı değildir.

## Dosyalar

**Yeni:**
- `modules/vulnerability/checks.py`, `findings.py`, `__init__.py`
- `tests/test_web_checks.py`, `test_web_safety.py`, `test_findings.py`, `test_phase3_integration.py`, `conftest.py`
- `scripts/compat_linux.sh`, `summarize_compat.py`, `validate_phase3.py`
- Bu rapor, `docs/phase3-*`, `docs/phase3-evidence/`, `docs/compat/`

**Değiştirilen:** `core/policies.py` ortak literal hedef kontrolü; `tools/adapters/nmap.py` bu ortak kontrolü kullanır; `services/application.py` yeni işlemler ve bulgu sorgusu; `ui/main_window.py`; `tests/test_ui.py`; `pyproject.toml`, `requirements-lock.txt`, `README.md`.

Yeni Python bağımlılığı cryptography 48.0.1. PySide6 6.12.0, Pydantic 2.14.2, SQLAlchemy 2.1.6, psutil 7.2.2. Nmap ayrı sistem paketidir. Ücretli API/bulut açılmadı; web araştırması yapılmadı. Kullanıcının bilgisayarı, firewall veya SELinux ayarları değiştirilmedi.

## Görülen ve giderilen hatalar

1. Sağlayıcının `evidence_sha256` alanı bulgu çıktı sözleşmesinde eksikti; strict model ve kanıt kaynağı düzeltildi.
2. Qt test kapanışında exit 134/139 bellek hatası görüldü. Pencereyi tutan lambda döngüleri bağlı metotlara dönüştürüldü; testte tek QApplication ve zamanında widget temizliği eklendi. Son üç ortamda test ve smoke çıkışı 0.
3. Debian'ın minimal rootfs'inde `libglib-2.0.so.0` eksikti; yalnız test rootfs'ine `libglib2.0-0t64` eklendi. İlk hatalı XML/metin ve kurulum kaydı `docs/compat/debian13/` içinde korundu. Hazırlama scripti bağımlılığı içerir.
4. Fedora'nın venv symlink'i host dosya sisteminde yanlış kontrol edilerek “environment missing” üretildi. Python varlık kontrolü gerçek chroot içinde yapıldı; yeniden kurulum gerekmeksizin gerçek Fedora testi geçti.
5. Fedora paket indirmesi yavaştı; süreç/log/artifact kontrolü yapıldı, sessizlik hata sayılmadı ve iş yeniden başlatılmadı.
6. Eksik HTTP terminatörü, uzun seçili başlık ve mevcut CSP frame-ancestors için yanlış bulgu riskleri engellendi; regresyon testleri eklendi.

## Kapsam dışı ve kredi

CVE/CVSS, Nuclei, istismar, hostname/SNI değerlendirmesi, bütün TLS protokol/cipher kombinasyonlarının testi, geniş subnet taraması, sürekli Blue izleme, otonom Red/Purple, Lab Manager ve native masaüstü dağıtım paketi bu aşamada yok.

Toplam plan **3.100 kredi**, Phase 3 onaylanan zarf **450 kredi**, korunan entegrasyon/hata rezervi **en az 620 kredi**. Bunlar plan değerleridir. Doğrulanabilir kredi sayacı erişilebilir olmadığından gerçek tüketim, gerçek kalan bakiye veya rezervin fiilen korunmuş tutarı kesin sayı olarak verilemedi. 450 kredinin harcandığı ya da bütçenin kesin altında kalındığı iddia edilmez.

Kaynak ZIP; kod, testler, kullanım ve kanıtları içerir. Rootfs imajları, venv, çalışma veritabanları ve test özel anahtarı dahil değildir. Phase 1/2 ZIP'leri değiştirilmedi. Sonraki aşama için ayrı kapsam/bütçe onayı gerekir.

Yalnızca yetkili ve yasal ortamlarda kullanın.
