# SecRam-Pro v0.4.0 — özgün kapsam matrisi

Durumlar: **çalışıyor** gerçek yürütme/test kanıtı bulunan işlev; **kısmi** yalnız belirtilen alt kapsam; **yok** entegrasyon/gösterim tamamlanmadı. Bu tablo özgün talimatın tamamının bitirildiği iddiası değildir.

| Özgün alan | Durum | Uygulanan / kalan |
|---|---|---|
| Linux / Fedora / Debian | Kısmi | Gerçek kullanıcı alanı regresyonu; ortak kernel. Native SELinux/kernel/masaüstü ve türev dağıtımlar sertifikalı değil. |
| Windows 10/11 | Kapsamdan çıkarıldı | Kullanıcının Linux-only kararı; destek iddiası yok. |
| Modüler monolit, Python/PySide6/SQLite/asyncio | Çalışıyor | Tek kalıcı TaskEngine; ikinci mikroservis/görev motoru yok. |
| Scope, onay, timeout, iptal, kalıcılık | Çalışıyor | CIDR/port/işlem/süre, yetki kaydı, subprocess iptali, yeniden açılışta interrupted recovery; kullanıcı yetkisi bağımsız doğrulanmaz. |
| Tool Registry / Adapter | Kısmi | Gerçek Python runtime ve Nmap adaptörleri. Diğer araçlar çağrılabilir gibi gösterilmez. |
| Ağ keşfi / TCP | Kısmi | Tek IP/32 TCP portu; toplu CIDR, cihaz/topoloji/DNS/UDP ve sürüm tespiti yok. |
| Nmap | Çalışıyor — sınırlı | Gerçek -sT profili, XML, hata/timeout/cancel/kapsam testi, Orchestrator seçimi. |
| Masscan / theHarvester | Yok | Gerçek adaptör/test yok. |
| Nuclei / Greenbone-OpenVAS | Yok | Şablon/servis adaptörleri ve gerçek doğrulama yok. |
| OWASP ZAP / Burp Community / SQLmap | Yok | OWASP Top 10, auth, XSS/SQLi doğrulaması veya proxy entegrasyonu yok. |
| Metasploit / kontrollü PoC | Yok | Etki doğrulaması ve exploit-safe VM/konteyner altyapısı yok. |
| Wireshark / TShark / Scapy / PCAP | Yok | Canlı paket yakalama, PCAP/protokol analizi yok. |
| Aircrack-ng | Yok | Kablosuz değerlendirme yok. |
| Hashcat / John / parola politikası | Yok | Parola/hash dayanıklılığı değerlendirmesi yok. |
| HTTP / TLS | Kısmi | Kanıtlı başlık/sertifika adayları; sanal host/SNI, tam cipher/protokol enumerasyonu, uygulama mantığı ve istismar yok. |
| OSV / sürüm eşleşmesi | Kısmi | Yerel JSON, PyPI/importlib.metadata, kaynak fingerprint’i, aday eşleşmesi. Hazır feed veya RPM/DEB yok. |
| CVE / CVSS / CPE / NVD / KEV | Yok | OSV gerçek ID/alias’larını koruyabilir; genel CVE motoru/puanlama/güncelleme yok. |
| Tekrar birleştirme / kanıt | Kısmi | HTTP/TLS kural-hedef-port-kapsam birleştirmesi; çapraz tüm-araç doğrulama, uzman false-positive yönetimi yok. |
| Host kaynak/süreç/arayüz/bağlantı | Çalışıyor — sınırlı | Gerçek OS-visible envanter; kısıtlı/erişilemeyen kayıt açık. |
| systemd servisleri | Kısmi | Erişilebilen servis snapshot; host’s systemd rootfs testinde tam doğrulanmaz. |
| journalctl / Linux log | Kısmi | Seçilen auth dosyasının yeni satırları; journal okuyucusu yok. |
| Kullanıcı/izin/firewall/SSH hardening | Yok | nftables/firewalld, SSH yapılandırması ve kullanıcı izin güvenliği incelemesi yok. |
| Blue sürekli izleme | Kısmi | Bağımsız yerel thread, gerçek process/network/auth/integrity/IOC gözlemi, expiry/stop. Polling tam paket kapsamı değildir. |
| Suricata / Zeek / Sigma / YARA | Yok | IDS/rule motoru/eBPF entegrasyonu ve packet-ground-truth yok. |
| Olay inceleme / alarm yönetimi | Kısmi | Gerçek sınıflı gözlemler/audit; incident-case sistemi ve tam alarm yaşam döngüsü yok. |
| Purple ilişkilendirme | Kısmi | Zaman/endpoint aday bağı, açık ID+kural+güvenilir kapsam modeli; gerçek IDS kapsamı kurulu değil. |
| MITRE ATT&CK | Kısmi | Yalnız Nmap T1046; tam teknik/senaryo kataloğu yok. |
| Tespit/FPR/gecikme metrikleri | Kısmi | Kanıt varsa hesaplanabilir; mevcut demo kapsamı tespit/FPR için yetersiz ve null. Sentetik üretim oranı yok. |
| Host Mode / LAN hedefi | Kısmi | Gerçek lokal host ve seçili yetkili LAN IP; hedef liste/aralık yoğunluk ve tam LAN workflow yok. |
| Lab Manager | Kısmi | Rootless user+network namespace sabit HTTP fixture, lifecycle/gateway/telemetri. Kernel/FS ortak; güvenilmeyen PoC için güvenli değil. |
| Podman / Docker / KVM/libvirt | Yok | Image/VM orchestration, filesystem sandbox, kaynak cgroup limitleri ve reset/snapshot yok. |
| Altı bağımsız ajan sorumluluğu | Kısmi | Red planner, Orchestrator, Blue monitor, Purple correlator, Lab manager ve exporter modüler; genel akıllı ajan/blackboard sistemi değil. |
| Dinamik otonom koordinasyon | Kısmi | Sonuca bağlı Nmap→izinli HTTP/TLS, bağımsız Blue, scope recheck, iptal ve rapor. Alternatif araç/retry/çok hedef/LLM planlama yok. |
| Ollama / yerel AI | Yok — isteğe bağlı gereksinim | Temel işlev için LLM/API gerekmez. |
| PySide6 ekranları | Kısmi | Değerlendirme, görev, araç, audit, modül, Host, Nmap, web, bulgu ve altı operasyon paneli. Ayrı packet analyzer, grafik dashboard/ayar merkezi yok. |
| PDF/HTML/JSON/CSV/Markdown | Çalışıyor | Gerçek dosya, SHA-256, HTML kaçış, CSV güvenliği, redaksiyon ve Türkçe font desteği; kaynak/font yoksa açık sınırlama. |
| Yerel/offline/history | Çalışıyor — sınırlı | Runtime mandatory internet/account yok. Initial OS/pip dependencies gerekir. Genel imza/TI updater yok. |
| Şifreli veri / imzalı audit | Yok | SQLite/raporlar şifreli değil; SHA-256 manifest kimlik doğrulama değildir. |
| Test / GitHub dokümantasyonu | Çalışıyor | Kaynak/tests/CI/kullanım belgeleri; GitHub workflow/push henüz çalıştırılmadı. |
| PyInstaller/native binary | Yok | Python kaynak teslimi; frozen binary yayınlanmadı. |
| Tam akademik saldırı-savunma başarısı | Kısmi | Gerçek controlled workflow gösterilebilir; IDS tespit başarısı, FPR ground-truth ve exploit doğruluk ölçümü tamamlanmadı. |

## Bütçe ve durma noktası

Kullanıcının başlangıç bütçesi 3.100 kredi; asgari %20 entegrasyon/hata düzeltme payı 620 kredi olarak planlanır. Gerçek toplam/kalan kredi bu oturumdan doğrulanamıyor; plan zarfı gerçek fatura değildir. Büyük arsenal, native dağıtım sertifikasyonu ve VM/IDS altyapısı için maliyet uydurulmadı. Bu teslim, doğrulanmış mevcut bütünleşik sürüm ve açık kalan işlerdir; tamamlanmayan özellikler bitmiş sayılmadı.
