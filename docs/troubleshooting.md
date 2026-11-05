# Sorun giderme

**Nmap yok / düğme pasif:** `nmap --version`, `secram-pro --doctor` kullanın. Nmap’i kendi OS paket yöneticinizle kurun; discovery oturum başlangıcında cache’lendiği için uygulamayı yeniden başlatın. Scope’da Nmap/port izni de gereklidir.

**Scope/port/işlem reddi:** CIDR, izinli operation, port alt kümesi ve expiry kontrol edin. Orchestrator için ayrı Nmap izni gerekir. İzinli subnet otomatik subnet taraması anlamına gelmez. API default assessment yalnız core.self_check izni verir.

**Qt xcb plugin:** Gerçek DISPLAY/Wayland oturumu ve Qt native kütüphanelerini doğrulayın. Debian’da `libxcb-cursor0 libxkbcommon-x11-0`, Fedora’da `xcb-util-cursor libxkbcommon-x11` paketleri gerekebilir; kurulu Qt plugin’inin `ldd` çıktısıyla eksikleri belirleyin. Headless test için `QT_QPA_PLATFORM=offscreen`; bu masaüstü çözümü değildir. Native grafik sürücüsü bu teslimde sertifikalı değildir.

**Lab notavailable:** `unshare`/`ip` binary veya kernel unprivileged user/network namespace izni olmayabilir. Container/CI/AppArmor/policy engelini reason alanından okuyun. Kernel güvenlik sınırlarını otomatik kapatmayın; uygulamayı sudo/privileged modda çalıştırıp başarı taklidi yapmayın. Normal yetkili Host/Nmap işlemleri ayrı çalışabilir.

**Blue auth veri yok:** Yalnız açıkça verilen okunabilir regular auth dosyasının yeni append satırları okunur. Journal reader yok; Fedora yalnız journald kullanıyorsa dosya olmayabilir. Symlink/çok büyük bütünlük dosyası ve permission failure açık limitation olarak görünür. Network polling kısa bağlantıları kaçırabilir; tam IDS değildir.

**OSV eşleşme yok:** Snapshot yok/eksik/eskimiş veya ekosistem desteklenmiyor olabilir. Yalnız bu Python ortamının PyPI paketleri eşleşir, host RPM/DEB paketleri değil. `clean:false` ve no-match birlikte olabilir, bu doğrudur.

**PDF unavailable / Türkçe font:** ReportLab ve DejaVu font paketini doğrulayın. `unavailable_formats` ve limitations alanını okuyun; boş/sahte PDF üretilmez.

**İkinci instance / interrupted:** Aynı data-dir ile ikinci uygulama açılamaz. READY/RUNNING recovery FAILED yapar; otomatik rerun yoktur. Ayrı `--data-dir` veya önceki uygulamanın kapanması gerekir.

**GitHub’a yanlış dosya ekleme:** `git status --short` kontrol edin; .env, private-export, DB, auth/PCAP, gerçek rapor ve anahtarları çıkartın. Ignore kuralları her kullanıcı seçimi/custom export yolunu otomatik tanımaz.
