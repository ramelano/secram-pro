# Test ve kanıt yöntemi

`QT_QPA_PLATFORM=offscreen python -m pytest -q` unit, storage, policy, adapter, gerçek loopback HTTP/TLS/Nmap, Qt ve gerçek rootless Lab/Orchestrator entegrasyonlarını birlikte yürütür. Test doubles/OSV-TEST kayıtları yalnız test fixture’larıdır; üretim sonuçları olarak gösterilmez.

Gerçek otonom test: uygulama owned loopback HTTP Lab açar → izinli ephemeral TCP portuyla assessment oluşturur → Nmap’i çağırır → açık portta HEAD yapar → gerçek request telemetry okur → candidate findings/Purple oluşturur → gerçek JSON/MD/HTML/CSV/PDF dosyası yazar → own process/gateway kapanır. Nmap XML ve PDF magic/header kontrollü çıktıları kontrol edilir.

Fedora/Debian yöntemi: resmi OCI kullanıcı alanı, hazırlanmış OS/Python paketleri, chroot ve mount/PID/network namespace; test sırasında yalnız lo aktif. Kernel host ile ortaktır. Python/SQLite/Qt/Nmap kullanıcı alanı uyumluluğudur; native SELinux, cgroups, firewall/systemd, NIC sürücüsü ve grafik masaüstü sertifikasyonu değildir. Normal kullanıcının bilgisayarında otomatik uygulanmaz.

Kontrollü test makinesinde mevcut ortam için `bash scripts/compat_linux.sh update` ve `bash scripts/compat_linux.sh test`; ilk hazırlama için `prepare`. sudo/unshare/mount/chroot/skopeo/umoci gerekir. Package update internet kullanabilir; test fazı izole ağdadır.

GitHub CI üç OCI kullanıcı alanında test için tanımlanmıştır. GitHub’da henüz çalıştırılmamıştır; default CI container’da user namespace kapalıysa Lab gerçek testleri reason ile skip edilir. Skip, başarı kanıtı değildir; kendi native sisteminizde `--lab-demo` ile yeniden doğrulayın.

Son sonuçlar `release-report.md`, `release-test-results.xml`, `compat/` ve `compatibility-matrix.md` dosyalarında. Tarihsel phase1/2/3 raporları tarihsel kapsamlarını korur; güncel sürüm durumunu yeni rapor/matris belirler.
