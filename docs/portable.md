# Portable Linux dağıtımı

SecRam-Pro v0.4.0 için iki portable çıktı vardır:

- `SecRam-Pro-v0.4.0-x86_64.AppImage`: x86_64 Linux için tek dosya.
- `SecRam-Pro-v0.4.0-portable-x86_64.tar.gz`: AppDir içeriği ve launcher.

## AppImage

```bash
chmod +x SecRam-Pro-v0.4.0-x86_64.AppImage
./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
./SecRam-Pro-v0.4.0-x86_64.AppImage --self-check
./SecRam-Pro-v0.4.0-x86_64.AppImage --lab-demo
```

`--lab-demo` yalnız SecRam-Pro’nun kendi geçici loopback Lab’ını kullanır. Yetkili bir değerlendirme için açık kapsam ve izin içeren JSON profilini `--run-assessment profil.json` ile kullanın.

## Sistem sınırları

AppImage Python/Qt çalışma dosyalarını taşır; Linux kernel’i ve host sistem araçlarını taşımaz. Nmap, `ip`, `unshare`, kernel user/network namespace desteği, grafik sürücüsü ve bazı glibc/X11/Wayland bileşenleri host’tan gelir. `--doctor` bunların varlığını raporlar. Eksik sistem bileşeni varsa özellik kullanılamaz; program bunu başarılı tarama gibi göstermez.

Bu nedenle AppImage tam VM/konteyner izolasyonu değildir ve güvenilmeyen exploit çalıştırma ortamı değildir. Rootless Lab mevcut kernel/namespace politikasına bağlıdır. FUSE kapalı sistemlerde AppImage’ı `APPIMAGE_EXTRACT_AND_RUN=1` ile çalıştırmak gerekebilir; bu durumda host’ta `python3 >= 3.12` bulunmalıdır.

Portable tarball:

```bash
tar -xzf SecRam-Pro-v0.4.0-portable-x86_64.tar.gz
cd SecRam-Pro.AppDir
./AppRun --doctor
./AppRun --self-check
```

Checksum dosyaları teslim arşiviyle birlikte verilir. AppImage ve tarball x86_64 sandbox üzerinde üretildi; ARM veya farklı CPU mimarileri için yeniden paketleme gerekir.
