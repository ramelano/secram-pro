# Kurulum ve çalıştırma

Bu belge ayrıntılı kurulum içindir. Hızlı başlangıç için ana [README](../README.md) dosyasına bakın.

## AppImage

GitHub Release sayfasından AppImage’ı indirin:

```text
https://github.com/ramelano/secram-pro/releases/latest/download/SecRam-Pro-v0.4.0-x86_64.AppImage
```

SHA256 doğrulaması:

```bash
wget https://github.com/ramelano/secram-pro/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Çalıştırma:

```bash
chmod +x SecRam-Pro-v0.4.0-x86_64.AppImage
./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
./SecRam-Pro-v0.4.0-x86_64.AppImage --self-check
./SecRam-Pro-v0.4.0-x86_64.AppImage
```

FUSE kapalıysa:

```bash
APPIMAGE_EXTRACT_AND_RUN=1 ./SecRam-Pro-v0.4.0-x86_64.AppImage
```

AppImage Python/Qt dosyalarını taşır; Nmap, `ip`, `unshare`, Linux kernel namespace yeteneği ve grafik sürücüleri host sistemden gelir. Tam VM/konteyner izolasyonu değildir.

## Portable tarball

```bash
tar -xzf SecRam-Pro-v0.4.0-portable-x86_64.tar.gz
cd SecRam-Pro.AppDir
./AppRun --doctor
./AppRun --self-check
./AppRun
```

## Kaynaktan kurulum

Python 3.12+ ve Linux gerekir. Programı normal kullanıcıyla çalıştırın; `sudo secram-pro` kullanmayın.

### Fedora

```bash
sudo dnf install python3 python3-pip nmap util-linux iproute \
  mesa-libGL mesa-libEGL libxkbcommon fontconfig dbus-libs glib2 dejavu-sans-fonts
```

### Debian veya Ubuntu

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip nmap util-linux iproute2 \
  libgl1 libegl1 libxkbcommon0 libfontconfig1 libdbus-1-3 \
  libglib2.0-0t64 fonts-dejavu-core
```

### Python kurulumu

```bash
cd secram-pro
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
secram-pro --doctor
secram-pro
```

Tekrarlanabilir sürüm kurulumu:

```bash
python -m pip install -r requirements-lock.txt
python -m pip install --no-deps --no-build-isolation -e .
```

`requirements-lock.txt` sürüm kaydıdır; hash’li tedarik zinciri kilidi değildir.

## Veri klasörü

Varsayılan veri klasörü:

```text
~/.local/share/secram-pro
```

Başka klasör:

```bash
mkdir -p "$HOME/secram-verileri"
./SecRam-Pro-v0.4.0-x86_64.AppImage --data-dir "$HOME/secram-verileri"
```

Aynı veri klasörünü iki instance ile aynı anda kullanmayın. Uygulama bunu lock dosyasıyla reddeder. Veritabanı ve raporlar şifreli değildir.

## Sorun giderme

```bash
./SecRam-Pro-v0.4.0-x86_64.AppImage --doctor
./SecRam-Pro-v0.4.0-x86_64.AppImage --self-check
```

Nmap eksikse Fedora’da `sudo dnf install nmap`, Debian/Ubuntu’da `sudo apt install nmap` çalıştırın.

Lab çalışmıyorsa Linux sistemi rootless user/network namespace kullanımına izin vermiyor olabilir. `sudo` veya privileged fallback kullanmayın. Ayrıntı için [testing.md](testing.md) ve [troubleshooting.md](troubleshooting.md) dosyalarına bakın.
