# Test ve kanıt yöntemi

## Yerel test

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

Bu komut policy, storage, adapter, gerçek loopback HTTP/TLS/Nmap, Qt ve rootless Lab/Orchestrator entegrasyonlarını birlikte çalıştırır. Test double’ları ve `OSV-TEST-*` kayıtları yalnızca test fixture’ıdır; üretim sonucu değildir.

Gerçek otonom test akışı: uygulama kendi loopback HTTP Lab’ını açar → izinli ephemeral TCP portuyla assessment oluşturur → Nmap’i çağırır → açık portta HEAD yapar → telemetry okur → candidate finding/Purple oluşturur → JSON/MD/HTML/CSV/PDF yazar → kendi process/gateway’ini kapatır.

## Fedora/Debian uyumluluk testi

Fedora 43 ve Debian 13 testleri resmi OCI kullanıcı alanlarında, aynı Linux kernel üzerinde yürütülür. Bu testler Python/SQLite/Qt/Nmap kullanıcı alanı uyumluluğunu gösterir; native SELinux, cgroups, firewall/systemd, NIC sürücüsü veya fiziksel grafik masaüstü sertifikasyonu değildir.

Rootless Lab için iki ayrı koşul gerekir:

1. `unshare -Urn true` çalışmalı.
2. Uygulamanın `unshare` içindeki sabit Lab worker’ı loopback gateway’e başarıyla bağlanmalı.

Host veya CI container user namespace’i kapatırsa Lab testleri **skip** edilir ve skip gerekçesi test çıktısında görünür. Skip, Lab’ın çalıştığı anlamına gelmez. `sudo` veya privileged fallback kullanılmaz.

Kontrollü test makinesindeki dağıtım testleri:

```bash
bash scripts/compat_linux.sh prepare
bash scripts/compat_linux.sh update
bash scripts/compat_linux.sh test
```

Bu script kontrollü bir test makinesinde sudo/OCI/chroot/mount/network namespace araçları gerektirir; günlük kurulum aracı değildir.

## GitHub Actions CI

Workflow dosyası [`.github/workflows/tests.yml`](../.github/workflows/tests.yml) Ubuntu host üzerinde Ubuntu 24.04, Fedora 43 ve Debian 13 container matrix’i çalıştırır.

Her matrix işi:

- dağıtım paketlerini kurar,
- Python lock dosyasını ve projeyi kurar,
- `pytest` sonuçlarını JUnit XML olarak üretir,
- `unshare -Urn true` probe sonucunu `namespace-probe.txt` artifact’ine koyar,
- test ve probe çıktılarını GitHub Actions artifact’i olarak saklar.

Böylece Fedora/Debian Lab testleri atlandıysa neden yalnızca varsayılmaz; CI artifact’inde namespace probe ve pytest skip nedeni incelenebilir. Namespace yetkisi olan bir CI runner’da aynı testler gerçek Lab akışını çalıştırır.

README’deki CI rozeti GitHub Actions workflow durumuna bağlıdır. Yerel sandbox sonucu CI sonucu değildir; Ubuntu sandbox doğrulaması ayrı bir yerel kanıttır.

## Kanıtı yorumlama

- `passed`: Test senaryosu bu ortamda yürütüldü ve geçti.
- `failed`: Kod veya ortam problemi var; başarı sayılmaz.
- `skipped`: Koşul sağlanmadı; özellik doğrulanmış sayılmaz.
- `inconclusive`: Ürün gerçek bir sonuç üretemedi; temiz veya güvenli sonucu değildir.

Raporlarda `candidate`, `unknown` ve `inconclusive` ayrımları korunur. Açık port, IOC eşleşmesi, yeni süreç veya eksik header tek başına başarılı saldırı/kompromizasyon kanıtı değildir.
