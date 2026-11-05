# v0.4.0 — gerçek kullanıcı alanı uyumluluğu

| Ortam | Python | Passed | Failed/errors | Skipped | Qt exit |
|---|---|---:|---:|---:|---:|
| Ubuntu sandbox | 3.12.3 | 180 | 0 | 0 | 0 |
| Fedora Linux 43 (Container Image) | Python 3.14.8 | 176 | 0 | 4 | 0 |
| Debian GNU/Linux 13 (trixie) | Python 3.13.5 | 176 | 0 | 4 | 0 |

Kernel: `6.18.38+`. Fedora/Debian resmi OCI rootfs, ayrı mount/PID/network namespaces, testte yalnız loopback. Native kernel/SELinux/systemd/NIC/fiziksel masaüstü sertifikasyonu değildir. Skip başarı sayılmaz.

Ham test kayıtları: `release-test-results.xml`, `compat/fedora43/tests.xml`, `compat/debian13/tests.xml`; imaj digest ve sürümler `compat/summary.json` içinde.
