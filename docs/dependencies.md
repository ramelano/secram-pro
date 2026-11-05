# Bağımlılıklar

Aşağıdaki lisanslar kurulu dağıtım metadatasından kaydedilmiştir; güncel hukuki yorum veya tüm binary yeniden dağıtım yükümlülüklerinin incelemesi değildir. SecRam-Pro kaynak kodunun MIT lisansı üçüncü taraf lisansları değiştirmez.

| Doğrudan bağımlılık | Test sürümü | Metadata lisansı | Kullanım / offline |
|---|---|---|---|
| PySide6 | 6.12.0 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only | Qt desktop; kurulum sonrası yerel. Ticari Qt lisansı temel sistem için zorunlu değil. |
| Pydantic | 2.14.2 | MIT | Modeller / yerel |
| SQLAlchemy | 2.1.6 | MIT | SQLite / yerel |
| psutil | 7.2.2 | BSD-3-Clause | OS-visible telemetry / yerel |
| defusedxml | 0.7.1 | PSFL | Güvenli XML / yerel |
| cryptography | 48.0.1 | Apache-2.0 OR BSD-3-Clause | TLS sertifika / yerel |
| ReportLab | 4.5.1 | BSD license; dağıtımın license.txt dosyası | PDF / yerel |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | PyPI sürüm eşleşmesi / yerel |
| pytest — geliştirme | 9.2.0 | MIT | Test / yerel |

Tam transitive test sürümleri `requirements-lock.txt` ve dağıtım kanıtındaki `python-packages.txt` dosyalarında bulunur. Pillow/charset-normalizer, shiboken/Qt essentials ve diğer transitif paketler kendi dağıtım lisanslarıyla kalır; wheelhouse/frozen binary yayınında ayrıca korunmalıdır.

Nmap harici sistem binary’sidir. Ubuntu paketindeki `/usr/share/doc/nmap/copyright` değeri `nmap-GPL-2`/istisnalı lisans olarak kaydedildi; diğer dağıtım/upstream sürümlerinde lisans farklı olabilir. Seçilen paketin gerçek copyright/lisans dosyasını okuyun. Nmap veya Qt binary’si kaynak ZIP’ine dahil değildir.

Rootless Lab `unshare`/`ip` sistem araçları ve kernel user/network namespace desteğini kullanır. Ücretsiz yerel araçlardır; varlıkları izolasyon iznini garanti etmez. Paket yöneticisi/OS dependencies offline için ayrıca hazırlanır. DejaVu fontu PDF’de Türkçe karakter içindir; sistem font paketinin lisansı kendisine aittir.

Ücretli API, abonelik, bulut LLM, zorunlu Ollama veya cloud hesabı yoktur. GitHub Actions opsiyoneldir; GitHub hesabının plan/minute koşulları uygulama runtime’ına bağımlılık değildir. Mevcut kaynakta internetli veri güncelleme servisi veya ücretli üçüncü taraf araç yoktur.
