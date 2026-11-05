# Katkı

Python 3.12+ Linux ortamında `python -m pip install -e '.[dev]'` ve `QT_QPA_PLATFORM=offscreen python -m pytest -q` kullanın.

Çalışan kodu önce okuyun; küçük ve test edilebilir değişiklikler yapın. Yeni ağ işlemi ayrı operation ID/izin, literal hedef/port doğrulaması, timeout, bounded output ve subprocess cleanup içermelidir. Engine/policy kapısını atlayan ikinci yürütme altyapısı eklemeyin.

Gerçek testleri yalnız kendi geçici loopback fixture veya açıkça izinli lab’da çalıştırın. Mock/unit fixture’larını üretim telemetrisi gibi sunmayın. Araç yalnız binary detection ile entegre sayılmaz: gerçek çağrı, normalized output, hata/cancel/scope testleri ve distro durumu gerekir.

Gerekçesiz bağımlılık/ücretli API eklemeyin. Lisans, offline durum ve uyumluluk bilgisini güncelleyin. Canary/test CVE’leri `OSV-TEST-*` olarak ayırın. Bilinmeyen metrikleri sıfıra çevirmeyin.

Yeni özellik için test, README/kapsam matrisi ve CHANGELOG güncellemesi gönderin. Rapor/DB/sır dosyalarını commit etmeyin. Rootless Lab yetersizliğini `--privileged` veya otomatik sudo ile gizlemeyin.
