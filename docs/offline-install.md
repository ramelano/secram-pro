# Çevrimdışı kurulum

Runtime zorunlu internet/API hesabı gerektirmez. Nmap/Qt/OS paketleri ve Python bağımlılıkları önceden sağlanmalıdır; kaynak ZIP’i tek başına bütün binary’leri içermez.

İnternetli ve hedefle aynı Python minor sürüm/ABI/CPU mimarisinde `bash scripts/prepare_offline.sh` çalıştırın. Script pip wheelhouse, kaynak ZIP ve fingerprint manifesti oluşturur; OS paketleri veya Nmap indirmez. Paketlerin kaynağına/lisansına güven değerlendirmesi ayrıca yapılmalıdır; manifest imzalı tedarik zinciri kanıtı değildir.

Çevrimdışı makineye aktarın, ZIP’i açın. Kaynak dizininde (wheelhouse yolunu gerçek konumuna göre değiştirin):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --no-index --find-links ../wheelhouse 'setuptools>=69' wheel
python -m pip install --no-index --find-links ../wheelhouse -r requirements-lock.txt
python -m pip install --no-index --no-build-isolation --no-deps -e .
secram-pro --doctor
secram-pro --lab-demo
```

Wheel yerine sdist gelmişse offline build araçları gerekebilir; ilgili platform için hazır wheel tercih edin. Fedora/Debian glibc, PySide/Qt sistem kütüphaneleri ve Python minor sürümü farklı olabilir; bir wheelhouse tüm makineler için evrensel değildir.

OSV üretim verisi yoktur. Güvendiğiniz kaynaktan önceden edinilen destekli OSV JSON’u `--import-osv` ile yerel içe aktarın. Data yok/eskimiş/kısmi olabilir; no-match clean değildir.

GitHub CI opsiyoneldir ve dependency setup internet kullanabilir. Yerel runtime için GitHub veya Manus servisi gerekmez.
