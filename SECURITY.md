# Güvenlik

v0.4.0 geliştirme sürümüdür; üretim güvenlik ürünü, compliance sertifikası veya exploit-safe sandbox değildir.

Yalnız sahip olduğunuz/yetkilendirilmiş hedeflerde kullanın. `approved_by` ve `evidence_reference` alanları serbest metin olarak denetim izi sağlar; **yetkiyi doğrulamaz**. Kullanıcı yetki beyanı bağımsız yetki doğrulaması değildir. Buna karşılık uygulama her görevde değerlendirme kimliği, işlem, literal hedef, port ve yetki süresini yeniden denetler; kapsam dışı veya süresi bitmiş görevleri çalıştırmamalıdır. Bu sürüm serbest komut, exploit, credential theft, persistence, evasion veya destructive response yüzeyi sunmaz.

SQLite/raporlar şifreli değildir. Kaynak repository’ye gerçek müşteri/hedef IP’leri, auth kayıtları, DB, rapor, PCAP, sertifika özel anahtarı veya token koymayın. Redaksiyon her olası sırrı tanımaz. Rapor manifesti dijital imza değildir.

Rootless Lab kernel ve filesystem paylaşır. Yalnız sabit educational HTTP fixture için kullanın; güvenilmeyen PoC/zararlı yazılım çalıştırmayın. Programı normal kullanıcıyla çalıştırın; unshare kullanılamıyorsa sudo veya geniş privileged fallback eklemeyin.

Güvenlik sorunu bildirirken kamuya açık issue içine exploit/kişisel veri/sır dökmeyin. Repository sahibinin belirlediği özel kanal veya etkinse GitHub private security advisory kullanın. Şu an bir e-posta/özel kanal adresi tanımlanmamıştır.

Raporlarda `candidate`, `unknown`, `inconclusive` ayrımlarını koruyun. Açık port, IOC eşleşmesi, yeni süreç veya eksik header tek başına başarılı saldırı/kompromizasyon kanıtı değildir.
