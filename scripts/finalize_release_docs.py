"""Generate final release docs only from completed, recorded test evidence."""
import json
from pathlib import Path
import platform
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]


def counts(path):
    suites=ET.parse(path).getroot().findall('testsuite')
    result={key:sum(int(s.get(key,0)) for s in suites) for key in ('tests','failures','errors','skipped')}
    result['passed']=result['tests']-result['failures']-result['errors']-result['skipped']
    return result


def main():
    compat=json.loads((ROOT/'docs/compat/summary.json').read_text())
    evidence=json.loads((ROOT/'docs/release-evidence/validation-summary.json').read_text())
    ubuntu=counts(ROOT/'docs/release-test-results.xml')
    rows=[{'name':'Ubuntu sandbox','python':platform.python_version(),'counts':ubuntu,'gui_exit':int((ROOT/'docs/release-evidence/gui-exit-code.txt').read_text())}]
    rows.extend({'name':row['os'],'python':row['python'],'counts':{**row['tests'],'passed':row['tests']['tests']-row['tests']['failures']-row['tests']['errors']-row['tests']['skipped']},'gui_exit':row['gui_exit']} for row in compat['results'])
    table=['| Ortam | Python | Passed | Failed/errors | Skipped | Qt exit |','|---|---|---:|---:|---:|---:|']
    for row in rows:
        c=row['counts']; table.append(f"| {row['name']} | {row['python']} | {c['passed']} | {c['failures']+c['errors']} | {c['skipped']} | {row['gui_exit']} |")
    matrix='# v0.4.0 — gerçek kullanıcı alanı uyumluluğu\n\n'+ '\n'.join(table)+ '\n\nKernel: `'+compat['shared_kernel']+'`. Fedora/Debian resmi OCI rootfs, ayrı mount/PID/network namespaces, testte yalnız loopback. Native kernel/SELinux/systemd/NIC/fiziksel masaüstü sertifikasyonu değildir. Skip başarı sayılmaz.\n\nHam test kayıtları: `release-test-results.xml`, `compat/fedora43/tests.xml`, `compat/debian13/tests.xml`; imaj digest ve sürümler `compat/summary.json` içinde.\n'
    (ROOT/'docs/compatibility-matrix.md').write_text(matrix,encoding='utf-8')
    file_list=['agents/red.py','agents/orchestrator.py','services/operations.py','services/application.py','core/tasks.py','storage/repository.py','modules/blue/monitor.py','modules/purple/correlation.py','modules/vulnerability/advisories.py','lab/manager.py','lab/worker.py','reporting/exporter.py','ui/operations_panel.py','ui/main_window.py','app.py']
    report='# SecRam-Pro v0.4.0 — teslim raporu\n\n**Çalışan bütünleşik geliştirme sürümü; özgün tam kapsam tamamlanmadı.** Nuclei/ZAP/ileri arsenal, paket IDS, VM/konteyner Lab ve genel CVE/CVSS/CPE yok. [Tam matris](requirements-matrix.md). GitHub push/workflow henüz çalıştırılmadı.\n\n## Gerçek işlev ve test\n\n'+ '\n'.join(table)+f"\n\nOwned rootless Lab → gerçek Nmap TCP → gerçek HEAD → actual lab request telemetry → Purple → beş format rapor zinciri `{evidence['workflow_status']}`. Süre: {evidence['duration_seconds']:.3f} s; aday bulgu: {evidence['candidate_findings']}; Nmap XML SHA-256: `{evidence.get('nmap_xml_sha256')}`.\n\nPurple tespit/FPR: `{evidence['purple_metrics'].get('detection_rate')}` / `{evidence['purple_metrics'].get('false_positive_rate')}`: bilinmiyor; paket/IDS kapsamı ve etiketli negatif veri yokken sıfıra çevrilmedi. Kaynak ölçümü yalnız validation Python süreci lifetime highwater; çocuklar/host veya yalnız operasyon peak ölçümü değildir.\n\nGerçek XML/JSON/PDF kanıtı `release-evidence/`; [örnek gerçek PDF](release-evidence/example-lab-report.pdf). Qt giriş/kapanış ve CLI doctor/self-check kanıtı aynı klasörde. Native/gerçek LAN cihazında üretim sertifikasyonu yapılmadı.\n\n## Dosyalar\n\n`src/secram/` altında yeni/değişen çekirdek dosyaları:\n\n" + '\n'.join('- `'+name+'`' for name in file_list)+'\n\nTestler: `test_blue`, `test_purple`, `test_lab`, `test_reporting`, `test_advisories`, `test_release_integration`, `test_release_hardening` ve güncellenen Qt testleri. Scripts: compatibility, source packaging, release validation/docs ve offline preparation. README, MIT LICENSE, SECURITY, CONTRIBUTING, CHANGELOG, docs, örnek profil ve `.github/workflows/tests.yml` eklendi/güncellendi.\n\n## Düzeltilen hatalar ve sınırlar\n\n- Controller alt görevleri aynı semaphore slotuna kilitlenmez; tek slotla gerçek test geçti.\n- Task/audit birlikte transaction; audit hata enjeksiyonunda task değişimi rollback.\n- DB symlink reddi; init hatasında instance lock cleanup; bool/ondalık expiry reddi.\n- Devam eden işlem scope deadline’ında durdurulur; ayrı expiry regresyonu.\n- Blue PID/network cache bounded; auth nofollow/nonblocking regular-file okuma; toplu auth satırları korunur; mixed integrity limited.\n- Eski Lab telemetry yeni assessment’a replay edilmez.\n- OSV sparse/no-match clean sayılmaz; unavailable analiz Purple’da executed-success sayılmaz.\n- `.gitignore` root-anchored; Lab kaynak kodu runtime lab ile birlikte dışlanmaz.\n- Son test kayıtlarında failure/error ve skip sayıları yukarıda; eski phase raporları tarihsel olarak kalır.\n\nLab kernel/filesystem paylaşır, untrusted exploit sandbox değildir. SQLite/raporlar şifreli değildir; manifest imza değildir. Export redaksiyonu tüm sırları garanti etmez. Yalnız owned/authorized hedefler; rol tabanlı planner LLM değildir.\n\n## Kredi\n\nBaşlangıç plan bütçesi 3.100, minimum %20 reserve 620 kredidir. Önceden onaylanan 450-credit phase zarfları planlama sınırıdır, gerçek tüketim değildir. Gerçek toplam/kalan Manus kredisi bu oturumda doğrulanamıyor; tam kapsam veya bütçe korunması sayısal olarak garanti edilmedi. Yeni büyük arsenal/VM/IDS aşaması başlatılmadı; mevcut doğrulanmış sürüm ve açık eksikler teslim edilir.\n'
    (ROOT/'docs/release-report.md').write_text(report,encoding='utf-8')
    print(json.dumps({'tests':rows,'workflow':evidence['workflow_status'],'docs':['docs/compatibility-matrix.md','docs/release-report.md']},ensure_ascii=False,indent=2))


if __name__=='__main__': main()
