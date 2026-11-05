"""Real operation controls, with explicit limitations instead of placeholder metrics."""
from pathlib import Path
import json
import weakref

from PySide6.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QFormLayout,QLabel,QLineEdit,
                               QPlainTextEdit,QPushButton,QTabWidget,QMessageBox)


class OperationsPanel(QWidget):
    def __init__(self, service, parent_window):
        super().__init__(parent_window)
        self.service = service
        self.owner = weakref.ref(parent_window)
        layout = QVBoxLayout(self)
        self.scope_label = QLabel("Değerlendirme seçin")
        self.scope_label.setWordWrap(True)
        layout.addWidget(self.scope_label)
        tabs=QTabWidget(); layout.addWidget(tabs)
        self.tabs=tabs

        tab, body=self._tab("Otonom / Red", "Kural tabanlı, tek IP ve izinli portlarla Nmap → bulguya bağlı HTTP/TLS → rapor. LLM veya istismar değildir.")
        form=QFormLayout(); body.addLayout(form)
        self.target=QLineEdit("127.0.0.1"); self.ports=QLineEdit(); self.hints=QLineEdit()
        self.ports.setPlaceholderText("80,443 — en fazla 32")
        self.hints.setPlaceholderText("80=http,443=https — yalnız gerekli portlarda")
        form.addRow("Hedef literal IP",self.target); form.addRow("TCP portları",self.ports); form.addRow("Açık protokol ipucu",self.hints)
        self.auto_button=self._button(body,"Yetkili otonom değerlendirmeyi başlat",self.start_auto)
        self.auto_view=self._view(body)

        tab,body=self._tab("Blue", "Host/süreç/ağ gözlemleri, seçilen yeni auth-log satırları, dosya hash değişiklikleri ve kullanıcı IOC IP'leri. Bu veriler tek başına saldırı kanıtı değildir. Journal okuyucusu yok.")
        form=QFormLayout(); body.addLayout(form)
        self.auth=QLineEdit(); self.integrity=QPlainTextEdit(); self.integrity.setMaximumHeight(65)
        self.integrity.setPlaceholderText("Her satıra bir mutlak dosya yolu; en fazla 16 dosya / 4 MiB")
        self.iocs=QLineEdit(); self.iocs.setPlaceholderText("Kendi doğruladığınız IOC IP'leri; virgülle ayırın")
        form.addRow("Auth log — isteğe bağlı",self.auth); form.addRow("Dosya bütünlüğü",self.integrity); form.addRow("IOC IP listesi",self.iocs)
        self.blue_button=self._button(body,"Seçili kapsamla Blue izlemeyi başlat",self.start_blue)
        self.blue_stop_button=self._button(body,"Blue izlemeyi durdur",self.stop_blue)
        self.blue_view=self._view(body)

        tab,body=self._tab("Purple", "Gerçek görev/telemetri zaman çizelgesi. Endpoint/zaman ilişkisi nedensellik değildir. Tam sensör kapsamı ve negatif veri yoksa tespit/yanlış alarm oranları bilinmiyor kalır.")
        self.purple_view=self._view(body)

        tab,body=self._tab("Lab", "Yalnız sabit eğitim HTTP servisi: rootless user+network namespace ve 127.0.0.1 gateway. Kernel ve dosya sistemi paylaşılır; güvenilmeyen exploit için güvenli VM/konteyner değildir.")
        self.lab_button=self._button(body,"Kontrollü rootless Lab oluştur",self.create_lab)
        self.lab_assessment_button=self._button(body,"Bu Lab için yetkili değerlendirme oluştur",self.lab_assessment)
        self.lab_stop_button=self._button(body,"Yalnız bu Lab'i durdur",self.stop_lab)
        self.lab_view=self._view(body)

        tab,body=self._tab("Çevrimdışı OSV", "Yerel OSV JSON → yalnız bu Python ortamının PyPI paket sürümleri. Veri içe aktarılmadan sonuç üretilemez; eşleşme yokluğu sistem temiz anlamına gelmez. RPM/DEB ve tam NVD/CPE yok.")
        self.osv_path=QLineEdit(); self.osv_path.setPlaceholderText("Yerel OSV JSON dosyası")
        body.addWidget(self.osv_path)
        self.osv_import_button=self._button(body,"Yerel OSV verisini içe aktar",self.import_osv)
        self.osv_match_button=self._button(body,"İzinli yerel paket sürümlerini eşleştir",self.match_osv)
        self.osv_view=self._view(body)

        tab,body=self._tab("Raporlar", "JSON, Markdown, HTML, CSV, PDF ve SHA-256 manifesti. Raporlar kişisel/operasyonel veri içerebilir; GitHub'a otomatik yüklenmez. Manifest kimlik doğrulamalı imza değildir.")
        self.output=QLineEdit(); self.output.setPlaceholderText("Boş: kullanıcı veri dizini / reports")
        body.addWidget(self.output)
        self.report_button=self._button(body,"Seçili değerlendirmeyi beş formatta dışa aktar",self.export_report)
        self.report_view=self._view(body)

    def _tab(self,title,note):
        tab=QWidget(); layout=QVBoxLayout(tab)
        label=QLabel(note); label.setWordWrap(True); label.setStyleSheet("color:#665629;")
        layout.addWidget(label); self.tabs.addTab(tab,title)
        return tab,layout

    @staticmethod
    def _view(layout):
        view=QPlainTextEdit(); view.setReadOnly(True); layout.addWidget(view,1); return view

    @staticmethod
    def _button(layout,title,handler):
        button=QPushButton(title); button.clicked.connect(handler); layout.addWidget(button); return button

    def assessment_id(self):
        owner=self.owner()
        identity=owner.selected_assessment_id if owner is not None else None
        if not identity:
            raise ValueError("Önce değerlendirme seçin veya Lab için değerlendirme oluşturun.")
        return identity

    def _show(self,view,result):
        view.setPlainText(json.dumps(result,ensure_ascii=False,indent=2,default=str))
        owner=self.owner()
        if owner is not None:
            owner.refresh_data()

    def _error(self,exc):
        QMessageBox.critical(self,"İşlem gerçekleştirilemedi",str(exc))

    def start_auto(self):
        try:
            from secram.ui.main_window import _parse_ports
            hints={}
            for pair in self.hints.text().split(","):
                if pair.strip():
                    port,scheme=pair.strip().split("=",1); hints[port.strip()]=scheme.strip()
            task=self.service.submit_operation(self.assessment_id(),"Kapsam kontrollü otonom profil","orchestrator.run",
                target=self.target.text(),params={"ports":_parse_ports(self.ports.text()),"web_services":hints})
            self._show(self.auto_view,{"task_id":task.id,"state":task.state.value})
        except Exception as exc: self._error(exc)

    def start_blue(self):
        try:
            task=self.service.start_blue(self.assessment_id(),Path(self.auth.text()) if self.auth.text().strip() else None,
                [Path(p.strip()) for p in self.integrity.toPlainText().splitlines() if p.strip()],
                {ip.strip() for ip in self.iocs.text().split(",") if ip.strip()})
            self._show(self.blue_view,{"task_id":task.id,"state":task.state.value})
        except Exception as exc: self._error(exc)

    def stop_blue(self):
        try: self._show(self.blue_view,self.service.stop_blue())
        except Exception as exc: self._error(exc)

    def create_lab(self):
        try:
            result=self.service.create_lab()
            if result["status"]=="running":
                self.target.setText(result["target"]); self.ports.setText(str(result["port"])); self.hints.setText(f"{result['port']}=http")
            self._show(self.lab_view,result)
        except Exception as exc: self._error(exc)

    def lab_assessment(self):
        try:
            lab=self.service.lab_status()
            if lab["status"]!="running": raise ValueError("Önce kontrollü Lab oluşturun.")
            assessment=self.service.create_assessment("Kontrollü rootless Lab",["127.0.0.1/32"],"Yerel Lab sahibi",
                "GUI: yalnız uygulamanın oluşturduğu geçici loopback Lab için kullanıcı işlemi", expires_hours=1,
                allowed_operations={"core.self_check","orchestrator.run","nmap.tcp_scan","web.http_headers","blue.monitor"},allowed_ports={lab["port"]})
            owner=self.owner()
            if owner is not None: owner._selected_assessment_id=assessment.id
            self.target.setText(lab["target"]); self.ports.setText(str(lab["port"])); self.hints.setText(f"{lab['port']}=http")
            self._show(self.lab_view,lab)
        except Exception as exc: self._error(exc)

    def stop_lab(self):
        try: self._show(self.lab_view,self.service.stop_lab())
        except Exception as exc: self._error(exc)

    def import_osv(self):
        try: self._show(self.osv_view,self.service.import_advisories(Path(self.osv_path.text())))
        except Exception as exc: self._error(exc)

    def match_osv(self):
        try:
            task=self.service.submit_operation(self.assessment_id(),"Yerel OSV eşleştirme","host.advisories")
            self._show(self.osv_view,{"task_id":task.id,"state":task.state.value})
        except Exception as exc: self._error(exc)

    def export_report(self):
        try: self._show(self.report_view,self.service.export_report(self.assessment_id(),Path(self.output.text()) if self.output.text().strip() else None))
        except Exception as exc: self._error(exc)

    def refresh(self):
        owner=self.owner()
        selected=owner.selected_assessment_id if owner is not None else None
        assessment=next((a for a in self.service.list_assessments() if a.id==selected),None)
        operations=assessment.scope.allowed_operations if assessment is not None else set()
        self.scope_label.setText(f"{assessment.title if assessment is not None else 'Değerlendirme seçilmedi'} · {', '.join(sorted(operations)) or 'izin yok'}")
        available=hasattr(self.service,"blue_status")
        self.auto_button.setEnabled(available and {"orchestrator.run","nmap.tcp_scan"}<=operations)
        self.blue_button.setEnabled(available and "blue.monitor" in operations)
        self.osv_match_button.setEnabled(available and "host.advisories" in operations)
        self.report_button.setEnabled(available and bool(selected))
        for button in (self.lab_button,self.lab_stop_button,self.lab_assessment_button,self.osv_import_button,self.blue_stop_button):
            button.setEnabled(available)
        if not available:
            return
        self._show_readonly(self.blue_view,self.service.blue_status())
        self._show_readonly(self.lab_view,self.service.lab_status())
        if selected: self._show_readonly(self.purple_view,self.service.purple_result(selected))
        matches=[t for t in self.service.list_tasks() if t.assessment_id==selected and t.operation=="orchestrator.run"]
        if matches: self._show_readonly(self.auto_view,matches[-1].model_dump(mode="json"))
        matches=[t for t in self.service.list_tasks() if t.assessment_id==selected and t.operation=="host.advisories"]
        if matches: self._show_readonly(self.osv_view,matches[-1].model_dump(mode="json"))
        elif not self.osv_view.toPlainText(): self._show_readonly(self.osv_view,self.service.advisory_status())

    @staticmethod
    def _show_readonly(view,value):
        text=json.dumps(value,ensure_ascii=False,indent=2,default=str)
        if view.toPlainText()!=text: view.setPlainText(text)
