"""SecRam-Pro Phase 1 Linux UI.

The service owns persistence and background execution.  This module only
presents service data and makes short, synchronous service calls from UI
handlers; it does not create an event loop, worker thread, or database
connection.
"""
from __future__ import annotations

import json
import ipaddress
from datetime import date, datetime
from enum import Enum
from typing import Any, Iterable

try:
    from PySide6.QtCore import QTimer, Qt
    from PySide6.QtGui import QCloseEvent
    from PySide6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QFormLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QSpinBox,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover - exercised only without the optional GUI dependency
    raise ImportError(
        "SecRam-Pro UI requires PySide6. Install the project dependencies before starting the app."
    ) from exc


_PHASE1_OPERATION = "core.self_check"
_MODULE_STATUS_ROWS = (
    ("Red Team v0.1", "Implemented — sınırlı", "Yetkili tek IP TCP keşfi → izinli HTTP/TLS takipleri → kanıtlı rapor; MITRE T1046; istismar yok."),
    ("Blue", "Partial", "Süreç/ağ gözlemi, seçilmiş auth log, hash ve IOC; journal/eBPF/IDS yok."),
    ("Purple", "Partial", "Kanıtlı zaman çizelgesi; ölçülemeyen oranlar bilinmiyor. Yalnız T1046 eşlemesi."),
    ("Host", "Implemented — sınırlı", "Salt okunur anlık kaynak/süreç/ağ/erişilebilir servis bilgisi."),
    ("Yapılandırma / danışma", "Partial", "HTTP/TLS kanıtlı adaylar ve yerel OSV/PyPI; tam NVD/CPE/Nuclei yok."),
    ("Lab", "Partial", "Rootless sabit HTTP fixture; kernel/filesystem ortak, exploit VM'si değil."),
    ("AI", "Not Implemented", "Yerel model entegrasyonu henüz yok."),
)


def _value(item: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a model-like object or a dict."""
    if item is None:
        return default
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _id(item: Any) -> str:
    return str(_value(item, "id", ""))


def _enum_text(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw) if raw is not None else ""


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    return str(value)


def _json_text(value: Any) -> str:
    if value is None:
        value = {}
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=_json_default,
        )
    except (TypeError, ValueError):
        return json.dumps({"value": str(value)}, ensure_ascii=False, indent=2)


def _plain(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _nmap_summary(result: Any) -> str:
    if not isinstance(result, dict):
        return "Sonuç özeti alınamadı."
    hosts = result.get("hosts") or []
    ports = hosts[0].get("ports", []) if hosts and isinstance(hosts[0], dict) else []
    open_ports = [str(item.get("port")) for item in ports if item.get("state") == "open"]
    closed_ports = [str(item.get("port")) for item in ports if item.get("state") != "open"]
    requested = result.get("requested_ports") or []
    return (
        f"İstenen port: {', '.join(map(str, requested)) or 'yok'} · "
        f"Açık: {', '.join(open_ports) or 'yok'} · "
        f"Kapalı/filtreli: {', '.join(closed_ports) or 'yok'}"
    )


def _parse_ports(text: str) -> list[int]:
    if not text.strip():
        return []
    parts = [part.strip() for part in text.split(",")]
    if any(not part.isascii() or not part.isdecimal() for part in parts):
        raise ValueError("Portlar virgülle ayrılmış sayılar olmalı; aralık veya komut kabul edilmez.")
    ports = [int(part) for part in parts]
    if not 1 <= len(ports) <= 32 or len(set(ports)) != len(ports):
        raise ValueError("1–32 farklı TCP portu girin.")
    if any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("Portlar 1–65535 arasında olmalı.")
    return ports


class MainWindow(QMainWindow):
    """Main Phase 1 window backed by an already-running service instance."""

    def __init__(self, service: Any) -> None:
        super().__init__()
        self.service = service
        self._assessments: list[Any] = []
        self._tasks: list[Any] = []
        self._audit_records: list[Any] = []
        self._tools: list[Any] = []
        self._findings: list[Any] = []
        self._selected_assessment_id: str | None = None
        self._selected_task_id: str | None = None
        self._selected_finding_id: str | None = None
        self._last_refresh_error: str | None = None

        self.setWindowTitle("SecRam-Pro — Linux Güvenlik Platformu")
        self.resize(1180, 760)
        self._build_ui()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(1000)
        self._refresh_timer.timeout.connect(self.refresh_data)
        self._refresh_timer.start()
        self.refresh_data()

    @property
    def selected_assessment_id(self) -> str | None:
        return self._selected_assessment_id

    @property
    def selected_task_id(self) -> str | None:
        return self._selected_task_id

    def _build_ui(self) -> None:
        root = QWidget(self)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(18, 16, 18, 14)
        root_layout.setSpacing(12)

        heading_layout = QHBoxLayout()
        heading = QLabel("SecRam-Pro")
        heading.setObjectName("applicationTitle")
        heading.setStyleSheet("font-size: 22px; font-weight: 700;")
        subtitle = QLabel("v0.4.0 · Linux · kontrollü otonom değerlendirme")
        subtitle.setStyleSheet("color: #536170;")
        heading_layout.addWidget(heading)
        heading_layout.addWidget(subtitle)
        heading_layout.addStretch(1)
        self.counts_label = QLabel("Veritabanı: hazırlanıyor…")
        self.counts_label.setObjectName("databaseCounts")
        self.counts_label.setStyleSheet("font-weight: 600; color: #31465a;")
        heading_layout.addWidget(self.counts_label)
        root_layout.addLayout(heading_layout)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self._build_quick_scan_tab(), "Hızlı Tarama")
        self.tab_widget.addTab(self._build_assessments_tab(), "Değerlendirmeler")
        self.tab_widget.addTab(self._build_tasks_tab(), "Görevler")
        self.tab_widget.addTab(self._build_tools_tab(), "Araçlar")
        self.tab_widget.addTab(self._build_audit_tab(), "İşlem Kaydı")
        self.tab_widget.addTab(self._build_modules_tab(), "Modül Durumu")
        self.tab_widget.addTab(self._build_host_tab(), "Host Mode")
        self.tab_widget.addTab(self._build_nmap_tab(), "LAN / Nmap")
        self.tab_widget.addTab(self._build_web_tab(), "HTTP / TLS")
        self.tab_widget.addTab(self._build_findings_tab(), "Bulgular")
        from secram.ui.operations_panel import OperationsPanel
        self.operations_panel = OperationsPanel(self.service, self)
        self.tab_widget.addTab(self.operations_panel, "Operasyonlar")
        root_layout.addWidget(self.tab_widget, 1)

        self.setCentralWidget(root)
        self.statusBar().showMessage("Hazır")

    def _build_quick_scan_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        intro = QLabel(
            "Başlangıç için burada yalnızca tek IP ve izinli TCP portlarını girin. "
            "Tarama bitince açık/kapalı port sonucu bu ekranda gösterilir ve özel JSON dosyasına kaydedilir. "
            "CIDR aralığı veya hostname bu hızlı ekranda kullanılmaz."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("font-size: 14px; color: #31465a;")
        layout.addWidget(intro)
        form = QFormLayout()
        self.quick_target_input = QLineEdit()
        self.quick_target_input.setPlaceholderText("Örn. 192.168.1.1")
        self.quick_ports_input = QLineEdit("22,80,443")
        self.quick_ports_input.setPlaceholderText("Örn. 22,80,443")
        form.addRow("Hedef IP", self.quick_target_input)
        form.addRow("TCP portları", self.quick_ports_input)
        layout.addLayout(form)
        self.quick_authorization_checkbox = QCheckBox(
            "Bu hedef için açık yetkim olduğunu beyan ediyorum"
        )
        self.quick_authorization_checkbox.toggled.connect(
            lambda checked: self.quick_scan_button.setEnabled(checked)
        )
        layout.addWidget(self.quick_authorization_checkbox)
        self.quick_scan_button = QPushButton("Taramayı Başlat")
        self.quick_scan_button.setEnabled(False)
        self.quick_scan_button.clicked.connect(self._start_quick_scan)
        layout.addWidget(self.quick_scan_button)
        self.quick_result_label = QLabel("Henüz tarama yapılmadı.")
        self.quick_result_label.setWordWrap(True)
        layout.addWidget(self.quick_result_label)
        self.quick_result_view = QPlainTextEdit()
        self.quick_result_view.setReadOnly(True)
        self.quick_result_view.setPlaceholderText("Tarama sonucu burada görünecek.")
        layout.addWidget(self.quick_result_view, 1)
        return tab

    def _build_assessments_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        form_group = QGroupBox("Yeni değerlendirme")
        form = QFormLayout(form_group)
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("Örn. İç ağ ön kontrolü")
        self.cidrs_input = QLineEdit()
        self.cidrs_input.setPlaceholderText("Örn. 192.168.1.0/24, 10.0.0.0/8")
        self.approved_by_input = QLineEdit()
        self.approved_by_input.setPlaceholderText("Yetkiyi beyan eden kişi")
        self.evidence_reference_input = QLineEdit()
        self.evidence_reference_input.setPlaceholderText("Bilet, kayıt veya referans")
        self.expires_hours_input = QSpinBox()
        self.expires_hours_input.setRange(1, 168)
        self.expires_hours_input.setValue(24)
        self.expires_hours_input.setSuffix(" saat")
        form.addRow("Başlık", self.title_input)
        form.addRow("CIDR'lar", self.cidrs_input)
        form.addRow("Onaylayan", self.approved_by_input)
        form.addRow("Kanıt referansı", self.evidence_reference_input)
        form.addRow("Yetki süresi", self.expires_hours_input)

        self.host_permission_checkbox = QCheckBox("Yerel Host verilerinin salt okunur toplanmasına izin ver")
        self.nmap_permission_checkbox = QCheckBox("Kapsam içindeki tek IP'lerde sınırlı Nmap TCP taramasına izin ver")
        self.http_permission_checkbox = QCheckBox("İzinli IP/portlarda salt okunur HTTP başlığı kontrolüne izin ver")
        self.tls_permission_checkbox = QCheckBox("TLS sertifikası incelemesine izin ver; gerekirse yalnız sertifika için doğrulanmamış handshake")
        self.scope_ports_input = QLineEdit()
        self.scope_ports_input.setPlaceholderText("İzinli ağ portları: örn. 22,443 — en fazla 32")
        form.addRow(self.host_permission_checkbox)
        form.addRow(self.nmap_permission_checkbox)
        form.addRow(self.http_permission_checkbox)
        form.addRow(self.tls_permission_checkbox)
        self.blue_permission_checkbox = QCheckBox("Yerel Blue telemetri/log/dosya izlemeye izin ver")
        self.advisory_permission_checkbox = QCheckBox("Bu Python ortamının paket sürümlerini yerel OSV ile eşleştirmeye izin ver")
        self.auto_permission_checkbox = QCheckBox("İzinli alt işlemleri kural tabanlı Orchestrator ile yürütmeye izin ver — Nmap izni ayrıca gerekli")
        form.addRow(self.blue_permission_checkbox)
        form.addRow(self.advisory_permission_checkbox)
        form.addRow(self.auto_permission_checkbox)
        form.addRow("İzinli ağ portları", self.scope_ports_input)

        self.authorization_checkbox = QCheckBox(
            "Bu değerlendirme için açık yetkim olduğunu beyan ediyorum"
        )
        self.authorization_checkbox.setObjectName("authorizationCheckbox")
        self.authorization_note = QLabel(
            "Not: Bu, kullanıcı tarafından beyan edilen yetkilendirmedir; "
            "SecRam-Pro yetkiyi doğrulamaz."
        )
        self.authorization_note.setWordWrap(True)
        self.authorization_note.setStyleSheet("color: #725b28;")
        form.addRow(self.authorization_checkbox)
        form.addRow(self.authorization_note)

        self.create_assessment_button = QPushButton("Değerlendirme Oluştur")
        self.create_assessment_button.setObjectName("createAssessmentButton")
        self.create_assessment_button.setEnabled(False)
        self.authorization_checkbox.toggled.connect(self.create_assessment_button.setEnabled)
        self.create_assessment_button.clicked.connect(self._create_assessment)
        form.addRow(self.create_assessment_button)
        layout.addWidget(form_group)

        self.assessments_table = self._make_table(
            ["Başlık", "CIDR kapsamı", "Onaylayan", "Bitiş", "Kimlik"]
        )
        self.assessments_table.setObjectName("assessmentsTable")
        self.assessments_table.setColumnHidden(4, True)
        self.assessments_table.itemSelectionChanged.connect(self._on_assessment_selected)
        layout.addWidget(QLabel("Kayıtlı değerlendirmeler"))
        layout.addWidget(self.assessments_table, 1)

        action_layout = QHBoxLayout()
        self.start_self_check_button = QPushButton("Çekirdek Kontrolü Başlat")
        self.start_self_check_button.setObjectName("startSelfCheckButton")
        self.start_self_check_button.setToolTip(
            "Python/runtime/veritabanı sağlığını kontrol eder; güvenlik testi değildir."
        )
        self.start_self_check_button.setEnabled(False)
        self.start_self_check_button.clicked.connect(self._start_self_check)
        action_layout.addWidget(self.start_self_check_button)
        action_layout.addWidget(
            QLabel(
                "Çekirdek kontrolü güvenlik testi değildir. Host ve LAN işlemleri ayrı sekmelerde; "
                "yalnızca açıkça izin verilen işlemler yürütülür."
            )
        )
        action_layout.addStretch(1)
        layout.addLayout(action_layout)
        return tab

    def _build_tasks_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        intro = QLabel(
            "Görevler servis tarafından yürütülür. UI arka plan motoru, asyncio veya "
            "veritabanı bağlantısı oluşturmaz."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #536170;")
        layout.addWidget(intro)

        self.tasks_table = self._make_table(
            ["Ad", "İşlem", "Durum", "Değerlendirme", "Hata", "Kimlik"]
        )
        self.tasks_table.setObjectName("tasksTable")
        self.tasks_table.setColumnHidden(5, True)
        self.tasks_table.itemSelectionChanged.connect(self._on_task_selected)
        layout.addWidget(self.tasks_table, 1)

        task_actions = QHBoxLayout()
        self.cancel_task_button = QPushButton("İptal")
        self.cancel_task_button.setObjectName("cancelTaskButton")
        self.cancel_task_button.setEnabled(False)
        self.cancel_task_button.clicked.connect(self._cancel_selected_task)
        task_actions.addWidget(self.cancel_task_button)
        task_actions.addStretch(1)
        layout.addLayout(task_actions)

        detail_group = QGroupBox("Seçili görev çıktısı")
        detail_layout = QVBoxLayout(detail_group)
        self.task_detail_label = QLabel("Görev seçilmedi")
        self.task_detail_label.setWordWrap(True)
        detail_layout.addWidget(self.task_detail_label)
        detail_layout.addWidget(QLabel("Sonuç (JSON)"))
        self.task_result_view = QPlainTextEdit()
        self.task_result_view.setObjectName("taskResultView")
        self.task_result_view.setReadOnly(True)
        self.task_result_view.setMinimumHeight(120)
        detail_layout.addWidget(self.task_result_view)
        detail_layout.addWidget(QLabel("Hata (JSON)"))
        self.task_error_view = QPlainTextEdit()
        self.task_error_view.setObjectName("taskErrorView")
        self.task_error_view.setReadOnly(True)
        self.task_error_view.setMinimumHeight(72)
        detail_layout.addWidget(self.task_error_view)
        layout.addWidget(detail_group)
        self._clear_task_detail()
        return tab

    def _build_tools_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(
            QLabel("Servisin tanıdığı araçlar; kurulum ve entegrasyon durumu salt okunur gösterilir.")
        )
        self.tools_table = self._make_table(
            ["Ad", "Kurulu", "Entegre", "Test edildi", "Destekleniyor", "Detay"]
        )
        self.tools_table.setObjectName("toolsTable")
        layout.addWidget(self.tools_table)
        return tab

    def _build_audit_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("Son işlemler; kayıtlar servisten okunur ve UI tarafından değiştirilmez."))
        self.audit_table = self._make_table(["Zaman", "Olay", "Değerlendirme", "Görev", "İçerik"])
        self.audit_table.setObjectName("auditTable")
        layout.addWidget(self.audit_table)
        return tab

    def _build_modules_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        note = QLabel(
            "Host ve sınırlı Nmap TCP işlemleri mevcut. Diğer modüller çalışır gibi gösterilmez. "
            "Fedora native uyumluluğu henüz doğrulanmadı."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.modules_table = self._make_table(["Modül", "Durum", "Açıklama"])
        self.modules_table.setObjectName("modulesTable")
        self.modules_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.modules_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        for module, status, description in _MODULE_STATUS_ROWS:
            row = self.modules_table.rowCount()
            self.modules_table.insertRow(row)
            for column, text in enumerate((module, status, description)):
                self.modules_table.setItem(row, column, QTableWidgetItem(text))
        layout.addWidget(self.modules_table)
        layout.addStretch(1)
        return tab

    def _build_host_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        note = QLabel("Değerlendirmeler sekmesinden Host izni verilmiş bir kayıt seçin. "
                      "Bu işlem yalnız uygulamanın kurulu olduğu sistemi okur; uzak cihazı incelemez. "
                      "Sürekli izleme veya güvenlik puanı üretmez.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.host_selection_label = QLabel("Değerlendirme seçilmedi")
        layout.addWidget(self.host_selection_label)
        self.start_host_button = QPushButton("Salt Okunur Host Bilgisi Topla")
        self.start_host_button.setEnabled(False)
        self.start_host_button.clicked.connect(self._start_host)
        layout.addWidget(self.start_host_button)
        self.host_result_view = QPlainTextEdit()
        self.host_result_view.setReadOnly(True)
        self.host_result_view.setPlainText("Henüz gerçek Host sonucu yok.")
        layout.addWidget(self.host_result_view, 1)
        return tab

    def _build_nmap_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        note = QLabel("Yalnız seçili kapsam içindeki tek IPv4/IPv6 adresi ve açıkça izinli 1–32 TCP portu. "
                      "DNS, UDP, NSE, istismar ve serbest komut yok. Servis adları sürüm/banner kanıtı değildir.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.nmap_selection_label = QLabel("Değerlendirme seçilmedi")
        self.nmap_selection_label.setWordWrap(True)
        layout.addWidget(self.nmap_selection_label)
        form = QFormLayout()
        self.nmap_target_input = QLineEdit()
        self.nmap_target_input.setPlaceholderText("Kapsam içindeki tek IP; CIDR veya hostname değil")
        self.nmap_ports_input = QLineEdit()
        self.nmap_ports_input.setPlaceholderText("Yalnız izinli TCP portları: örn. 22,443")
        form.addRow("Hedef IP", self.nmap_target_input)
        form.addRow("TCP portları", self.nmap_ports_input)
        layout.addLayout(form)
        self.start_nmap_button = QPushButton("Yetkili TCP Taramasını Başlat")
        self.start_nmap_button.setEnabled(False)
        self.start_nmap_button.clicked.connect(self._start_nmap)
        layout.addWidget(self.start_nmap_button)
        self.nmap_result_view = QPlainTextEdit()
        self.nmap_result_view.setReadOnly(True)
        self.nmap_result_view.setPlainText("Henüz gerçek Nmap sonucu yok.")
        layout.addWidget(self.nmap_result_view, 1)
        return tab

    def _build_web_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        note = QLabel("Yalnız seçili kapsamın tek IP/portu. HTTP: sabit HEAD /, yönlendirme takibi ve kimlik bilgisi yok. "
                      "TLS: sertifika ve görüşülen bağlantı; bütün protokollerin güvenli olduğu iddia edilmez. "
                      "Başlık eksikliği veya sertifika gözlemi otomatik kesin zafiyet değildir.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.web_selection_label = QLabel("Değerlendirme seçilmedi")
        self.web_selection_label.setWordWrap(True)
        layout.addWidget(self.web_selection_label)
        form = QFormLayout()
        self.web_target_input = QLineEdit()
        self.web_target_input.setPlaceholderText("İzinli tek literal IPv4/IPv6")
        self.web_port_input = QSpinBox()
        self.web_port_input.setRange(1, 65535)
        self.web_port_input.setValue(443)
        self.web_scheme_input = QComboBox()
        self.web_scheme_input.addItems(["http", "https"])
        form.addRow("Hedef IP", self.web_target_input)
        form.addRow("İzinli port", self.web_port_input)
        form.addRow("HTTP bağlantısı", self.web_scheme_input)
        layout.addLayout(form)
        actions = QHBoxLayout()
        self.start_http_button = QPushButton("HTTP Başlıklarını Kontrol Et")
        self.start_tls_button = QPushButton("TLS Sertifikasını İncele")
        self.start_http_button.setEnabled(False)
        self.start_tls_button.setEnabled(False)
        self.start_http_button.clicked.connect(self._start_http)
        self.start_tls_button.clicked.connect(self._start_tls)
        actions.addWidget(self.start_http_button)
        actions.addWidget(self.start_tls_button)
        layout.addLayout(actions)
        self.web_result_view = QPlainTextEdit()
        self.web_result_view.setReadOnly(True)
        self.web_result_view.setPlainText("Henüz gerçek HTTP/TLS sonucu yok.")
        layout.addWidget(self.web_result_view, 1)
        return tab

    def _build_findings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        note = QLabel("Seçili değerlendirmenin kanıtlı aday bulguları. Tekrarlar birleştirilir; "
                      "tekrar gözlem kesin zafiyet doğrulaması sayılmaz. CVE/CVSS bu aşamada üretilmez.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.findings_table = self._make_table(["Kural", "Başlık", "Önem", "Durum", "IP / Port"])
        self.findings_table.itemSelectionChanged.connect(self._on_finding_selected)
        layout.addWidget(self.findings_table, 1)
        self.finding_detail_view = QPlainTextEdit()
        self.finding_detail_view.setReadOnly(True)
        self.finding_detail_view.setPlainText("Bulgu seçilmedi.")
        layout.addWidget(self.finding_detail_view, 1)
        return tab

    @staticmethod
    def _make_table(headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        header = table.horizontalHeader()
        header.setStretchLastSection(True)
        for column in range(len(headers)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
        return table

    def refresh_data(self) -> None:
        """Refresh all read-only views while retaining selected rows by stable IDs."""
        try:
            assessments = list(self.service.list_assessments() or [])
            tasks = list(self.service.list_tasks() or [])
            audit_records = list(self.service.list_audit(limit=200) or [])
            tools = list(self.service.list_tools() or [])
            counts = dict(self.service.counts() or {})
            findings_method = getattr(self.service, "list_findings", None)
            findings = list(findings_method() or []) if callable(findings_method) else []
        except Exception as exc:  # refresh failures must not interrupt the timer
            self._show_refresh_error(exc)
            return

        self._assessments = assessments
        self._tasks = tasks
        self._audit_records = audit_records
        self._tools = tools
        self._findings = findings
        self._populate_assessments()
        self._populate_tasks()
        self._populate_tools()
        self._populate_audit()
        self._populate_findings()
        self._update_counts(counts)
        self._refresh_module_results()
        self.operations_panel.refresh()
        self._last_refresh_error = None

    def _show_refresh_error(self, exc: Exception) -> None:
        message = f"Veri yenileme başarısız: {exc}"
        if message != self._last_refresh_error:
            self.statusBar().showMessage(message)
            self._last_refresh_error = message

    def _update_counts(self, counts: dict[str, Any]) -> None:
        labels = {
            "assessments": "Değerlendirme",
            "tasks": "Görev",
            "tools": "Araç",
            "audit": "Kayıt",
            "findings": "Bulgu",
        }
        parts: list[str] = []
        for key, label in labels.items():
            if key in counts:
                parts.append(f"{label}: {_plain(counts[key])}")
        known = set(labels)
        for key in sorted(set(counts) - known):
            parts.append(f"{key}: {_plain(counts[key])}")
        self.counts_label.setText("Veritabanı: " + (" · ".join(parts) if parts else "0"))

    def _populate_assessments(self) -> None:
        table = self.assessments_table
        wanted = self._selected_assessment_id
        table.blockSignals(True)
        try:
            table.setRowCount(0)
            for assessment in self._assessments:
                scope = _value(assessment, "scope")
                authorization = _value(assessment, "authorization")
                row = table.rowCount()
                table.insertRow(row)
                values = (
                    _plain(_value(assessment, "title", "")),
                    ", ".join(_plain(cidr) for cidr in (_value(scope, "cidrs", []) or [])),
                    _plain(_value(authorization, "approved_by", "")),
                    _plain(_value(scope, "expires_at", "")),
                    _id(assessment),
                )
                for column, text in enumerate(values):
                    item = QTableWidgetItem(text)
                    if column == 0:
                        item.setData(Qt.ItemDataRole.UserRole, _id(assessment))
                    table.setItem(row, column, item)
        finally:
            table.blockSignals(False)
        row = self._row_for_id(table, wanted)
        if row < 0 and table.rowCount() and not wanted:
            row = 0
        self._select_row(table, row)
        self._selected_assessment_id = self._row_id(table, row)
        self._update_action_enabled_state()

    def _populate_tasks(self) -> None:
        table = self.tasks_table
        wanted = self._selected_task_id
        table.blockSignals(True)
        try:
            table.setRowCount(0)
            for task in self._tasks:
                row = table.rowCount()
                table.insertRow(row)
                values = (
                    _plain(_value(task, "name", "")),
                    _plain(_value(task, "operation", "")),
                    _enum_text(_value(task, "state", "")),
                    _plain(_value(task, "assessment_id", "")),
                    _plain(_value(task, "error", "") or ""),
                    _id(task),
                )
                for column, text in enumerate(values):
                    item = QTableWidgetItem(text)
                    if column == 0:
                        item.setData(Qt.ItemDataRole.UserRole, _id(task))
                    table.setItem(row, column, item)
        finally:
            table.blockSignals(False)
        row = self._row_for_id(table, wanted)
        if row < 0 and table.rowCount() and not wanted:
            row = 0
        self._select_row(table, row)
        self._selected_task_id = self._row_id(table, row)
        self._update_task_detail()

    def _populate_tools(self) -> None:
        table = self.tools_table
        table.setRowCount(0)
        for tool in self._tools:
            row = table.rowCount()
            table.insertRow(row)
            values = (
                _plain(_value(tool, "name", "")),
                self._yes_no(_value(tool, "installed", False)),
                self._yes_no(_value(tool, "integrated", False)),
                self._yes_no(_value(tool, "tested", False)),
                self._yes_no(_value(tool, "supported", False)),
                _plain(_value(tool, "details", "")),
            )
            for column, text in enumerate(values):
                table.setItem(row, column, QTableWidgetItem(text))

    def _populate_audit(self) -> None:
        table = self.audit_table
        table.setRowCount(0)
        for record in self._audit_records:
            row = table.rowCount()
            table.insertRow(row)
            payload = _value(record, "payload", {}) or {}
            values = (
                _plain(_value(record, "timestamp", "")),
                _plain(_value(record, "event", "")),
                _plain(_value(record, "assessment_id", "") or ""),
                _plain(_value(record, "task_id", "") or ""),
                _json_text(payload),
            )
            for column, text in enumerate(values):
                table.setItem(row, column, QTableWidgetItem(text))

    @staticmethod
    def _yes_no(value: Any) -> str:
        if value is None:
            return "Doğrulanmadı"
        return "Evet" if bool(value) else "Hayır"

    @staticmethod
    def _row_for_id(table: QTableWidget, wanted: str | None) -> int:
        if not wanted:
            return -1
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item is not None and str(item.data(Qt.ItemDataRole.UserRole)) == wanted:
                return row
        return -1

    @staticmethod
    def _select_row(table: QTableWidget, row: int) -> None:
        if row >= 0:
            table.selectRow(row)
            table.setCurrentCell(row, 0)
        else:
            table.clearSelection()
            table.setCurrentItem(None)

    def _on_assessment_selected(self) -> None:
        row = self.assessments_table.currentRow()
        self._selected_assessment_id = self._row_id(self.assessments_table, row)
        self._update_action_enabled_state()
        self._populate_findings()
        self._refresh_module_results()

    def _on_task_selected(self) -> None:
        row = self.tasks_table.currentRow()
        self._selected_task_id = self._row_id(self.tasks_table, row)
        self._update_task_detail()

    @staticmethod
    def _row_id(table: QTableWidget, row: int) -> str | None:
        if row < 0:
            return None
        item = table.item(row, 0)
        if item is None:
            return None
        value = item.data(Qt.ItemDataRole.UserRole)
        return str(value) if value else None

    def _update_action_enabled_state(self) -> None:
        assessment = next((a for a in self._assessments if _id(a) == self._selected_assessment_id), None)
        scope = _value(assessment, "scope")
        operations = _value(scope, "allowed_operations", set()) or set()
        self.start_self_check_button.setEnabled("core.self_check" in operations)
        self.cancel_task_button.setEnabled(bool(self._selected_task_id))
        self.start_host_button.setEnabled("host.snapshot" in operations)
        nmap_status = next((tool for tool in self._tools if _value(tool, "name") == "nmap"), None)
        installed = _value(nmap_status, "installed", False) is True
        self.start_nmap_button.setEnabled("nmap.tcp_scan" in operations and installed)
        title = _value(assessment, "title", "Değerlendirme seçilmedi")
        self.host_selection_label.setText(str(title))
        ports = sorted(_value(scope, "allowed_ports", set()) or set())
        self.nmap_selection_label.setText(f"{title} · İzinli portlar: {','.join(map(str, ports)) or 'yok'} "
                                         f"· Nmap: {'kurulu' if installed else 'kullanılamıyor'}")
        self.start_http_button.setEnabled("web.http_headers" in operations)
        self.start_tls_button.setEnabled("web.tls_check" in operations)
        self.web_selection_label.setText(f"{title} · İzinli portlar: {','.join(map(str, ports)) or 'yok'}")

    def _refresh_module_results(self) -> None:
        for operation, view in (("host.snapshot", self.host_result_view),
                                ("nmap.tcp_scan", self.nmap_result_view)):
            matches = [task for task in self._tasks if _value(task, "operation") == operation
                       and _value(task, "assessment_id") == self._selected_assessment_id]
            if not matches:
                view.setPlainText("Henüz bu değerlendirmeye ait gerçek sonuç yok.")
                continue
            task = matches[-1]
            view.setPlainText(_json_text({"task_id": _id(task), "state": _enum_text(_value(task, "state")),
                                         "error": _value(task, "error"), "result": _value(task, "result", {})}))
        matches = [task for task in self._tasks if _value(task, "operation") in {"web.http_headers", "web.tls_check"}
                   and _value(task, "assessment_id") == self._selected_assessment_id]
        if matches:
            task = matches[-1]
            self.web_result_view.setPlainText(_json_text({"task_id": _id(task), "state": _enum_text(_value(task, "state")),
                                                         "error": _value(task, "error"), "result": _value(task, "result", {})}))
        else:
            self.web_result_view.setPlainText("Henüz bu değerlendirmeye ait gerçek HTTP/TLS sonucu yok.")

    def _populate_findings(self) -> None:
        table = self.findings_table
        table.blockSignals(True)
        selected = self._selected_finding_id
        try:
            table.setRowCount(0)
            for finding in self._findings:
                if _value(finding, "assessment_id") != self._selected_assessment_id:
                    continue
                row = table.rowCount()
                table.insertRow(row)
                values = [_value(finding, "rule_id"), _value(finding, "title"),
                          _enum_text(_value(finding, "severity")), _enum_text(_value(finding, "status")),
                          f"{_value(finding, 'target')}:{_value(finding, 'port')}"]
                for column, text in enumerate(values):
                    item = QTableWidgetItem(str(text))
                    if column == 0:
                        item.setData(Qt.ItemDataRole.UserRole, _id(finding))
                    table.setItem(row, column, item)
        finally:
            table.blockSignals(False)
        row = self._row_for_id(table, selected)
        if row < 0 and table.rowCount():
            row = 0
        self._select_row(table, row)
        self._on_finding_selected()

    def _on_finding_selected(self) -> None:
        self._selected_finding_id = self._row_id(self.findings_table, self.findings_table.currentRow())
        finding = next((f for f in self._findings if _id(f) == self._selected_finding_id), None)
        self.finding_detail_view.setPlainText(_json_text(finding) if finding is not None else "Bulgu seçilmedi.")

    def _create_assessment(self) -> None:
        if not self.authorization_checkbox.isChecked():
            QMessageBox.warning(
                self,
                "Yetkilendirme gerekli",
                "Değerlendirme oluşturmak için açık yetki beyanını işaretleyin.",
            )
            return
        title = self.title_input.text().strip()
        cidrs = [part.strip() for part in self.cidrs_input.text().split(",") if part.strip()]
        approved_by = self.approved_by_input.text().strip()
        evidence_reference = self.evidence_reference_input.text().strip()
        expires_hours = self.expires_hours_input.value()
        if not title or not cidrs or not approved_by or not evidence_reference:
            QMessageBox.warning(
                self,
                "Eksik bilgi",
                "Başlık, en az bir CIDR, onaylayan ve kanıt referansı zorunludur.",
            )
            return
        if not 1 <= expires_hours <= 168:
            QMessageBox.warning(self, "Geçersiz süre", "Yetki süresi 1 ile 168 saat arasında olmalıdır.")
            return
        try:
            operations = {"core.self_check"}
            if self.host_permission_checkbox.isChecked():
                operations.add("host.snapshot")
            if self.http_permission_checkbox.isChecked():
                operations.add("web.http_headers")
            if self.tls_permission_checkbox.isChecked():
                operations.add("web.tls_check")
            if self.blue_permission_checkbox.isChecked():
                operations.add("blue.monitor")
            if self.advisory_permission_checkbox.isChecked():
                operations.add("host.advisories")
            if self.auto_permission_checkbox.isChecked():
                if not self.nmap_permission_checkbox.isChecked():
                    raise ValueError("Otonom ağ değerlendirmesi için ayrı Nmap iznini işaretleyin.")
                operations.add("orchestrator.run")
            ports = set()
            if self.nmap_permission_checkbox.isChecked():
                operations.add("nmap.tcp_scan")
            if operations & {"nmap.tcp_scan", "web.http_headers", "web.tls_check"}:
                ports = set(_parse_ports(self.scope_ports_input.text()))
                if not ports:
                    raise ValueError("Ağ kontrolleri için portları açıkça belirtin.")
            assessment = self.service.create_assessment(
                title=title,
                cidrs=cidrs,
                approved_by=approved_by,
                evidence_reference=evidence_reference,
                expires_hours=expires_hours,
                allowed_operations=operations,
                allowed_ports=ports,
            )
            self._selected_assessment_id = _id(assessment) or None
            self.authorization_checkbox.setChecked(False)
            self.statusBar().showMessage("Değerlendirme oluşturuldu.")
            self.refresh_data()
        except Exception as exc:
            self._show_action_error("Değerlendirme oluşturulamadı", exc)

    def _start_self_check(self) -> None:
        assessment_id = self._selected_assessment_id
        if not assessment_id:
            QMessageBox.warning(self, "Değerlendirme seçin", "Önce bir değerlendirme seçin.")
            return
        assessment = next(
            (item for item in self._assessments if _id(item) == assessment_id), None
        )
        title = _plain(_value(assessment, "title", "Değerlendirme"))
        try:
            task = self.service.submit_operation(
                assessment_id=assessment_id,
                name=f"Çekirdek Kontrolü — {title}",
                operation=_PHASE1_OPERATION,
                target=None,
            )
            self._selected_task_id = _id(task) or None
            self.statusBar().showMessage(
                "Çekirdek kontrolü gönderildi; bu işlem güvenlik testi değildir."
            )
            self.refresh_data()
        except Exception as exc:
            self._show_action_error("Çekirdek kontrolü başlatılamadı", exc)

    def _start_host(self) -> None:
        try:
            if not self._selected_assessment_id:
                raise ValueError("Önce değerlendirme seçin.")
            task = self.service.submit_operation(self._selected_assessment_id, "Yerel Host bilgisi", "host.snapshot")
            self._selected_task_id = _id(task)
            self.statusBar().showMessage("Salt okunur Host görevi gönderildi.")
            self.refresh_data()
        except Exception as exc:
            self._show_action_error("Host görevi başlatılamadı", exc)

    def _start_nmap(self) -> None:
        try:
            if not self._selected_assessment_id:
                raise ValueError("Önce değerlendirme seçin.")
            ports = _parse_ports(self.nmap_ports_input.text())
            if not ports:
                raise ValueError("TCP portlarını açıkça girin.")
            target = self.nmap_target_input.text()
            task = self.service.submit_operation(self._selected_assessment_id, "Yetkili Nmap TCP", "nmap.tcp_scan",
                                                 target=target, params={"ports": ports})
            self._selected_task_id = _id(task)
            self.statusBar().showMessage("Kapsamı doğrulanmış Nmap görevi gönderildi.")
            self.refresh_data()
        except Exception as exc:
            self._show_action_error("Nmap görevi başlatılamadı", exc)

    def _start_quick_scan(self) -> None:
        try:
            if not self.quick_authorization_checkbox.isChecked():
                raise ValueError("Tarama için açık yetki beyanını işaretleyin.")
            target = self.quick_target_input.text().strip()
            address = ipaddress.ip_address(target)
            if address.is_unspecified or address.is_multicast or address.is_reserved:
                raise ValueError("Geçerli bir unicast IPv4/IPv6 hedefi girin.")
            ports = _parse_ports(self.quick_ports_input.text())
            assessment = self.service.create_assessment(
                "Hızlı TCP taraması",
                [f"{address}/{'128' if address.version == 6 else '32'}"],
                "GUI kullanıcısı",
                "GUI hızlı tarama yetki beyanı",
                expires_hours=1,
                allowed_operations={"nmap.tcp_scan"},
                allowed_ports=set(ports),
            )
            self._selected_assessment_id = _id(assessment)
            task = self.service.submit_operation(
                self._selected_assessment_id,
                "Hızlı Nmap TCP taraması",
                "nmap.tcp_scan",
                target=str(address),
                params={"ports": ports},
            )
            self.statusBar().showMessage("Tarama çalışıyor; sonuç bekleniyor…")
            self.service.wait_idle(70)
            completed = self.service.repository.get_task(task.id)
            result_path = self.service.save_task_result(task.id)
            payload = completed.model_dump(mode="json")
            payload["result_file"] = str(result_path)
            self.quick_result_label.setText(
                f"Durum: {completed.state.value} · {_nmap_summary(payload.get('result'))}\n"
                f"Sonuç dosyası: {result_path}"
            )
            self.quick_result_view.setPlainText(_json_text(payload))
            self.quick_authorization_checkbox.setChecked(False)
            self.statusBar().showMessage("Tarama tamamlandı; sonuç bu ekranda ve JSON dosyasında.")
            self.refresh_data()
        except Exception as exc:
            self._show_action_error("Hızlı tarama başlatılamadı", exc)

    def _start_http(self) -> None:
        self._start_web("web.http_headers")

    def _start_tls(self) -> None:
        self._start_web("web.tls_check")

    def _start_web(self, operation: str) -> None:
        try:
            if not self._selected_assessment_id:
                raise ValueError("Önce değerlendirme seçin.")
            params = {"scheme": self.web_scheme_input.currentText()} if operation == "web.http_headers" else {}
            task = self.service.submit_operation(self._selected_assessment_id, operation, operation,
                                                 target=self.web_target_input.text(), port=self.web_port_input.value(),
                                                 params=params)
            self._selected_task_id = _id(task)
            self.statusBar().showMessage("Kapsam kontrollü HTTP/TLS görevi gönderildi.")
            self.refresh_data()
        except Exception as exc:
            self._show_action_error("HTTP/TLS görevi başlatılamadı", exc)

    def _cancel_selected_task(self) -> None:
        task_id = self._selected_task_id
        if not task_id:
            QMessageBox.warning(self, "Görev seçin", "Önce iptal edilecek görevi seçin.")
            return
        try:
            self.service.cancel_task(task_id)
            self.statusBar().showMessage("Görev iptal isteği gönderildi.")
            self.refresh_data()
        except Exception as exc:
            self._show_action_error("Görev iptal edilemedi", exc)

    def _show_action_error(self, title: str, exc: Exception) -> None:
        QMessageBox.critical(self, title, str(exc))
        self.statusBar().showMessage(f"{title}: {exc}")

    def _update_task_detail(self) -> None:
        task = next((item for item in self._tasks if _id(item) == self._selected_task_id), None)
        if task is None:
            self._clear_task_detail()
            self._update_action_enabled_state()
            return
        state = _enum_text(_value(task, "state", ""))
        self.task_detail_label.setText(
            f"{_plain(_value(task, 'name', 'Görev'))} · "
            f"{_plain(_value(task, 'operation', ''))} · durum: {state}"
        )
        self.task_result_view.setPlainText(_json_text(_value(task, "result", {}) or {}))
        error = _value(task, "error", None)
        self.task_error_view.setPlainText(_json_text({"error": error} if error else {}))
        self._update_action_enabled_state()

    def _clear_task_detail(self) -> None:
        self.task_detail_label.setText("Görev seçilmedi")
        self.task_result_view.setPlainText("{}")
        self.task_error_view.setPlainText("{}")

    def closeEvent(self, event: QCloseEvent) -> None:
        # Application shutdown owns service/database cleanup.  The UI only stops its timer.
        self._refresh_timer.stop()
        event.accept()


__all__ = ["MainWindow"]
