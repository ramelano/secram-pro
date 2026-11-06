"""Small UI contract tests for SecRam-Pro Phase 1.

These tests use a local FakeService only; they never exercise the live
service, engine, storage, or database.
"""
from __future__ import annotations

import os
from datetime import timedelta

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from secram.core.models import (  # noqa: E402
    Assessment,
    AuditRecord,
    Authorization,
    Scope,
    Task,
    TaskState,
    utcnow,
)
from secram.ui.main_window import MainWindow  # noqa: E402


class FakeService:
    """Deterministic in-memory service double for UI-only behavior."""

    def __init__(self) -> None:
        self.assessments: list[Assessment] = []
        self.tasks: list[Task] = []
        self.audit: list[AuditRecord] = []
        self.tools = [
            {
                "name": "python",
                "installed": True,
                "integrated": True,
                "tested": True,
                "supported": True,
                "details": "Runtime health provider",
            }
        ]

    def create_assessment(
        self,
        title: str,
        cidrs: list[str],
        approved_by: str,
        evidence_reference: str,
        expires_hours: int = 24,
        allowed_operations: set[str] | None = None,
        allowed_ports: set[int] | None = None,
    ) -> Assessment:
        assessment = Assessment(
            title=title,
            scope=Scope(
                cidrs=cidrs,
                allowed_operations=allowed_operations or {"core.self_check"},
                allowed_ports=allowed_ports or set(),
                expires_at=utcnow() + timedelta(hours=expires_hours),
            ),
            authorization=Authorization(
                approved_by=approved_by,
                evidence_reference=evidence_reference,
                statement="Kullanıcı tarafından beyan edilen yetki; doğrulama yapılmadı.",
            ),
        )
        self.assessments.append(assessment)
        return assessment

    def submit_operation(
        self,
        assessment_id: str,
        name: str,
        operation: str,
        target: str | None = None,
        port: int | None = None,
        params: dict | None = None,
        dependencies: list[str] | None = None,
    ) -> Task:
        assert operation == "core.self_check"
        assert target is None
        task = Task(
            assessment_id=assessment_id,
            name=name,
            operation=operation,
            target=target,
            port=port,
            params=params or {},
            dependencies=dependencies or [],
            state=TaskState.SUCCEEDED,
            result={"healthy": True, "security_test": False},
        )
        self.tasks.append(task)
        return task

    def cancel_task(self, task_id: str) -> None:
        for task in self.tasks:
            if task.id == task_id:
                task.state = TaskState.CANCELLED
                return
        raise KeyError(task_id)

    def list_assessments(self) -> list[Assessment]:
        return list(self.assessments)

    def list_tasks(self) -> list[Task]:
        return list(self.tasks)

    def list_audit(self, limit: int = 200) -> list[AuditRecord]:
        return list(self.audit)[-limit:]

    def list_tools(self) -> list[dict]:
        return list(self.tools)

    def counts(self) -> dict[str, int]:
        return {
            "assessments": len(self.assessments),
            "tasks": len(self.tasks),
            "tools": len(self.tools),
            "audit": len(self.audit),
        }


@pytest.fixture(scope="session")
def qt_app() -> QApplication:
    app = QApplication.instance() or QApplication([])
    return app


def _process_events(qt_app: QApplication) -> None:
    qt_app.processEvents()


def test_tab_labels_and_empty_service_are_safe(qt_app: QApplication) -> None:
    window = MainWindow(FakeService())
    labels = [window.tab_widget.tabText(i) for i in range(window.tab_widget.count())]
    assert labels == [
        "Hızlı Tarama",
        "Değerlendirmeler",
        "Görevler",
        "Araçlar",
        "İşlem Kaydı",
        "Modül Durumu",
        "Host Mode",
        "LAN / Nmap",
        "HTTP / TLS",
        "Bulgular",
        "Operasyonlar",
    ]
    assert window.assessments_table.rowCount() == 0
    assert window.tasks_table.rowCount() == 0
    window.close()
    _process_events(qt_app)


def test_authorization_checkbox_gates_assessment_creation(qt_app: QApplication) -> None:
    window = MainWindow(FakeService())
    assert not window.create_assessment_button.isEnabled()
    window.authorization_checkbox.setChecked(True)
    assert window.create_assessment_button.isEnabled()
    window.authorization_checkbox.setChecked(False)
    assert not window.create_assessment_button.isEnabled()
    window.close()
    _process_events(qt_app)


def test_quick_scan_is_gated_by_authorization_checkbox(qt_app: QApplication) -> None:
    window = MainWindow(FakeService())
    assert not window.quick_scan_button.isEnabled()
    window.quick_authorization_checkbox.setChecked(True)
    assert window.quick_scan_button.isEnabled()
    window.quick_authorization_checkbox.setChecked(False)
    assert not window.quick_scan_button.isEnabled()
    window.close()
    _process_events(qt_app)


def test_self_check_result_is_json_and_selection_survives_refresh(qt_app: QApplication) -> None:
    service = FakeService()
    first = service.create_assessment(
        "İlk değerlendirme", ["192.168.1.0/24"], "tester", "TICKET-1"
    )
    service.create_assessment("İkinci değerlendirme", ["10.0.0.0/8"], "tester", "TICKET-2")
    window = MainWindow(service)
    window.assessments_table.selectRow(1)
    _process_events(qt_app)
    selected_assessment_id = window.selected_assessment_id
    assert selected_assessment_id is not None

    service.create_assessment("Yeni değerlendirme", ["172.16.0.0/12"], "tester", "TICKET-3")
    window.refresh_data()
    assert window.selected_assessment_id == selected_assessment_id

    window.assessments_table.selectRow(0)
    _process_events(qt_app)
    window.start_self_check_button.click()
    _process_events(qt_app)
    assert window.tasks_table.rowCount() == 1
    window.tasks_table.selectRow(0)
    _process_events(qt_app)
    assert '"healthy": true' in window.task_result_view.toPlainText()

    selected_task_id = window.selected_task_id
    assert selected_task_id is not None
    service.submit_operation(first.id, "İkinci kontrol", "core.self_check", target=None)
    window.refresh_data()
    assert window.selected_task_id == selected_task_id
    window.close()
    _process_events(qt_app)
