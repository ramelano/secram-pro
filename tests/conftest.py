"""Keep one QApplication and destroy test widgets before interpreter shutdown."""
import gc
import os

import pytest

_QT_APPLICATION = None


@pytest.fixture(scope="session", autouse=True)
def stable_qt_application():
    global _QT_APPLICATION
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    _QT_APPLICATION = QApplication.instance() or QApplication([])
    yield _QT_APPLICATION
    _QT_APPLICATION.processEvents()


@pytest.fixture(autouse=True)
def cleanup_qt_widgets(stable_qt_application):
    yield
    from PySide6.QtCore import QCoreApplication, QEvent
    for widget in stable_qt_application.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    stable_qt_application.processEvents()
    gc.collect()
