"""Main application window: stacked pages + sidebar navigation."""

from __future__ import annotations

import logging
from importlib import resources
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from ..auth import AuthManager
from ..config import Settings
from ..engine import load_all_benchmarks
from ..engine.runner import RunResult
from .pages.benchmarks_page import BenchmarksPage
from .pages.connect_page import ConnectPage
from .pages.reports_page import ReportsPage
from .pages.results_page import ResultsPage
from .pages.run_page import RunPage

log = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    benchmarks_loaded = pyqtSignal(list)
    auth_changed = pyqtSignal(object)
    run_finished = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Sec-Benchmarks")
        self.resize(1180, 760)

        self.settings = Settings.load()
        self.auth = AuthManager()
        self.benchmarks = load_all_benchmarks()
        self.last_run: Optional[RunResult] = None

        self._apply_stylesheet()
        self._build_ui()
        self.benchmarks_loaded.emit(self.benchmarks)

    # -------------------------------------------------------- styling helpers
    def _apply_stylesheet(self) -> None:
        try:
            files = resources.files("secbench.gui")
            with resources.as_file(files.joinpath("style.qss")) as p:
                self.setStyleSheet(Path(p).read_text(encoding="utf-8"))
        except Exception:
            pass

    # ----------------------------------------------------------------- layout
    def _build_ui(self) -> None:
        central = QWidget(self)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.nav = QListWidget()
        self.nav.setFixedWidth(200)
        for label in ("Connect", "Benchmarks", "Run", "Results", "Reports"):
            QListWidgetItem(label, self.nav)
        self.nav.setCurrentRow(0)

        self.stack = QStackedWidget()
        self.connect_page = ConnectPage(self)
        self.benchmarks_page = BenchmarksPage(self)
        self.run_page = RunPage(self)
        self.results_page = ResultsPage(self)
        self.reports_page = ReportsPage(self)
        for w in (
            self.connect_page,
            self.benchmarks_page,
            self.run_page,
            self.results_page,
            self.reports_page,
        ):
            self.stack.addWidget(w)

        layout.addWidget(self.nav)
        layout.addWidget(self.stack, 1)

        self.setCentralWidget(central)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)

        sb = QStatusBar()
        self.status_label = QLabel("Not signed in")
        sb.addWidget(self.status_label)
        sb.addPermanentWidget(QLabel("Sec-Benchmarks 0.1.0"))
        self.setStatusBar(sb)

        # Wire cross-page signals.
        self.auth_changed.connect(self._on_auth_changed)
        self.run_finished.connect(self._on_run_finished)

    # ---------------------------------------------------------------- signals
    def _on_auth_changed(self, bundle) -> None:
        if bundle is None:
            self.status_label.setText("Not signed in")
        else:
            self.status_label.setText(
                f"Signed in via {bundle.method.value} (tenant {bundle.tenant_id or 'unknown'})"
            )

    def _on_run_finished(self, run: RunResult) -> None:
        self.last_run = run
        self.results_page.load(run)
        self.reports_page.set_run(run)
        self.nav.setCurrentRow(3)

    # ------------------------------------------------------------ shutdown
    def closeEvent(self, event):  # noqa: N802 - Qt API
        try:
            self.settings.save()
            self.auth.sign_out()
        finally:
            super().closeEvent(event)
