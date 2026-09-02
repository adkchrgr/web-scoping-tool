"""PyQt front end for Web Scoping Tool."""

from __future__ import annotations

import sys
from functools import partial
from pathlib import Path
from threading import Event

import pyttsx3
import qdarkstyle
from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from web_scoping_core import (
    CheckResult,
    ScanOutcome,
    build_http_session,
    check_waf,
    collect_http_diagnostics,
    generate_html_report,
    normalize_url,
    open_report,
    scan_urls,
    url_to_filename,
)

SCREENSHOT_DIRECTORY = Path("screenshots")
REPORT_FILE = Path("web_check_report.html")


class ScanWorker(QObject):
    """Run blocking scan operations away from the GUI thread."""

    progress = pyqtSignal(int, int, str)
    finished = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, urls: list[str], waf_check_enabled: bool) -> None:
        super().__init__()
        self.urls = urls
        self.waf_check_enabled = waf_check_enabled
        self._cancel_requested = Event()

    def cancel(self) -> None:
        """Request cooperative cancellation from the GUI thread."""
        self._cancel_requested.set()

    @pyqtSlot()
    def run(self) -> None:
        browser: webdriver.Chrome | None = None
        http_session = build_http_session()

        def take_screenshot(url: str) -> str:
            nonlocal browser
            if browser is None:
                browser = WebScopingApp.create_browser()
            return WebScopingApp.take_screenshot(browser, url, SCREENSHOT_DIRECTORY)

        def report_progress(completed: int, total: int, result: CheckResult) -> None:
            self.progress.emit(completed, total, result.url)

        try:
            outcome = scan_urls(
                self.urls,
                waf_check_enabled=self.waf_check_enabled,
                take_screenshot=take_screenshot,
                status_checker=partial(collect_http_diagnostics, client=http_session),
                waf_checker=partial(check_waf, client=http_session),
                should_cancel=self._cancel_requested.is_set,
                on_progress=report_progress,
            )
            self.finished.emit(outcome)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            if browser is not None:
                browser.quit()
            http_session.close()


class WebScopingApp(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.scan_thread: QThread | None = None
        self.scan_worker: ScanWorker | None = None
        self.init_ui()

    def init_ui(self) -> None:
        self.setWindowTitle("Web Checking Tool")
        self.setGeometry(100, 100, 500, 350)

        heading_font = QFont("Helvetica", 16)
        label_font = QFont("Helvetica", 12)

        self.label_heading = QLabel("Web Checking Tool")
        self.label_heading.setFont(heading_font)
        self.label_heading.setAlignment(Qt.AlignCenter)

        self.label_description = QLabel(
            "Enter a URL or select a file containing URLs. "
            "Optionally, enable the WAF heuristic check."
        )
        self.label_description.setFont(label_font)
        self.label_description.setWordWrap(True)

        self.label_url = QLabel("Enter URL or Select File:")
        self.label_url.setFont(label_font)

        self.entry_url = QLineEdit(self)
        self.entry_url.setFont(label_font)

        self.button_browse = QPushButton("Browse", self)
        self.button_browse.setFont(label_font)
        self.button_browse.clicked.connect(self.browse_file)

        self.waf_check_toggle = QCheckBox("Include WAF Check", self)
        self.waf_check_toggle.setFont(label_font)

        self.button_run_scoping = QPushButton("Run Web Check", self)
        self.button_run_scoping.setFont(label_font)
        self.button_run_scoping.clicked.connect(self.run_web_scoping)

        self.button_cancel = QPushButton("Cancel Scan", self)
        self.button_cancel.setFont(label_font)
        self.button_cancel.setEnabled(False)
        self.button_cancel.clicked.connect(self.cancel_scan)

        self.label_progress = QLabel("Ready")
        self.label_progress.setFont(label_font)

        layout = QVBoxLayout(self)
        layout.addWidget(self.label_heading)
        layout.addWidget(self.label_description)
        layout.addSpacing(20)
        layout.addWidget(self.label_url)
        layout.addWidget(self.entry_url)
        layout.addWidget(self.button_browse)
        layout.addWidget(self.waf_check_toggle)
        layout.addWidget(self.button_run_scoping)
        layout.addWidget(self.button_cancel)
        layout.addWidget(self.label_progress)
        layout.addSpacing(20)

        self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())

    def browse_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File",
            str(Path.home()),
            "Text files (*.txt);;All files (*)",
        )
        if file_path:
            self.entry_url.setText(file_path)

    @staticmethod
    def load_urls(value: str) -> list[str]:
        candidate = Path(value).expanduser()
        if candidate.is_file():
            raw_urls = candidate.read_text(encoding="utf-8").splitlines()
        else:
            raw_urls = [value]

        urls: list[str] = []
        for raw_url in raw_urls:
            if not raw_url.strip():
                continue
            urls.append(normalize_url(raw_url))

        if not urls:
            raise ValueError("No valid URLs were supplied")
        return urls

    @staticmethod
    def create_browser() -> webdriver.Chrome:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1440,1200")
        return webdriver.Chrome(options=options)

    @staticmethod
    def take_screenshot(
        driver: webdriver.Chrome,
        url: str,
        output_directory: Path,
    ) -> str:
        driver.get(url)
        screenshot_path = output_directory / f"{url_to_filename(url)}.png"
        driver.save_screenshot(str(screenshot_path))
        return str(screenshot_path)

    @staticmethod
    def speak(message: str) -> None:
        try:
            engine = pyttsx3.init()
            engine.say(message)
            engine.runAndWait()
        except Exception as exc:  # Audio is optional; do not fail a scan over it.
            print(f"Voice notification unavailable: {exc}")

    def run_web_scoping(self) -> None:
        try:
            self.urls = self.load_urls(self.entry_url.text())
        except (OSError, ValueError) as exc:
            print(f"Input error: {exc}")
            return

        SCREENSHOT_DIRECTORY.mkdir(parents=True, exist_ok=True)
        waf_check_enabled = self.waf_check_toggle.isChecked()
        self.speak("Web check starting! Please wait.")
        self.set_scan_controls(running=True)
        self.label_progress.setText(f"Starting scan of {len(self.urls)} target(s)…")

        self.scan_thread = QThread(self)
        self.scan_worker = ScanWorker(self.urls, waf_check_enabled)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.progress.connect(self.update_progress)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.failed.connect(self.scan_failed)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.failed.connect(self.scan_thread.quit)
        self.scan_thread.finished.connect(self.scan_worker.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.finished.connect(self.clear_scan_references)
        self.scan_thread.start()

    def set_scan_controls(self, *, running: bool) -> None:
        self.button_run_scoping.setEnabled(not running)
        self.button_browse.setEnabled(not running)
        self.entry_url.setEnabled(not running)
        self.waf_check_toggle.setEnabled(not running)
        self.button_cancel.setEnabled(running)

    def cancel_scan(self) -> None:
        if self.scan_worker is not None:
            self.scan_worker.cancel()
            self.button_cancel.setEnabled(False)
            self.label_progress.setText("Cancelling after the current operation…")

    @pyqtSlot(int, int, str)
    def update_progress(self, completed: int, total: int, url: str) -> None:
        self.label_progress.setText(f"Checked {completed}/{total}: {url}")

    @pyqtSlot(object)
    def scan_finished(self, outcome: ScanOutcome) -> None:
        if not outcome.results and outcome.cancelled:
            self.label_progress.setText("Scan cancelled before any targets completed.")
            return

        report_path = generate_html_report(
            outcome.results,
            REPORT_FILE,
            scan_id=outcome.scan_id,
            started_at=outcome.started_at,
            completed_at=outcome.completed_at,
        )
        open_report(report_path)
        state = "cancelled" if outcome.cancelled else "completed"
        self.label_progress.setText(
            f"Scan {state}: {len(outcome.results)}/{len(self.urls)} target(s) reported."
        )
        self.speak(f"Web check {state}!")
        print(f"Web check {state}. Report: {report_path.resolve()}")

    @pyqtSlot(str)
    def scan_failed(self, message: str) -> None:
        self.label_progress.setText(f"Scan failed: {message}")
        print(f"Scan failed: {message}")

    @pyqtSlot()
    def clear_scan_references(self) -> None:
        self.scan_worker = None
        self.scan_thread = None
        self.set_scan_controls(running=False)


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    window = WebScopingApp()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
