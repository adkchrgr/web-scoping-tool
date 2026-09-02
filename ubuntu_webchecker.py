"""PyQt front end for Web Scoping Tool."""

from __future__ import annotations

import sys
from pathlib import Path

import pyttsx3
import qdarkstyle
from PyQt5.QtCore import Qt
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
    check_waf,
    check_website_status,
    generate_html_report,
    normalize_url,
    open_report,
    url_to_filename,
)

SCREENSHOT_DIRECTORY = Path("screenshots")
REPORT_FILE = Path("web_check_report.html")


class WebScopingApp(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
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

        layout = QVBoxLayout(self)
        layout.addWidget(self.label_heading)
        layout.addWidget(self.label_description)
        layout.addSpacing(20)
        layout.addWidget(self.label_url)
        layout.addWidget(self.entry_url)
        layout.addWidget(self.button_browse)
        layout.addWidget(self.waf_check_toggle)
        layout.addWidget(self.button_run_scoping)
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
        results: list[CheckResult] = []
        browser: webdriver.Chrome | None = None

        self.speak("Web check starting! Please wait.")

        try:
            for url in self.urls:
                is_up, status_code, error = check_website_status(url)
                waf_result = check_waf(url) if waf_check_enabled else "WAF check disabled."
                screenshot_path: str | None = None

                if is_up:
                    try:
                        if browser is None:
                            browser = self.create_browser()
                        screenshot_path = self.take_screenshot(
                            browser,
                            url,
                            SCREENSHOT_DIRECTORY,
                        )
                    except Exception as exc:
                        screenshot_path = None
                        screenshot_error = f"Screenshot failed: {exc}"
                        error = f"{error}; {screenshot_error}" if error else screenshot_error

                results.append(
                    CheckResult(
                        url=url,
                        is_up=is_up,
                        status_code=status_code,
                        screenshot_path=screenshot_path,
                        waf_result=waf_result,
                        error=error,
                    )
                )
        finally:
            if browser is not None:
                browser.quit()

        report_path = generate_html_report(results, REPORT_FILE)
        open_report(report_path)
        self.speak("Web check completed!")
        print(f"Web check completed. Report: {report_path.resolve()}")


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    window = WebScopingApp()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
