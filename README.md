# Web Scoping Tool

Web Scoping Tool is a Python-based application for checking the status of websites, optionally checking for the presence of Web Application Firewalls (WAF), and taking screenshots of websites. The application is built with PyQt5 for the GUI, Selenium for web automation, and requests for HTTP requests. It also generates an HTML report of the results and provides voice notifications using pyttsx3.

## Features

- Enter a single URL or load multiple URLs from a text file.
- Optionally check for the presence of a Web Application Firewall (WAF).
- Take screenshots of the websites.
- Generate an HTML report summarizing the results.
- Voice notifications for start and completion of the web check.
- Dark mode UI with QDarkStyle.

## Prerequisites

Before you begin, ensure you have the following installed on your Ubuntu system:

- Python 3.7 or higher
- Google Chrome
- ChromeDriver

## Installation

1. **Install Google Chrome**:
    ```bash
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
    sudo apt install ./google-chrome-stable_current_amd64.deb
    ```

2. **Install ChromeDriver**:
    ```bash
    sudo apt update
    sudo apt install -y chromium-chromedriver
    sudo ln -s /usr/lib/chromium-browser/chromedriver /usr/bin/chromedriver
    ```

3. **Clone the repository**:
    ```bash
    git clone https://github.com/adkchrgr/web-scoping-tool.git
    cd web-scoping-tool
    ```

4. **Install Python dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the application**:
    ```bash
    python ubuntu_webchecker.py
    ```

2. **User Interface**:
    - **Enter URL or Select File**: Enter a single URL or click 'Browse' to select a text file containing multiple URLs.
    - **Include WAF Check**: Check this option to enable Web Application Firewall checking. This sends a live test payload to each URL — only enable it against systems you're authorized to test.
    - **Run Web Check**: Click this button to start the web check process.

## Functionality

- **URL Input**: Allows users to input a single URL or select a file with multiple URLs.
- **WAF Check**: Optionally checks for the presence of a Web Application Firewall.
- **Screenshot**: Takes a screenshot of the website and saves it in the `screenshots` directory.
- **HTML Report**: Generates an HTML report with the status, WAF check result, and screenshots of the websites.
- **Voice Notifications**: Notifies the user when the web check starts and completes.

## License

This project is licensed under the MIT License.

## Contributing

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/new-feature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/new-feature`).
5. Open a pull request.

## Acknowledgments

- [QDarkStyle](https://github.com/ColinDuquesnoy/QDarkStyleSheet) for the dark mode styling.
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/intro) for the GUI framework.
- [Selenium](https://www.selenium.dev/) for web automation.
- [requests](https://docs.python-requests.org/en/master/) for HTTP requests.
- [pyttsx3](https://pyttsx3.readthedocs.io/) for text-to-speech conversion.

