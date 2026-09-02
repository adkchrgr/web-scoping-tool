# Web Scoping Tool

A Python desktop utility for authorized web-scope validation. It can check website availability, take browser screenshots, run an optional WAF heuristic, and generate an HTML report from the results.

I built this as a practical automation project around a workflow I was familiar with: taking a list of web targets, checking basic reachability and behavior, and collecting consistent evidence without doing every step manually.

## What It Demonstrates

- Python application structure
- HTTP requests and response handling
- Selenium browser automation
- PyQt5 desktop UI development
- Batch processing from user input or a file
- HTML report generation
- Security-oriented workflow automation

## Features

- Enter a single URL or load multiple URLs from a text file.
- Check basic website availability.
- Optionally run a simple WAF-blocking heuristic.
- Capture website screenshots with Selenium.
- Generate an HTML report summarizing results.
- Voice notifications for start and completion.
- Dark-mode UI with QDarkStyle.

> **Authorized use only:** the optional WAF check sends a live test request to the supplied target. Use it only against systems you own or are explicitly authorized to test.

## High-Level Flow

```text
URL or file input
      ↓
HTTP availability check
      ↓
Optional WAF heuristic
      ↓
Selenium screenshot
      ↓
Structured result collection
      ↓
HTML report
```

## Prerequisites

- Python 3.7+
- Google Chrome
- ChromeDriver

## Installation

```bash
git clone https://github.com/adkchrgr/web-scoping-tool.git
cd web-scoping-tool
pip install -r requirements.txt
```

The current implementation expects ChromeDriver at `/usr/bin/chromedriver` on Ubuntu.

## Usage

```bash
python ubuntu_webchecker.py
```

In the UI:

1. Enter one URL or select a text file containing URLs.
2. Enable **Include WAF Check** only if authorized.
3. Select **Run Web Check**.
4. Review the generated HTML report and screenshots.

## WAF Check Limitation

The WAF option is deliberately described as a **heuristic**, not a definitive detector. A blocking response such as HTTP 403 can be consistent with a WAF, but it can also result from application logic, authentication, rate limiting, CDN behavior, or other controls.

The result should therefore be treated as a signal for further investigation rather than a positive identification.

## Current Limitations

- ChromeDriver path is hardcoded for the environment where I originally built the tool.
- Network requests do not yet use consistent timeout/retry handling.
- Browser sessions are created per target rather than reused.
- UI, networking, and reporting logic currently live in one module.
- The project does not yet include automated tests or CI.

## What I Would Change for Production

- Add request timeouts and broader exception handling.
- Use Selenium Manager instead of a hardcoded driver path.
- Reuse browser sessions where appropriate.
- Separate UI, network, browser, and reporting concerns into modules.
- Escape all dynamic values included in generated HTML.
- Add structured logging.
- Add unit tests with mocked HTTP responses.
- Add integration tests for report generation.
- Add linting and GitHub Actions CI.
- Add a dry-run or non-invasive mode for workflows where active checks are not appropriate.

## License

MIT License.
