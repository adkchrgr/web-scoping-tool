# Web Scoping Tool

![CI](https://github.com/adkchrgr/web-scoping-tool/actions/workflows/ci.yml/badge.svg)

Web Scoping Tool is a Python/PyQt utility for authorized web-scope validation. It checks HTTP reachability, can run an optional heuristic WAF probe, captures screenshots with Selenium, and generates an HTML report.

The project is split into a testable core module (`web_scoping_core.py`) and a PyQt front end (`ubuntu_webchecker.py`). This keeps HTTP and reporting logic independently testable without launching a GUI or browser in CI.

## Features

- Enter a single URL or load multiple URLs from a text file.
- Normalize bare hostnames to HTTPS.
- Check HTTP reachability with explicit timeouts and redirect handling.
- Optionally run a simple WAF heuristic probe.
- Reuse a single Selenium browser session for screenshots.
- Keep the interface responsive with a background scan worker.
- Show per-target progress and support cooperative cancellation.
- Generate an escaped HTML report.
- Open the report using the platform default browser without shell execution.
- Optional voice notifications.

> **Authorized use only:** Run active checks only against systems you own or have explicit permission to test.

## Architecture

```text
ubuntu_webchecker.py
        |
        +--> web_scoping_core.py
                |-- URL normalization
                |-- HTTP status checks
                |-- WAF heuristic probe
                |-- report generation
                +-- report opening
        |
        +--> Selenium screenshot capture
        +--> PyQt UI
```

## Installation

```bash
git clone https://github.com/adkchrgr/web-scoping-tool.git
cd web-scoping-tool
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Modern Selenium versions can use Selenium Manager to locate or provision a compatible browser driver, so the application no longer hardcodes `/usr/bin/chromedriver`.

## Usage

```bash
python ubuntu_webchecker.py
```

Enter either:

- a URL such as `https://example.com`
- a bare hostname such as `example.com`
- a text file containing one target per line

The generated report is written to `web_check_report.html`, and screenshots are stored under `screenshots/`.

## WAF Check

The optional WAF check appends an XSS-shaped query value and observes the HTTP response.

A `403` or `406` is treated as evidence that filtering may be occurring. A successful response does **not** prove that no WAF is present. This is intentionally described as a heuristic rather than a WAF fingerprinting engine.

## Tests

Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

Run the unit tests:

```bash
pytest -v
```

The tests exercise browser-independent behavior including:

- URL normalization
- request timeouts and network failures
- redirect handling
- WAF probe URL construction
- WAF response interpretation
- safe filename generation
- HTML escaping in generated reports
- scan orchestration, progress callbacks, cancellation, and screenshot failures

The tests do not make live network requests.

## Linting

```bash
ruff check .
```

Ruff checks the repository for common correctness, import, and code-quality problems.

## Continuous Integration

GitHub Actions runs both Ruff and pytest automatically on every push and pull request.

A green **CI passing** badge means the latest commit passed the automated checks. A red badge means the workflow completed with a failure that should be investigated in the repository's **Actions** tab.

## Production-Minded Improvements in This Refactor

The original project was a useful single-file prototype. The current version adds several engineering safeguards:

- explicit HTTP timeouts
- broader `requests.RequestException` handling
- URL construction with `urllib.parse` instead of string concatenation
- escaped untrusted values in HTML reports
- portable report opening via `webbrowser` rather than `os.system`
- Selenium Manager rather than a hardcoded ChromeDriver path
- one reusable browser session instead of a new driver per URL
- isolated browser-independent core logic
- typed result objects
- automated unit tests
- linting and CI
- background execution with observable progress and cooperative cancellation

## Known Limitations

- Cancellation is cooperative: an in-flight HTTP request or browser operation completes before the worker stops. Explicit timeouts keep this delay bounded for HTTP calls.
- The WAF check is heuristic and does not identify specific WAF vendors.
- Screenshot behavior still depends on a compatible local Chrome/Chromium installation.
- HTTP reachability is intentionally simple and is not a full application-health assessment.

## License

MIT License.
