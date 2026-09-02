"""Core HTTP, WAF-probe, screenshot, and report helpers for Web Scoping Tool.

The GUI imports this module, but the module itself has no PyQt dependency. That
keeps the network/report behavior independently testable in CI.
"""

from __future__ import annotations

import html
import re
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)
WAF_PROBE_VALUE = "<script>alert(1)</script>"


class HttpClient(Protocol):
    """Minimal interface used by HTTP helpers; makes requests easy to mock."""

    def get(self, url: str, **kwargs: Any) -> requests.Response: ...


@dataclass(frozen=True)
class CheckResult:
    """One URL's collected results for HTML reporting."""

    url: str
    is_up: bool
    status_code: int | None
    screenshot_path: str | None
    waf_result: str
    error: str | None = None


def normalize_url(value: str) -> str:
    """Return a trimmed HTTP(S) URL, adding https:// when no scheme is supplied."""
    url = value.strip()
    if not url:
        raise ValueError("URL cannot be empty")

    parsed = urlsplit(url)
    if not parsed.scheme:
        url = f"https://{url}"
        parsed = urlsplit(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL must use http or https")
    if not parsed.netloc:
        raise ValueError("URL must include a hostname")

    return urlunsplit(parsed)


def check_website_status(
    url: str,
    *,
    client: HttpClient = requests,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[bool, int | None, str | None]:
    """Check reachability and return (is_up, status_code, error).

    Any HTTP response means the host responded. 2xx/3xx are considered "up";
    4xx/5xx are considered reachable but unhealthy for this report.
    """
    try:
        response = client.get(
            url,
            headers={"User-Agent": DEFAULT_USER_AGENT},
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return False, None, str(exc)

    is_up = 200 <= response.status_code < 400
    return is_up, response.status_code, None


def build_waf_probe_url(url: str) -> str:
    """Add a benign XSS-shaped query value without corrupting existing query params."""
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("waf_test", WAF_PROBE_VALUE))
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query), parsed.fragment)
    )


def check_waf(
    url: str,
    *,
    client: HttpClient = requests,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Run a heuristic WAF probe and return a human-readable result.

    This is intentionally a heuristic, not a WAF fingerprinting engine. A 403 or
    406 after an XSS-shaped query is evidence of filtering, but not proof that a
    specific WAF product is present.
    """
    probe_url = build_waf_probe_url(url)
    try:
        response = client.get(
            probe_url,
            headers={"User-Agent": DEFAULT_USER_AGENT},
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return f"Probe failed: {exc}"

    if response.status_code in {403, 406}:
        return f"Filtering likely: probe returned HTTP {response.status_code}."
    if 200 <= response.status_code < 400:
        return (
            "No blocking detected by this heuristic probe; this does not prove "
            "that no WAF is present."
        )
    return f"Inconclusive: probe returned HTTP {response.status_code}."


def url_to_filename(url: str, *, max_length: int = 120) -> str:
    """Convert a URL to a filesystem-friendly deterministic filename stem."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", url).strip("._")
    return (cleaned or "site")[:max_length]


def generate_html_report(results: list[CheckResult], output_file: str | Path) -> Path:
    """Generate an escaped standalone HTML report and return its path."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[str] = []
    for result in results:
        safe_url = html.escape(result.url)
        status_text = "Up" if result.is_up else "Down"
        status_class = "up" if result.is_up else "down"
        status_detail = (
            f"HTTP {result.status_code}" if result.status_code is not None else "No HTTP response"
        )

        row = [
            f"<section><h2>{safe_url}</h2>",
            (
                f"<p>Status: <span class='{status_class}'>{status_text}</span> "
                f"({html.escape(status_detail)})</p>"
            ),
            f"<p>WAF check: {html.escape(result.waf_result)}</p>",
        ]
        if result.error:
            row.append(f"<p>Error: {html.escape(result.error)}</p>")
        if result.screenshot_path:
            screenshot = html.escape(result.screenshot_path, quote=True)
            row.append(f'<img src="{screenshot}" alt="Screenshot of {safe_url}">')
        else:
            row.append("<p>No screenshot available.</p>")
        row.append("</section>")
        rows.append("\n".join(row))

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Web Check Report</title>
    <style>
        body {{ font-family: Helvetica, Arial, sans-serif; max-width: 900px;
               margin: 0 auto; padding: 20px; background: #36454f; color: white; }}
        h1 {{ text-align: center; }}
        h2 {{ border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 28px; }}
        .up {{ color: #7ee787; }}
        .down {{ color: #ff7b72; }}
        img {{ max-width: 100%; height: auto; margin-top: 12px; }}
        section {{ overflow-wrap: anywhere; }}
    </style>
</head>
<body>
    <h1>Web Check Report</h1>
    {''.join(rows)}
</body>
</html>
"""
    output_path.write_text(document, encoding="utf-8")
    return output_path


def open_report(path: str | Path) -> bool:
    """Open a generated report with the platform default browser, without a shell."""
    return webbrowser.open(Path(path).resolve().as_uri())
