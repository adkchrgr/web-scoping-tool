"""Core HTTP, WAF-probe, screenshot, and report helpers for Web Scoping Tool.

The GUI imports this module, but the module itself has no PyQt dependency. That
keeps the network/report behavior independently testable in CI.
"""

from __future__ import annotations

import html
import re
import socket
import time
import webbrowser
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import NameResolutionError
from urllib3.exceptions import SSLError as Urllib3SSLError
from urllib3.exceptions import TimeoutError as Urllib3TimeoutError
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_RETRIES = 2
DEFAULT_BACKOFF_FACTOR = 0.5
RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)
WAF_PROBE_VALUE = "<script>alert(1)</script>"


class HttpClient(Protocol):
    """Minimal interface used by HTTP helpers; makes requests easy to mock."""

    def get(self, url: str, **kwargs: Any) -> requests.Response: ...


class ErrorCategory(StrEnum):
    """Stable machine-readable categories for failed or unhealthy checks."""

    TIMEOUT = "timeout"
    DNS = "dns"
    TLS = "tls"
    CONNECTION = "connection"
    HTTP = "http"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class HttpCheckResult:
    """Structured diagnostics from one HTTP reachability check."""

    is_up: bool
    status_code: int | None
    final_url: str | None
    checked_at: str
    duration_ms: float
    redirect_count: int
    retry_count: int | None
    error_category: ErrorCategory | None = None
    error: str | None = None


@dataclass(frozen=True)
class CheckResult:
    """One URL's collected results for HTML reporting."""

    url: str
    is_up: bool
    status_code: int | None
    screenshot_path: str | None
    waf_result: str
    error: str | None = None
    final_url: str | None = None
    checked_at: str | None = None
    duration_ms: float | None = None
    redirect_count: int = 0
    retry_count: int | None = 0
    error_category: ErrorCategory | None = None


@dataclass(frozen=True)
class ScanOutcome:
    """Results from a scan, including whether it ended early by cancellation."""

    results: list[CheckResult]
    cancelled: bool
    scan_id: str
    started_at: str
    completed_at: str
    duration_ms: float


StatusChecker = Callable[[str], HttpCheckResult]
WafChecker = Callable[[str], str]
ScreenshotTaker = Callable[[str], str]
ProgressCallback = Callable[[int, int, CheckResult], None]


def utc_timestamp(now: datetime | None = None) -> str:
    """Return an ISO-8601 UTC timestamp with an explicit Z suffix."""
    value = now or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def create_scan_id() -> str:
    """Create a compact identifier suitable for correlating logs and output."""
    return uuid4().hex


def _exception_chain(exc: BaseException) -> list[BaseException]:
    """Collect nested exceptions without looping over cyclic exception graphs."""
    found: list[BaseException] = []
    pending = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        found.append(current)
        pending.extend(arg for arg in current.args if isinstance(arg, BaseException))
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return found


def categorize_request_error(exc: requests.RequestException) -> ErrorCategory:
    """Map requests/urllib3 exception chains to a stable diagnostic category."""
    chain = _exception_chain(exc)
    if any(isinstance(item, (requests.Timeout, Urllib3TimeoutError)) for item in chain):
        return ErrorCategory.TIMEOUT
    if any(isinstance(item, (requests.exceptions.SSLError, Urllib3SSLError)) for item in chain):
        return ErrorCategory.TLS
    if any(isinstance(item, (NameResolutionError, socket.gaierror)) for item in chain):
        return ErrorCategory.DNS
    if any(isinstance(item, requests.ConnectionError) for item in chain):
        return ErrorCategory.CONNECTION
    return ErrorCategory.UNKNOWN


def _response_retry_count(response: requests.Response) -> int:
    retries = getattr(getattr(response, "raw", None), "retries", None)
    return len(getattr(retries, "history", ()) or ())


def build_http_session(
    *,
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
) -> requests.Session:
    """Create a pooled session with bounded retries for transient GET failures."""
    if max_retries < 0:
        raise ValueError("max_retries cannot be negative")
    if backoff_factor < 0:
        raise ValueError("backoff_factor cannot be negative")

    retry_policy = Retry(
        total=max_retries,
        connect=max_retries,
        read=max_retries,
        status=max_retries,
        allowed_methods=frozenset({"GET"}),
        status_forcelist=RETRYABLE_STATUS_CODES,
        backoff_factor=backoff_factor,
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_policy)
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


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


def collect_http_diagnostics(
    url: str,
    *,
    client: HttpClient = requests,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> HttpCheckResult:
    """Check reachability and return structured HTTP diagnostics.

    Any HTTP response means the host responded. 2xx/3xx are considered "up";
    4xx/5xx are considered reachable but unhealthy for this report.
    """
    started = time.perf_counter()
    checked_at = utc_timestamp()
    try:
        response = client.get(
            url,
            headers={"User-Agent": DEFAULT_USER_AGENT},
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return HttpCheckResult(
            is_up=False,
            status_code=None,
            final_url=None,
            checked_at=checked_at,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            redirect_count=0,
            retry_count=None,
            error_category=categorize_request_error(exc),
            error=str(exc),
        )

    is_up = 200 <= response.status_code < 400
    return HttpCheckResult(
        is_up=is_up,
        status_code=response.status_code,
        final_url=getattr(response, "url", None) or url,
        checked_at=checked_at,
        duration_ms=round((time.perf_counter() - started) * 1000, 2),
        redirect_count=len(getattr(response, "history", ()) or ()),
        retry_count=_response_retry_count(response),
        error_category=None if is_up else ErrorCategory.HTTP,
    )


def check_website_status(
    url: str,
    *,
    client: HttpClient = requests,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[bool, int | None, str | None]:
    """Backward-compatible reachability result: (is_up, status_code, error)."""
    result = collect_http_diagnostics(url, client=client, timeout=timeout)
    return result.is_up, result.status_code, result.error


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


def scan_urls(
    urls: Sequence[str],
    *,
    waf_check_enabled: bool,
    take_screenshot: ScreenshotTaker | None = None,
    status_checker: StatusChecker = collect_http_diagnostics,
    waf_checker: WafChecker = check_waf,
    should_cancel: Callable[[], bool] = lambda: False,
    on_progress: ProgressCallback | None = None,
    scan_id: str | None = None,
    wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    monotonic: Callable[[], float] = time.perf_counter,
) -> ScanOutcome:
    """Scan URLs sequentially with observable progress and cooperative cancellation.

    Dependencies are injected so orchestration can be tested without network or browser
    access. Cancellation is checked between expensive stages; an in-flight network or
    browser operation is allowed to finish before the scan stops.
    """
    results: list[CheckResult] = []
    total = len(urls)
    resolved_scan_id = scan_id or create_scan_id()
    started_at = utc_timestamp(wall_clock())
    started = monotonic()

    def finish(*, cancelled: bool) -> ScanOutcome:
        return ScanOutcome(
            results=results,
            cancelled=cancelled,
            scan_id=resolved_scan_id,
            started_at=started_at,
            completed_at=utc_timestamp(wall_clock()),
            duration_ms=round((monotonic() - started) * 1000, 2),
        )

    for url in urls:
        if should_cancel():
            return finish(cancelled=True)

        status = status_checker(url)
        if should_cancel():
            return finish(cancelled=True)

        waf_result = waf_checker(url) if waf_check_enabled else "WAF check disabled."
        if should_cancel():
            return finish(cancelled=True)

        screenshot_path: str | None = None
        error = status.error
        if status.is_up and take_screenshot is not None:
            try:
                screenshot_path = take_screenshot(url)
            except Exception as exc:
                screenshot_error = f"Screenshot failed: {exc}"
                error = f"{error}; {screenshot_error}" if error else screenshot_error

        result = CheckResult(
            url=url,
            is_up=status.is_up,
            status_code=status.status_code,
            screenshot_path=screenshot_path,
            waf_result=waf_result,
            error=error,
            final_url=status.final_url,
            checked_at=status.checked_at,
            duration_ms=status.duration_ms,
            redirect_count=status.redirect_count,
            retry_count=status.retry_count,
            error_category=status.error_category,
        )
        results.append(result)
        if on_progress is not None:
            on_progress(len(results), total, result)

    return finish(cancelled=False)


def generate_html_report(
    results: list[CheckResult],
    output_file: str | Path,
    *,
    scan_id: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> Path:
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
        diagnostics = []
        if result.duration_ms is not None:
            diagnostics.append(f"{result.duration_ms:.2f} ms")
        diagnostics.append(f"{result.redirect_count} redirect(s)")
        retry_text = (
            "retry count unavailable"
            if result.retry_count is None
            else f"{result.retry_count} retry/retries"
        )
        diagnostics.append(retry_text)
        row.append(f"<p>Diagnostics: {', '.join(diagnostics)}</p>")
        if result.checked_at:
            row.append(f"<p>Checked: {html.escape(result.checked_at)}</p>")
        if result.final_url and result.final_url != result.url:
            row.append(f"<p>Final URL: {html.escape(result.final_url)}</p>")
        if result.error_category:
            row.append(f"<p>Error category: {html.escape(result.error_category.value)}</p>")
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
    {f'<p>Scan ID: {html.escape(scan_id)}</p>' if scan_id else ''}
    {f'<p>Started: {html.escape(started_at)}</p>' if started_at else ''}
    {f'<p>Completed: {html.escape(completed_at)}</p>' if completed_at else ''}
    {''.join(rows)}
</body>
</html>
"""
    output_path.write_text(document, encoding="utf-8")
    return output_path


def open_report(path: str | Path) -> bool:
    """Open a generated report with the platform default browser, without a shell."""
    return webbrowser.open(Path(path).resolve().as_uri())
