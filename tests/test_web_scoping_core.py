from __future__ import annotations

import socket
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import requests

import web_scoping_core as core


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        *,
        url: str | None = None,
        redirect_count: int = 0,
        retry_count: int = 0,
    ) -> None:
        self.status_code = status_code
        self.url = url
        self.history = [object()] * redirect_count
        self.raw = SimpleNamespace(
            retries=SimpleNamespace(history=[object()] * retry_count)
        )


class FakeClient:
    def __init__(
        self,
        response: FakeResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        assert self.response is not None
        return self.response


def diagnostic(
    *,
    is_up: bool = True,
    status_code: int | None = 200,
    error: str | None = None,
) -> core.HttpCheckResult:
    return core.HttpCheckResult(
        is_up=is_up,
        status_code=status_code,
        final_url="https://example.com/final",
        checked_at="2026-09-02T20:00:00.000Z",
        duration_ms=125.5,
        redirect_count=1,
        retry_count=2,
        error_category=None if is_up else core.ErrorCategory.HTTP,
        error=error,
    )


def test_normalize_url_adds_https() -> None:
    assert core.normalize_url("example.com") == "https://example.com"


def test_normalize_url_rejects_non_http_scheme() -> None:
    try:
        core.normalize_url("ftp://example.com")
    except ValueError as exc:
        assert "http or https" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_status_check_marks_redirect_as_up() -> None:
    client = FakeClient(response=FakeResponse(302))

    is_up, status_code, error = core.check_website_status(
        "https://example.com",
        client=client,
    )

    assert is_up is True
    assert status_code == 302
    assert error is None
    assert client.calls[0][1]["timeout"] == core.DEFAULT_TIMEOUT_SECONDS


def test_status_check_handles_request_error() -> None:
    client = FakeClient(error=requests.ConnectionError("offline"))

    is_up, status_code, error = core.check_website_status(
        "https://example.com",
        client=client,
    )

    assert is_up is False
    assert status_code is None
    assert "offline" in error


def test_structured_http_diagnostics_capture_response_evidence() -> None:
    client = FakeClient(
        response=FakeResponse(
            200,
            url="https://example.com/final",
            redirect_count=1,
            retry_count=2,
        )
    )

    result = core.collect_http_diagnostics("https://example.com", client=client)

    assert result.is_up is True
    assert result.final_url == "https://example.com/final"
    assert result.redirect_count == 1
    assert result.retry_count == 2
    assert result.duration_ms >= 0
    assert result.checked_at.endswith("Z")
    assert result.error_category is None


def test_structured_http_diagnostics_categorize_http_failure() -> None:
    result = core.collect_http_diagnostics(
        "https://example.com",
        client=FakeClient(response=FakeResponse(503)),
    )

    assert result.is_up is False
    assert result.status_code == 503
    assert result.error_category == core.ErrorCategory.HTTP


def test_request_failures_have_stable_error_categories() -> None:
    failures = [
        (requests.Timeout("slow"), core.ErrorCategory.TIMEOUT),
        (
            requests.ConnectionError(core.Urllib3TimeoutError("wrapped timeout")),
            core.ErrorCategory.TIMEOUT,
        ),
        (requests.exceptions.SSLError("bad certificate"), core.ErrorCategory.TLS),
        (
            requests.ConnectionError(core.Urllib3SSLError("wrapped TLS failure")),
            core.ErrorCategory.TLS,
        ),
        (
            requests.ConnectionError(socket.gaierror(-2, "name not known")),
            core.ErrorCategory.DNS,
        ),
        (requests.ConnectionError("refused"), core.ErrorCategory.CONNECTION),
        (requests.RequestException("unexpected"), core.ErrorCategory.UNKNOWN),
    ]

    for error, expected_category in failures:
        result = core.collect_http_diagnostics(
            "https://example.com",
            client=FakeClient(error=error),
        )

        assert result.is_up is False
        assert result.error_category == expected_category
        assert result.error
        assert result.retry_count is None


def test_http_session_has_bounded_get_retry_policy() -> None:
    session = core.build_http_session(max_retries=3, backoff_factor=0.25)
    try:
        retry_policy = session.get_adapter("https://").max_retries

        assert retry_policy.total == 3
        assert retry_policy.backoff_factor == 0.25
        assert retry_policy.allowed_methods == frozenset({"GET"})
        assert retry_policy.status_forcelist == core.RETRYABLE_STATUS_CODES
        assert retry_policy.respect_retry_after_header is True
        assert retry_policy.raise_on_status is False
    finally:
        session.close()


def test_http_session_rejects_invalid_retry_configuration() -> None:
    for retries, backoff in [(-1, 0.5), (2, -0.1)]:
        try:
            core.build_http_session(max_retries=retries, backoff_factor=backoff)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError")


def test_waf_probe_preserves_existing_query() -> None:
    probe = core.build_waf_probe_url("https://example.com/path?a=1")

    assert "a=1" in probe
    assert "waf_test=" in probe
    assert probe.startswith("https://example.com/path?")


def test_waf_403_is_reported_as_filtering_likely() -> None:
    client = FakeClient(response=FakeResponse(403))

    result = core.check_waf("https://example.com", client=client)

    assert "Filtering likely" in result
    assert "403" in result


def test_waf_success_does_not_claim_no_waf() -> None:
    client = FakeClient(response=FakeResponse(200))

    result = core.check_waf("https://example.com", client=client)

    assert "does not prove" in result


def test_url_to_filename_is_safe_and_bounded() -> None:
    name = core.url_to_filename("https://example.com/a?b=c&x=y")

    assert "/" not in name
    assert "?" not in name
    assert len(name) <= 120


def test_report_escapes_untrusted_values(tmp_path: Path) -> None:
    output = tmp_path / "report.html"
    results = [
        core.CheckResult(
            url="https://example.com/<script>alert(1)</script>",
            is_up=False,
            status_code=500,
            screenshot_path=None,
            waf_result="<b>unsafe</b>",
            error="bad <input>",
            final_url="https://example.com/<final>",
            checked_at="2026-09-02T20:00:00.000Z",
            duration_ms=250.0,
            redirect_count=1,
            retry_count=2,
            error_category=core.ErrorCategory.HTTP,
        )
    ]

    core.generate_html_report(
        results,
        output,
        scan_id="scan-123",
        started_at="2026-09-02T20:00:00.000Z",
        completed_at="2026-09-02T20:00:01.000Z",
    )
    document = output.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document
    assert "&lt;b&gt;unsafe&lt;/b&gt;" in document
    assert "bad &lt;input&gt;" in document
    assert "https://example.com/&lt;final&gt;" in document
    assert "250.00 ms" in document
    assert "Checked: 2026-09-02T20:00:00.000Z" in document
    assert "Error category: http" in document
    assert "Scan ID: scan-123" in document


def test_scan_urls_reports_progress_and_collects_results() -> None:
    progress: list[tuple[int, int, str]] = []
    screenshots: list[str] = []

    def status_checker(url: str) -> core.HttpCheckResult:
        return diagnostic()

    def take_screenshot(url: str) -> str:
        screenshots.append(url)
        return f"screenshots/{url.removeprefix('https://')}.png"

    outcome = core.scan_urls(
        ["https://one.example", "https://two.example"],
        waf_check_enabled=False,
        status_checker=status_checker,
        take_screenshot=take_screenshot,
        on_progress=lambda completed, total, result: progress.append(
            (completed, total, result.url)
        ),
        scan_id="scan-123",
        wall_clock=iter(
            [
                datetime(2026, 9, 2, 20, 0, tzinfo=timezone.utc),
                datetime(2026, 9, 2, 20, 0, 1, tzinfo=timezone.utc),
            ]
        ).__next__,
        monotonic=iter([10.0, 10.25]).__next__,
    )

    assert outcome.cancelled is False
    assert len(outcome.results) == 2
    assert screenshots == ["https://one.example", "https://two.example"]
    assert progress == [
        (1, 2, "https://one.example"),
        (2, 2, "https://two.example"),
    ]
    assert all(result.waf_result == "WAF check disabled." for result in outcome.results)
    assert outcome.scan_id == "scan-123"
    assert outcome.started_at == "2026-09-02T20:00:00.000Z"
    assert outcome.completed_at == "2026-09-02T20:00:01.000Z"
    assert outcome.duration_ms == 250.0
    assert outcome.results[0].retry_count == 2


def test_scan_urls_stops_before_next_target_when_cancelled() -> None:
    calls: list[str] = []
    cancelled = False

    def status_checker(url: str) -> core.HttpCheckResult:
        nonlocal cancelled
        calls.append(url)
        cancelled = True
        return diagnostic()

    outcome = core.scan_urls(
        ["https://one.example", "https://two.example"],
        waf_check_enabled=False,
        status_checker=status_checker,
        take_screenshot=lambda url: f"{url}.png",
        should_cancel=lambda: cancelled,
    )

    assert outcome.cancelled is True
    assert outcome.results == []
    assert calls == ["https://one.example"]


def test_scan_urls_keeps_result_when_screenshot_fails() -> None:
    def failing_screenshot(url: str) -> str:
        raise RuntimeError(f"browser unavailable for {url}")

    outcome = core.scan_urls(
        ["https://example.com"],
        waf_check_enabled=True,
        status_checker=lambda url: diagnostic(),
        waf_checker=lambda url: "Filtering unlikely.",
        take_screenshot=failing_screenshot,
    )

    result = outcome.results[0]
    assert result.screenshot_path is None
    assert result.waf_result == "Filtering unlikely."
    assert result.error is not None
    assert "Screenshot failed" in result.error


def test_scan_urls_skips_screenshot_for_unhealthy_target() -> None:
    screenshot_calls: list[str] = []

    outcome = core.scan_urls(
        ["https://example.com"],
        waf_check_enabled=False,
        status_checker=lambda url: diagnostic(is_up=False, status_code=503),
        take_screenshot=lambda url: screenshot_calls.append(url) or "unused.png",
    )

    assert screenshot_calls == []
    assert outcome.results[0].status_code == 503
    assert outcome.results[0].screenshot_path is None
