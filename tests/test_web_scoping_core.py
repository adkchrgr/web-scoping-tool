from __future__ import annotations

from pathlib import Path

import requests

import web_scoping_core as core


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FakeClient:
    def __init__(self, response: FakeResponse | None = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        assert self.response is not None
        return self.response


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
        )
    ]

    core.generate_html_report(results, output)
    document = output.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document
    assert "&lt;b&gt;unsafe&lt;/b&gt;" in document
    assert "bad &lt;input&gt;" in document
