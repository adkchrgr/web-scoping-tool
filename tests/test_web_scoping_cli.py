from __future__ import annotations

import json
from io import StringIO

import web_scoping_cli as cli


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FakeSession:
    def __init__(self, statuses: dict[str, int]) -> None:
        self.statuses = statuses
        self.calls: list[str] = []
        self.closed = False

    def get(self, url: str, **kwargs) -> FakeResponse:
        self.calls.append(url)
        return FakeResponse(self.statuses[url])

    def close(self) -> None:
        self.closed = True


def test_cli_emits_json_and_returns_healthy_exit_code() -> None:
    session = FakeSession({"https://example.com": 204})
    stdout = StringIO()

    exit_code = cli.main(
        ["example.com"],
        stdout=stdout,
        session_factory=lambda **kwargs: session,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == cli.EXIT_HEALTHY
    assert payload["summary"] == {
        "total": 1,
        "healthy": 1,
        "unhealthy": 0,
        "cancelled": False,
    }
    assert payload["results"][0]["url"] == "https://example.com"
    assert payload["results"][0]["screenshot_path"] is None
    assert session.closed is True


def test_cli_returns_unhealthy_exit_code_for_failed_target() -> None:
    session = FakeSession({"https://example.com": 503})

    exit_code = cli.main(
        ["https://example.com"],
        stdout=StringIO(),
        session_factory=lambda **kwargs: session,
    )

    assert exit_code == cli.EXIT_UNHEALTHY
    assert session.closed is True


def test_cli_waf_probe_reuses_the_same_session() -> None:
    target = "https://example.com"
    probe = "https://example.com/?waf_test=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    session = FakeSession({target: 200, probe: 403})
    stdout = StringIO()

    exit_code = cli.main(
        [target, "--waf"],
        stdout=stdout,
        session_factory=lambda **kwargs: session,
    )

    payload = json.loads(stdout.getvalue())
    assert exit_code == cli.EXIT_HEALTHY
    assert session.calls == [target, probe]
    assert "Filtering likely" in payload["results"][0]["waf_result"]


def test_cli_returns_error_exit_code_for_invalid_configuration() -> None:
    invalid_options = [
        (["--timeout", "0"], "timeout must be greater than zero"),
        (["--retries", "-1"], "retries cannot be negative"),
        (["--backoff", "-0.1"], "backoff cannot be negative"),
    ]

    for options, expected_error in invalid_options:
        stderr = StringIO()
        exit_code = cli.main(["example.com", *options], stderr=stderr)

        assert exit_code == cli.EXIT_ERROR
        assert expected_error in stderr.getvalue()
