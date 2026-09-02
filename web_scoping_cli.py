"""Headless command-line interface for Web Scoping Tool."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict
from functools import partial
from pathlib import Path
from typing import TextIO

import requests

from web_scoping_core import (
    DEFAULT_BACKOFF_FACTOR,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT_SECONDS,
    ScanOutcome,
    build_http_session,
    check_waf,
    check_website_status,
    normalize_url,
    scan_urls,
)

EXIT_HEALTHY = 0
EXIT_UNHEALTHY = 1
EXIT_ERROR = 2
SessionFactory = Callable[..., requests.Session]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check authorized web targets and emit a JSON result document."
    )
    parser.add_argument("targets", nargs="*", help="HTTP(S) URLs or bare hostnames")
    parser.add_argument("--input-file", type=Path, help="text file containing one target per line")
    parser.add_argument("--waf", action="store_true", help="include the heuristic WAF probe")
    parser.add_argument("--output", type=Path, help="write JSON to this file instead of stdout")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"per-request timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help=f"transient retry count (default: {DEFAULT_MAX_RETRIES})",
    )
    parser.add_argument(
        "--backoff",
        type=float,
        default=DEFAULT_BACKOFF_FACTOR,
        help=f"retry backoff factor (default: {DEFAULT_BACKOFF_FACTOR})",
    )
    return parser


def load_targets(values: Sequence[str], input_file: Path | None) -> list[str]:
    raw_targets = list(values)
    if input_file is not None:
        raw_targets.extend(input_file.read_text(encoding="utf-8").splitlines())

    targets = [normalize_url(value) for value in raw_targets if value.strip()]
    if not targets:
        raise ValueError("at least one target or --input-file entry is required")
    return targets


def outcome_to_payload(outcome: ScanOutcome) -> dict[str, object]:
    healthy = sum(result.is_up for result in outcome.results)
    return {
        "summary": {
            "total": len(outcome.results),
            "healthy": healthy,
            "unhealthy": len(outcome.results) - healthy,
            "cancelled": outcome.cancelled,
        },
        "results": [asdict(result) for result in outcome.results],
    }


def run_scan(
    targets: Sequence[str],
    *,
    waf_check_enabled: bool,
    timeout: float,
    retries: int,
    backoff: float,
    session_factory: SessionFactory = build_http_session,
) -> ScanOutcome:
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if retries < 0:
        raise ValueError("retries cannot be negative")
    if backoff < 0:
        raise ValueError("backoff cannot be negative")

    session = session_factory(max_retries=retries, backoff_factor=backoff)
    try:
        return scan_urls(
            targets,
            waf_check_enabled=waf_check_enabled,
            status_checker=partial(check_website_status, client=session, timeout=timeout),
            waf_checker=partial(check_waf, client=session, timeout=timeout),
        )
    finally:
        session.close()


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    session_factory: SessionFactory = build_http_session,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        targets = load_targets(args.targets, args.input_file)
        outcome = run_scan(
            targets,
            waf_check_enabled=args.waf,
            timeout=args.timeout,
            retries=args.retries,
            backoff=args.backoff,
            session_factory=session_factory,
        )
        document = json.dumps(outcome_to_payload(outcome), indent=2) + "\n"
        if args.output is None:
            stdout.write(document)
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(document, encoding="utf-8")
    except (OSError, ValueError) as exc:
        stderr.write(f"error: {exc}\n")
        return EXIT_ERROR

    return EXIT_HEALTHY if all(result.is_up for result in outcome.results) else EXIT_UNHEALTHY


if __name__ == "__main__":
    raise SystemExit(main())
