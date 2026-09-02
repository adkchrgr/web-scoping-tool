"""Headless command-line interface for Web Scoping Tool."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import TextIO

import requests

from web_scoping_core import (
    DEFAULT_BACKOFF_FACTOR,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT_SECONDS,
    CheckResult,
    ProgressCallback,
    ScanOutcome,
    build_http_session,
    check_waf,
    collect_http_diagnostics,
    create_scan_id,
    normalize_url,
    scan_urls,
    utc_timestamp,
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
        "--verbose",
        action="store_true",
        help="emit structured JSON diagnostic events to stderr",
    )
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
        "schema_version": "1.1",
        "scan": {
            "id": outcome.scan_id,
            "started_at": outcome.started_at,
            "completed_at": outcome.completed_at,
            "duration_ms": outcome.duration_ms,
        },
        "summary": {
            "total": len(outcome.results),
            "healthy": healthy,
            "unhealthy": len(outcome.results) - healthy,
            "cancelled": outcome.cancelled,
        },
        "results": [asdict(result) for result in outcome.results],
    }


class JsonEventFormatter(logging.Formatter):
    """Serialize diagnostic events as one JSON object per stderr line."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = utc_timestamp(datetime.fromtimestamp(record.created, timezone.utc))
        payload = {
            "timestamp": timestamp,
            "level": record.levelname.lower(),
            **getattr(record, "event_fields", {}),
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def build_event_logger(*, verbose: bool, stream: TextIO) -> logging.Logger:
    """Create an isolated logger that never writes to the JSON result stream."""
    logger = logging.Logger("web_scoping_cli", level=logging.INFO)
    logger.propagate = False
    logger.disabled = not verbose
    if verbose:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonEventFormatter())
        logger.addHandler(handler)
    return logger


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    **fields: object,
) -> None:
    logger.log(level, "", extra={"event_fields": {"event": event, **fields}})


def validate_scan_options(*, timeout: float, retries: int, backoff: float) -> None:
    """Validate runtime controls before a scan-started event is emitted."""
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if retries < 0:
        raise ValueError("retries cannot be negative")
    if backoff < 0:
        raise ValueError("backoff cannot be negative")


def run_scan(
    targets: Sequence[str],
    *,
    waf_check_enabled: bool,
    timeout: float,
    retries: int,
    backoff: float,
    session_factory: SessionFactory = build_http_session,
    scan_id: str | None = None,
    on_progress: ProgressCallback | None = None,
) -> ScanOutcome:
    validate_scan_options(timeout=timeout, retries=retries, backoff=backoff)

    session = session_factory(max_retries=retries, backoff_factor=backoff)
    try:
        return scan_urls(
            targets,
            waf_check_enabled=waf_check_enabled,
            status_checker=partial(collect_http_diagnostics, client=session, timeout=timeout),
            waf_checker=partial(check_waf, client=session, timeout=timeout),
            scan_id=scan_id,
            on_progress=on_progress,
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
    logger = build_event_logger(verbose=args.verbose, stream=stderr)
    scan_id = create_scan_id()

    def report_progress(completed: int, total: int, result: CheckResult) -> None:
        log_event(
            logger,
            "target_checked",
            scan_id=scan_id,
            completed=completed,
            total=total,
            target=result.url,
            final_url=result.final_url,
            status_code=result.status_code,
            healthy=result.is_up,
            duration_ms=result.duration_ms,
            redirect_count=result.redirect_count,
            retry_count=result.retry_count,
            error_category=result.error_category.value if result.error_category else None,
            error=result.error,
            waf_result=result.waf_result,
        )

    try:
        targets = load_targets(args.targets, args.input_file)
        validate_scan_options(
            timeout=args.timeout,
            retries=args.retries,
            backoff=args.backoff,
        )
        log_event(
            logger,
            "scan_started",
            scan_id=scan_id,
            target_count=len(targets),
            waf_enabled=args.waf,
        )
        outcome = run_scan(
            targets,
            waf_check_enabled=args.waf,
            timeout=args.timeout,
            retries=args.retries,
            backoff=args.backoff,
            session_factory=session_factory,
            scan_id=scan_id,
            on_progress=report_progress,
        )
        document = json.dumps(outcome_to_payload(outcome), indent=2) + "\n"
        if args.output is None:
            stdout.write(document)
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(document, encoding="utf-8")
        log_event(
            logger,
            "scan_completed",
            scan_id=scan_id,
            healthy=sum(result.is_up for result in outcome.results),
            unhealthy=sum(not result.is_up for result in outcome.results),
            duration_ms=outcome.duration_ms,
        )
    except (OSError, ValueError) as exc:
        log_event(
            logger,
            "scan_failed",
            level=logging.ERROR,
            scan_id=scan_id,
            error_category="configuration",
            error=str(exc),
        )
        if not args.verbose:
            stderr.write(f"error: {exc}\n")
        return EXIT_ERROR

    return EXIT_HEALTHY if all(result.is_up for result in outcome.results) else EXIT_UNHEALTHY


if __name__ == "__main__":
    raise SystemExit(main())
