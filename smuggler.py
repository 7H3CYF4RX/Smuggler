#!/usr/bin/env python3
"""Smuggler CLI entry point."""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any, Dict, Optional

from smuggler_core import (
    SmugglerRunner,
    configure_logging,
    load_config,
)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Advanced HTTP request smuggling scanner",
    )
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("--config", help="Path to JSON config file", default=None)
    parser.add_argument("--threads", type=int, default=None, help="Concurrent request limit")
    parser.add_argument("--max-urls", type=int, default=None, help="Maximum URLs to discover")
    parser.add_argument(
        "--baseline-samples",
        type=int,
        default=None,
        help="Requests used to establish timing baselines",
    )
    parser.add_argument(
        "--aggressive",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable aggressive enumeration modes",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None,
        help="Logging verbosity",
    )
    parser.add_argument("--log-file", default=None, help="Optional log file path")
    parser.add_argument(
        "--log-json",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Emit logs in JSON (default) or colorized text",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="Path to save HTML report (e.g., report.html)",
    )
    parser.add_argument(
        "--urls-file",
        default=None,
        help="Path to file containing seed URLs (one per line)",
    )

    return parser.parse_args(argv)


def build_overrides(args: argparse.Namespace) -> Dict[str, Any]:
    overrides: Dict[str, Any] = {
        "threads": args.threads,
        "max_urls": args.max_urls,
        "baseline_samples": args.baseline_samples,
        "aggressive": args.aggressive,
        "log_level": args.log_level,
        "log_file": args.log_file,
        "log_json": args.log_json,
        "report_file": args.report,
        "url_file": args.urls_file,
    }
    return {key: value for key, value in overrides.items() if value is not None}


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    overrides = build_overrides(args)

    try:
        config = load_config(args.domain, overrides=overrides, config_file=args.config)
    except Exception as exc:  # pragma: no cover - CLI layer
        print(f"[!] Failed to load configuration: {exc}", file=sys.stderr)
        return 1

    logger = configure_logging(
        level=config.log_level,
        log_file=config.log_file,
        json_logs=config.log_json,
    )

    runner = SmugglerRunner(config, logger)
    try:
        asyncio.run(runner.run())
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
