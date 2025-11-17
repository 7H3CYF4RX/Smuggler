"""Logging utilities for Smuggler."""

from __future__ import annotations

import json
import logging
from logging import Logger
from pathlib import Path
from typing import Optional

from .constants import Colors


def configure_logging(
    level: str = "INFO",
    *,
    log_file: Optional[Path] = None,
    json_logs: bool = True,
) -> Logger:
    """Configure root logger with console + optional file handlers."""

    logger = logging.getLogger("smuggler")
    logger.setLevel(level.upper())

    # Clear existing handlers when reconfiguring for multiple runs/tests.
    if logger.handlers:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()

    formatter = _JsonFormatter() if json_logs else _ColorFormatter()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(_JsonFormatter())
        logger.addHandler(file_handler)

    logger.debug("Logging configured", extra={"level": level, "json": json_logs})
    return logger


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "level": record.levelname,
            "message": record.getMessage(),
            "name": record.name,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            payload.update(record.extra)  # type: ignore[arg-type]
        return json.dumps(payload)


class _ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": Colors.DIM,
        "INFO": Colors.G,
        "WARNING": Colors.Y,
        "ERROR": Colors.R,
        "CRITICAL": Colors.BG_R,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, Colors.END)
        reset = Colors.END
        return f"{color}{record.levelname:<8}{reset} {record.getMessage()}"
