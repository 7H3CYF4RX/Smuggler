"""Configuration management for Smuggler."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
import json


class ConfigError(Exception):
    """Raised when configuration loading fails."""


@dataclass(slots=True)
class SmugglerConfig:
    """Canonical configuration object used across the project."""

    domain: str
    threads: int = 15
    aggressive: bool = False
    max_urls: int = 500
    baseline_samples: int = 5
    log_level: str = "INFO"
    log_file: Optional[Path] = None
    log_json: bool = False
    report_file: Optional[Path] = None
    url_file: Optional[Path] = None
    config_source: Optional[Path] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "domain": self.domain,
            "threads": self.threads,
            "aggressive": self.aggressive,
            "max_urls": self.max_urls,
            "baseline_samples": self.baseline_samples,
            "log_level": self.log_level,
            "log_json": self.log_json,
        }
        if self.log_file:
            data["log_file"] = str(self.log_file)
        if self.report_file:
            data["report_file"] = str(self.report_file)
        if self.url_file:
            data["url_file"] = str(self.url_file)
        if self.config_source:
            data["config_source"] = str(self.config_source)
        return data


def _load_json_config(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in config file: {path}") from exc


def load_config(
    domain: str,
    overrides: Optional[Dict[str, Any]] = None,
    config_file: Optional[str] = None,
) -> SmugglerConfig:
    """Load configuration from file and inline overrides."""

    data: Dict[str, Any] = {"domain": domain}

    if config_file:
        path = Path(config_file).expanduser().resolve()
        file_data = _load_json_config(path)
        data.update(file_data)
        data["config_source"] = path

    if overrides:
        for key, value in overrides.items():
            if value is not None:
                data[key] = value

    def _expand_path(key: str) -> None:
        if key in data and data[key]:
            data[key] = Path(data[key]).expanduser().resolve()

    for path_key in ("log_file", "report_file", "url_file"):
        _expand_path(path_key)

    return SmugglerConfig(**data)
