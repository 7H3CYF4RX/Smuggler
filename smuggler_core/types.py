"""Core data structures and enums for Smuggler."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List
import statistics
import hashlib

import aiohttp


class VulnType(Enum):
    """Supported request-smuggling vulnerability classes."""

    CL_TE = ("CL.TE", "Front-end: Content-Length | Back-end: Transfer-Encoding")
    TE_CL = ("TE.CL", "Front-end: Transfer-Encoding | Back-end: Content-Length")
    TE_TE = ("TE.TE", "Both ends use TE but handle obfuscation differently")
    CL_CL = ("CL.CL", "Dual Content-Length desynchronization")
    H2_DESYNC = ("HTTP/2 Desync", "HTTP/2 to HTTP/1.1 downgrade issues")
    TIMEOUT = ("Timeout-Based", "Time-delay differential detection")

    def __init__(self, short: str, desc: str):
        self.short = short
        self.desc = desc


@dataclass(slots=True)
class TimingProfile:
    """Accumulates timing samples and exposes statistical helpers."""

    samples: List[float] = field(default_factory=list)

    @property
    def mean(self) -> float:
        return statistics.mean(self.samples) if self.samples else 0.0

    @property
    def stdev(self) -> float:
        return statistics.stdev(self.samples) if len(self.samples) > 1 else 0.0

    @property
    def median(self) -> float:
        return statistics.median(self.samples) if self.samples else 0.0

    def is_anomalous(self, value: float, threshold: float = 2.5) -> bool:
        if self.stdev == 0:
            return False
        z_score = abs((value - self.mean) / self.stdev)
        return z_score > threshold


@dataclass(slots=True)
class ResponseFingerprint:
    """Normalized snapshot of an HTTP response for differential comparisons."""

    status_code: int
    content_length: int
    content_hash: str
    headers_hash: str
    timing: float
    server_header: str = ""

    @classmethod
    def from_response(
        cls,
        response: aiohttp.ClientResponse,
        timing: float,
        content: str,
    ) -> "ResponseFingerprint":
        headers_str = "|".join(f"{k}:{v}" for k, v in sorted(response.headers.items()))
        return cls(
            status_code=response.status,
            content_length=len(content),
            content_hash=hashlib.sha256(content.encode()).hexdigest()[:16],
            headers_hash=hashlib.sha256(headers_str.encode()).hexdigest()[:16],
            timing=timing,
            server_header=response.headers.get("Server", ""),
        )

    def __eq__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, ResponseFingerprint):
            return NotImplemented
        return (
            self.status_code == other.status_code
            and self.content_hash == other.content_hash
            and self.headers_hash == other.headers_hash
        )


@dataclass(slots=True)
class Vulnerability:
    """Represents a verified or potential issue discovered during scanning."""

    url: str
    vuln_type: VulnType
    confidence: float
    verified: bool
    payload: str
    evidence: Dict[str, Any]
    false_positive_score: float
    technique: str
    server_behavior: str
