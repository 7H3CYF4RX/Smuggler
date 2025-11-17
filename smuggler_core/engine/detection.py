"""Detection engine implementation."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientSession, ClientTimeout

from ..types import ResponseFingerprint, TimingProfile, Vulnerability, VulnType
from .payloads import PayloadGenerator


class DetectionEngine:
    """Runs the suite of request-smuggling detection techniques."""

    def __init__(self, baseline_samples: int, logger):
        self.baseline_samples = baseline_samples
        self.logger = logger
        self.timing_baseline = TimingProfile()
        self.response_cache = defaultdict(list)

    async def establish_baseline(self, url: str, session: ClientSession) -> None:
        """Sample normal responses to build a timing baseline."""
        self.timing_baseline = TimingProfile()
        timeout = ClientTimeout(total=10)
        self.logger.debug(
            "Establishing baseline",
            extra={"url": url, "samples": self.baseline_samples},
        )

        for index in range(self.baseline_samples):
            try:
                start = time.time()
                async with session.get(url, timeout=timeout) as resp:
                    await resp.text()
                elapsed = time.time() - start
                self.timing_baseline.samples.append(elapsed)
            except Exception as exc:  # pragma: no cover - network errors expected
                self.logger.debug(
                    "Baseline sample failed",
                    extra={"url": url, "attempt": index, "error": str(exc)},
                )

        if self.timing_baseline.samples:
            self.logger.info(
                "Baseline established",
                extra={
                    "url": url,
                    "mean": f"{self.timing_baseline.mean:.3f}",
                    "stdev": f"{self.timing_baseline.stdev:.3f}",
                },
            )

    async def differential_timing_test(
        self, url: str, session: ClientSession
    ) -> Optional[Vulnerability]:
        """Detect CL.TE via time-delay differential analysis."""
        host = urlparse(url).netloc

        for delay in (3, 5, 8):
            payload = PayloadGenerator.cl_te_timeout(host, delay=delay)
            try:
                elapsed = await self._send_payload(session, url, payload, 20)
                actual_delay = elapsed - self.timing_baseline.mean
                expected_delay = delay

                # More lenient threshold for better detection
                if abs(actual_delay - expected_delay) < 3.0 and actual_delay > delay - 1:
                    verify_payload = PayloadGenerator.cl_te_timeout(host, delay=delay + 3)
                    verify_elapsed = await self._send_payload(
                        session, url, verify_payload, 25
                    )
                    verify_delay = verify_elapsed - self.timing_baseline.mean

                    if abs(verify_delay - (delay + 3)) < 3.0 and verify_delay > (delay + 2):
                        return Vulnerability(
                            url=url,
                            vuln_type=VulnType.CL_TE,
                            confidence=0.90,
                            verified=True,
                            payload=payload,
                            evidence={
                                "expected_delay": expected_delay,
                                "actual_delay": actual_delay,
                                "verify_delay": verify_delay,
                                "baseline": self.timing_baseline.mean,
                                "stdev": self.timing_baseline.stdev,
                            },
                            false_positive_score=0.05,
                            technique="Time-Delay Differential",
                            server_behavior="Back-end processes TE, waits for smuggled content",
                        )
            except asyncio.TimeoutError:
                self.logger.debug("Timing test timeout", extra={"url": url, "delay": delay})
                continue
            except Exception as exc:  # pragma: no cover
                self.logger.debug(
                    "Differential timing test failed",
                    extra={"url": url, "delay": delay, "error": str(exc)},
                )
                continue

        return None

    async def response_queue_poisoning(
        self,
        url: str,
        session: ClientSession,
    ) -> Optional[Vulnerability]:
        """Detect TE.CL via response queue poisoning."""
        host = urlparse(url).netloc
        payload = PayloadGenerator.te_cl_confirm(host)
        timeout = ClientTimeout(total=10)

        try:
            async with session.post(url, data=payload, timeout=timeout) as resp1:
                content1 = await resp1.text()
                fp1 = ResponseFingerprint.from_response(resp1, 0, content1)

            async with session.get(url, timeout=timeout) as resp2:
                content2 = await resp2.text()
                fp2 = ResponseFingerprint.from_response(resp2, 0, content2)

            if fp1 != fp2 and ("GPOST" in content2 or resp2.status >= 400):
                async with session.post(url, data=payload, timeout=timeout) as _:
                    await _.text()
                async with session.get(url, timeout=timeout) as verify_resp:
                    verify_content = await verify_resp.text()
                    if "GPOST" in verify_content or verify_resp.status >= 400:
                        return Vulnerability(
                            url=url,
                            vuln_type=VulnType.TE_CL,
                            confidence=0.92,
                            verified=True,
                            payload=payload,
                            evidence={
                                "response1_status": resp1.status,
                                "response2_status": resp2.status,
                                "poisoning_confirmed": True,
                            },
                            false_positive_score=0.03,
                            technique="Response Queue Poisoning",
                            server_behavior="Front-end uses TE, back-end uses CL",
                        )
        except Exception as exc:  # pragma: no cover
            self.logger.debug(
                "Response queue poisoning check failed",
                extra={"url": url, "error": str(exc)},
            )

        return None

    async def te_te_obfuscation_scan(
        self, url: str, session: ClientSession
    ) -> Optional[Vulnerability]:
        """Detect TE.TE differences via obfuscation variants."""
        host = urlparse(url).netloc
        variants = PayloadGenerator.te_te_variants(host)
        timeout = ClientTimeout(total=10)

        baseline_fps = []
        for _ in range(3):
            try:
                async with session.post(url, timeout=timeout) as resp:
                    content = await resp.text()
                    baseline_fps.append(
                        ResponseFingerprint.from_response(resp, 0, content)
                    )
            except Exception:
                continue

        if not baseline_fps:
            return None

        for variant_name, payload in variants:
            try:
                async with session.post(url, data=payload, timeout=timeout) as resp:
                    content = await resp.text()
                    variant_fp = ResponseFingerprint.from_response(resp, 0, content)

                if all(variant_fp != bfp for bfp in baseline_fps):
                    async with session.post(url, data=payload, timeout=timeout) as verify:
                        vcontent = await verify.text()
                        verify_fp = ResponseFingerprint.from_response(verify, 0, vcontent)

                    if variant_fp == verify_fp:
                        return Vulnerability(
                            url=url,
                            vuln_type=VulnType.TE_TE,
                            confidence=0.88,
                            verified=True,
                            payload=payload,
                            evidence={
                                "variant": variant_name,
                                "status_diff": variant_fp.status_code
                                != baseline_fps[0].status_code,
                                "content_diff": variant_fp.content_hash
                                != baseline_fps[0].content_hash,
                            },
                            false_positive_score=0.05,
                            technique=f"TE.TE Obfuscation ({variant_name})",
                            server_behavior="Servers handle TE obfuscation differently",
                        )
            except Exception as exc:  # pragma: no cover
                self.logger.debug(
                    "TE-TE variant failed",
                    extra={"url": url, "variant": variant_name, "error": str(exc)},
                )
                continue

        return None

    async def basic_cl_te_test(
        self, url: str, session: ClientSession
    ) -> Optional[Vulnerability]:
        """Basic CL.TE test using simple payload."""
        host = urlparse(url).netloc
        payload = PayloadGenerator.cl_te_basic(host)
        timeout = ClientTimeout(total=10)

        try:
            async with session.post(url, data=payload, timeout=timeout) as resp:
                content = await resp.text()
                # Check for error responses or unusual behavior
                if resp.status >= 400 or len(content) < 100:
                    return Vulnerability(
                        url=url,
                        vuln_type=VulnType.CL_TE,
                        confidence=0.70,
                        verified=False,
                        payload=payload,
                        evidence={
                            "status_code": resp.status,
                            "response_length": len(content),
                        },
                        false_positive_score=0.20,
                        technique="Basic CL.TE Probe",
                        server_behavior="Unusual response to malformed request",
                    )
        except Exception as exc:  # pragma: no cover
            self.logger.debug(
                "Basic CL.TE test failed",
                extra={"url": url, "error": str(exc)},
            )

        return None

    async def _send_payload(
        self,
        session: ClientSession,
        url: str,
        payload: str,
        timeout_seconds: int,
    ) -> float:
        timeout = ClientTimeout(total=timeout_seconds)
        start = time.time()
        async with session.post(url, data=payload, timeout=timeout) as resp:
            await resp.text()
        return time.time() - start
