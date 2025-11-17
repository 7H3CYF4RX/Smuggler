"""Advanced detection engine with deep validation for all smuggling types."""

from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientSession, ClientTimeout

from ..types import ResponseFingerprint, TimingProfile, Vulnerability, VulnType
from .advanced_payloads import AdvancedPayloadGenerator


class AdvancedDetectionEngine:
    """Comprehensive detection for all HTTP request smuggling types."""

    def __init__(self, baseline_samples: int, logger):
        self.baseline_samples = baseline_samples
        self.logger = logger
        self.timing_baseline = TimingProfile()
        self.response_cache: Dict[str, ResponseFingerprint] = {}

    async def establish_baseline(self, url: str, session: ClientSession) -> None:
        """Build timing and response baselines."""
        self.timing_baseline = TimingProfile()
        timeout = ClientTimeout(total=10)

        for index in range(self.baseline_samples):
            try:
                start = time.time()
                async with session.get(url, timeout=timeout) as resp:
                    content = await resp.text()
                    fp = ResponseFingerprint.from_response(resp, 0, content)
                    self.response_cache[f"baseline_{index}"] = fp
                elapsed = time.time() - start
                self.timing_baseline.samples.append(elapsed)
            except Exception as exc:
                self.logger.debug(f"Baseline sample {index} failed: {exc}")

        self.logger.info(
            "Baseline established",
            extra={
                "mean": f"{self.timing_baseline.mean:.3f}s",
                "stdev": f"{self.timing_baseline.stdev:.3f}s",
            },
        )

    async def run_comprehensive_scan(
        self, url: str, session: ClientSession
    ) -> List[Vulnerability]:
        """Run all detection methods and return findings."""
        vulnerabilities: List[Vulnerability] = []

        # Run all detection methods in parallel
        tasks = [
            self._test_cl_te(url, session),
            self._test_te_cl(url, session),
            self._test_te_te(url, session),
            self._test_cl_cl(url, session),
            self._test_h2_smuggling(url, session),
            self._test_header_smuggling(url, session),
            self._test_prefix_injection(url, session),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
            elif isinstance(result, Vulnerability):
                vulnerabilities.append(result)

        return vulnerabilities

    async def _test_cl_te(self, url: str, session: ClientSession) -> List[Vulnerability]:
        """Test all CL.TE variants with deep validation."""
        host = urlparse(url).netloc
        variants = AdvancedPayloadGenerator.cl_te_variants(host)
        findings: List[Vulnerability] = []

        for name, payload in variants:
            try:
                # Send payload and measure response
                start = time.time()
                async with session.post(url, data=payload, timeout=ClientTimeout(total=15)) as resp:
                    content = await resp.text()
                    elapsed = time.time() - start

                fp = ResponseFingerprint.from_response(resp, elapsed, content)

                # Deep validation checks
                is_anomalous = self.timing_baseline.is_anomalous(elapsed, threshold=2.0)
                status_unusual = resp.status >= 400
                response_small = len(content) < 50

                if is_anomalous or status_unusual or response_small:
                    confidence = 0.85 if is_anomalous else 0.70
                    findings.append(
                        Vulnerability(
                            url=url,
                            vuln_type=VulnType.CL_TE,
                            confidence=confidence,
                            verified=is_anomalous,
                            payload=payload,
                            evidence={
                                "timing_anomaly": is_anomalous,
                                "elapsed": f"{elapsed:.3f}s",
                                "baseline_mean": f"{self.timing_baseline.mean:.3f}s",
                                "status_code": resp.status,
                                "response_length": len(content),
                                "variant": name,
                            },
                            false_positive_score=0.10,
                            technique=name,
                            server_behavior="Possible CL.TE desynchronization detected",
                        )
                    )
            except asyncio.TimeoutError:
                self.logger.debug(f"CL.TE test timeout: {name}")
            except Exception as exc:
                self.logger.debug(f"CL.TE test failed ({name}): {exc}")

        return findings

    async def _test_te_cl(self, url: str, session: ClientSession) -> List[Vulnerability]:
        """Test all TE.CL variants with response poisoning validation."""
        host = urlparse(url).netloc
        variants = AdvancedPayloadGenerator.te_cl_variants(host)
        findings: List[Vulnerability] = []

        for name, payload in variants:
            try:
                timeout = ClientTimeout(total=10)

                # Send poisoning payload
                async with session.post(url, data=payload, timeout=timeout) as resp1:
                    content1 = await resp1.text()

                # Follow-up request to check for poisoning
                await asyncio.sleep(0.5)
                async with session.get(url, timeout=timeout) as resp2:
                    content2 = await resp2.text()

                # Deep validation
                poisoned = "GPOST" in content2 or resp2.status >= 400
                content_changed = content1 != content2
                status_error = resp2.status >= 400

                if poisoned or (content_changed and status_error):
                    findings.append(
                        Vulnerability(
                            url=url,
                            vuln_type=VulnType.TE_CL,
                            confidence=0.90 if poisoned else 0.75,
                            verified=poisoned,
                            payload=payload,
                            evidence={
                                "poisoned": poisoned,
                                "response_changed": content_changed,
                                "status_error": status_error,
                                "resp1_status": resp1.status,
                                "resp2_status": resp2.status,
                                "variant": name,
                            },
                            false_positive_score=0.08,
                            technique=name,
                            server_behavior="Response queue poisoning detected",
                        )
                    )
            except Exception as exc:
                self.logger.debug(f"TE.CL test failed ({name}): {exc}")

        return findings

    async def _test_te_te(self, url: str, session: ClientSession) -> List[Vulnerability]:
        """Test TE.TE obfuscation variants."""
        host = urlparse(url).netloc
        variants = AdvancedPayloadGenerator.te_te_variants(host)
        findings: List[Vulnerability] = []

        # Get baseline response
        baseline_fps = []
        for _ in range(2):
            try:
                async with session.get(url, timeout=ClientTimeout(total=10)) as resp:
                    content = await resp.text()
                    baseline_fps.append(ResponseFingerprint.from_response(resp, 0, content))
            except Exception:
                continue

        if not baseline_fps:
            return findings

        for name, payload in variants:
            try:
                async with session.post(url, data=payload, timeout=ClientTimeout(total=10)) as resp:
                    content = await resp.text()
                    test_fp = ResponseFingerprint.from_response(resp, 0, content)

                # Check if response differs from baseline
                differs = all(test_fp != bfp for bfp in baseline_fps)
                if differs:
                    findings.append(
                        Vulnerability(
                            url=url,
                            vuln_type=VulnType.TE_TE,
                            confidence=0.80,
                            verified=False,
                            payload=payload,
                            evidence={
                                "response_differs": differs,
                                "status_diff": test_fp.status_code != baseline_fps[0].status_code,
                                "content_diff": test_fp.content_hash != baseline_fps[0].content_hash,
                                "variant": name,
                            },
                            false_positive_score=0.15,
                            technique=name,
                            server_behavior="TE.TE obfuscation handling difference detected",
                        )
                    )
            except Exception as exc:
                self.logger.debug(f"TE.TE test failed ({name}): {exc}")

        return findings

    async def _test_cl_cl(self, url: str, session: ClientSession) -> List[Vulnerability]:
        """Test CL.CL dual Content-Length variants."""
        host = urlparse(url).netloc
        variants = AdvancedPayloadGenerator.cl_cl_variants(host)
        findings: List[Vulnerability] = []

        for name, payload in variants:
            try:
                async with session.post(url, data=payload, timeout=ClientTimeout(total=10)) as resp:
                    content = await resp.text()

                # Check for error or unusual response
                if resp.status >= 400 or len(content) < 100:
                    findings.append(
                        Vulnerability(
                            url=url,
                            vuln_type=VulnType.CL_CL,
                            confidence=0.65,
                            verified=False,
                            payload=payload,
                            evidence={
                                "status_code": resp.status,
                                "response_length": len(content),
                                "variant": name,
                            },
                            false_positive_score=0.25,
                            technique=name,
                            server_behavior="Dual Content-Length handling anomaly",
                        )
                    )
            except Exception as exc:
                self.logger.debug(f"CL.CL test failed ({name}): {exc}")

        return findings

    async def _test_h2_smuggling(self, url: str, session: ClientSession) -> List[Vulnerability]:
        """Test HTTP/2 smuggling variants."""
        host = urlparse(url).netloc
        variants = AdvancedPayloadGenerator.h2_smuggling_variants(host)
        findings: List[Vulnerability] = []

        for name, payload in variants:
            try:
                async with session.post(url, data=payload, timeout=ClientTimeout(total=10)) as resp:
                    content = await resp.text()

                # Check for h2c upgrade or unusual response
                if "101" in str(resp.status) or resp.status >= 400:
                    findings.append(
                        Vulnerability(
                            url=url,
                            vuln_type=VulnType.H2_DESYNC,
                            confidence=0.70,
                            verified=False,
                            payload=payload,
                            evidence={
                                "status_code": resp.status,
                                "upgrade_response": "101" in str(resp.status),
                                "variant": name,
                            },
                            false_positive_score=0.20,
                            technique=name,
                            server_behavior="HTTP/2 downgrade or upgrade anomaly",
                        )
                    )
            except Exception as exc:
                self.logger.debug(f"H2 test failed ({name}): {exc}")

        return findings

    async def _test_header_smuggling(self, url: str, session: ClientSession) -> List[Vulnerability]:
        """Test header normalization smuggling."""
        host = urlparse(url).netloc
        variants = AdvancedPayloadGenerator.header_smuggling_variants(host)
        findings: List[Vulnerability] = []

        for name, payload in variants:
            try:
                async with session.post(url, data=payload, timeout=ClientTimeout(total=10)) as resp:
                    content = await resp.text()

                # Check for unusual behavior
                if resp.status >= 400 or "error" in content.lower():
                    findings.append(
                        Vulnerability(
                            url=url,
                            vuln_type=VulnType.CL_TE,
                            confidence=0.60,
                            verified=False,
                            payload=payload,
                            evidence={
                                "status_code": resp.status,
                                "error_in_response": "error" in content.lower(),
                                "variant": name,
                            },
                            false_positive_score=0.30,
                            technique=name,
                            server_behavior="Header normalization difference detected",
                        )
                    )
            except Exception as exc:
                self.logger.debug(f"Header smuggling test failed ({name}): {exc}")

        return findings

    async def _test_prefix_injection(self, url: str, session: ClientSession) -> List[Vulnerability]:
        """Test prefix injection for cache poisoning."""
        host = urlparse(url).netloc
        variants = AdvancedPayloadGenerator.prefix_injection_variants(host)
        findings: List[Vulnerability] = []

        for name, payload in variants:
            try:
                async with session.post(url, data=payload, timeout=ClientTimeout(total=10)) as resp:
                    content = await resp.text()

                # Check for injected content
                if "HTTP/1.1" in content or "GET" in content:
                    findings.append(
                        Vulnerability(
                            url=url,
                            vuln_type=VulnType.CL_TE,
                            confidence=0.75,
                            verified=False,
                            payload=payload,
                            evidence={
                                "injected_content_found": True,
                                "response_length": len(content),
                                "variant": name,
                            },
                            false_positive_score=0.18,
                            technique=name,
                            server_behavior="Prefix injection detected in response",
                        )
                    )
            except Exception as exc:
                self.logger.debug(f"Prefix injection test failed ({name}): {exc}")

        return findings
