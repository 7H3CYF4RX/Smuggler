"""High-level scanner orchestration."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import List, Set

import aiohttp
from aiohttp import ClientSession, TCPConnector

from .config import SmugglerConfig
from .constants import Colors as C
from .engine.advanced_detection import AdvancedDetectionEngine
from .enumeration import URLEnumerator
from .reporting import ReportGenerator
from .types import Vulnerability


class SmugglerRunner:
    """Coordinates enumeration, detection, and reporting."""

    def __init__(self, config: SmugglerConfig, logger) -> None:
        self.config = config
        self.logger = logger
        self.urls: Set[str] = set()
        self.vulnerabilities: List[Vulnerability] = []
        self.start_time = time.time()

    async def run(self) -> None:
        self._print_banner()
        enumerator = URLEnumerator(
            self.config.domain,
            max_urls=self.config.max_urls,
            aggressive=self.config.aggressive,
            logger=self.logger,
        )
        self.urls = await enumerator.enumerate()

        if not self.urls:
            self.logger.warning("No URLs discovered; exiting")
            print(f"{C.R}[!] No URLs found{C.END}")
            return

        self.logger.info("Starting detection phase", extra={"urls": len(self.urls)})
        await self._scan_urls()
        self._print_summary()
        
        # Generate reports if configured
        if self.config.report_file:
            self._generate_reports()

    async def _scan_urls(self) -> None:
        connector = TCPConnector(limit=self.config.threads, ssl=False)
        semaphore = asyncio.Semaphore(self.config.threads)

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._bounded_scan(url, session, semaphore) for url in self.urls]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _bounded_scan(
        self,
        url: str,
        session: ClientSession,
        semaphore: asyncio.Semaphore,
    ) -> None:
        async with semaphore:
            await self._scan_single(url, session)

    async def _scan_single(self, url: str, session: ClientSession) -> None:
        print(f"{C.C}[→]{C.END} Scanning: {C.DIM}{url}{C.END}")
        engine = AdvancedDetectionEngine(self.config.baseline_samples, self.logger)
        await engine.establish_baseline(url, session)

        # Run comprehensive scan with all detection methods
        results = await engine.run_comprehensive_scan(url, session)
        
        for vuln in results:
            if isinstance(vuln, Vulnerability):
                self.vulnerabilities.append(vuln)
                self._print_vulnerability(vuln)

    def _print_banner(self) -> None:
        print(
            f"""
{C.R}{C.BOLD}
╔═══════════════════════════════════════════════════════════╗
║         SMUGGLER - Request Smuggling Scanner             ║
║              Advanced Detection Engine v2.0              ║
╚═══════════════════════════════════════════════════════════╝{C.END}
{C.C}Target:{C.END} {self.config.domain}
{C.C}Threads:{C.END} {self.config.threads}
{C.C}Detection Methods:{C.END} Time-Delay, Response Poisoning, TE Obfuscation
{C.DIM}{'─' * 63}{C.END}
"""
        )

    def _print_vulnerability(self, result: Vulnerability) -> None:
        status = (
            f"{C.BG_R} VERIFIED {C.END}"
            if result.verified
            else f"{C.Y} POTENTIAL {C.END}"
        )
        print(f"\n{C.R}{C.BOLD}{'═' * 60}{C.END}")
        print(f"{status} {C.BOLD}{result.vuln_type.short}{C.END}")
        print(f"{C.B}URL:{C.END} {result.url}")
        print(
            f"{C.B}Confidence:{C.END} {result.confidence:.1%} "
            f"(FP Score: {result.false_positive_score:.2%})"
        )
        print(f"{C.B}Technique:{C.END} {result.technique}")
        print(f"{C.B}Behavior:{C.END} {result.server_behavior}")
        print(f"{C.B}Evidence:{C.END} {json.dumps(result.evidence, indent=2)}")
        print(f"{C.R}{C.BOLD}{'═' * 60}{C.END}\n")

    def _print_summary(self) -> None:
        elapsed = time.time() - self.start_time
        verified = [v for v in self.vulnerabilities if v.verified]
        potential = [v for v in self.vulnerabilities if not v.verified]
        
        print(f"\n{C.C}{C.BOLD}{'═' * 63}{C.END}")
        print(f"{C.C}{C.BOLD}                        SCAN SUMMARY                          {C.END}")
        print(f"{C.C}{C.BOLD}{'═' * 63}{C.END}\n")
        print(f"{C.B}URLs Scanned:{C.END} {len(self.urls)}")
        rate = len(self.urls) / elapsed if elapsed else 0
        print(f"{C.B}Time:{C.END} {elapsed:.2f}s ({rate:.2f} URLs/s)")
        print(f"{C.B}Verified Vulns:{C.END} {C.R}{C.BOLD}{len(verified)}{C.END}")
        print(f"{C.B}Potential Issues:{C.END} {C.Y}{C.BOLD}{len(potential)}{C.END}")
        
        if verified:
            print(f"\n{C.R}{C.BOLD}VERIFIED FINDINGS:{C.END}")
            for v in verified:
                fp_status = (
                    f"{C.G}LOW FP{C.END}"
                    if v.false_positive_score < 0.05
                    else f"{C.Y}MEDIUM FP{C.END}"
                )
                print(f"  {C.R}•{C.END} {v.url}")
                print(
                    f"    Type: {v.vuln_type.short} | Technique: {v.technique} | Confidence: {v.confidence:.1%} | {fp_status}"
                )
        
        if potential:
            print(f"\n{C.Y}{C.BOLD}POTENTIAL ISSUES:{C.END}")
            for v in potential[:5]:  # Show top 5
                print(f"  {C.Y}•{C.END} {v.url}")
                print(f"    Type: {v.vuln_type.short} | Technique: {v.technique} | Confidence: {v.confidence:.1%}")
        
        if not verified and not potential:
            print(f"\n{C.G}[✓] No smuggling vulnerabilities detected{C.END}")
        
        print(f"\n{C.C}{C.BOLD}{'═' * 63}{C.END}\n")

    def _generate_reports(self) -> None:
        """Generate HTML and JSON reports."""
        elapsed = time.time() - self.start_time
        
        # Generate HTML report
        html_path = self.config.report_file
        ReportGenerator.generate_html_report(
            self.vulnerabilities,
            self.config.domain,
            html_path,
            elapsed,
        )
        print(f"{C.G}[✓] HTML Report:{C.END} {html_path}")
        
        # Generate JSON report
        json_path = html_path.with_suffix(".json")
        ReportGenerator.generate_json_report(
            self.vulnerabilities,
            self.config.domain,
            json_path,
            elapsed,
        )
        print(f"{C.G}[✓] JSON Report:{C.END} {json_path}")
