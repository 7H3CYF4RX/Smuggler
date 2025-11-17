"""Comprehensive URL discovery utilities."""

from __future__ import annotations

import asyncio
import re
from logging import Logger
from typing import Optional, Set
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import ClientSession, ClientTimeout


DEFAULT_COMMON_PATHS = [
    "/",
    "/api",
    "/admin",
    "/login",
    "/dashboard",
    "/user",
    "/users",
    "/account",
    "/profile",
    "/settings",
    "/config",
    "/search",
    "/upload",
    "/download",
    "/file",
    "/files",
    "/data",
    "/v1",
    "/v2",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/rest",
    "/webhook",
    "/callback",
    "/auth",
    "/oauth",
    "/token",
    "/refresh",
    "/logout",
    "/register",
    "/signup",
    "/password",
    "/reset",
    "/verify",
    "/confirm",
    "/activate",
    "/checkout",
    "/cart",
    "/order",
    "/orders",
    "/payment",
    "/billing",
    "/invoice",
    "/subscription",
    "/product",
    "/products",
    "/category",
    "/categories",
    "/item",
    "/items",
    "/post",
    "/posts",
    "/article",
    "/articles",
    "/blog",
    "/news",
    "/feed",
    "/rss",
    "/sitemap.xml",
    "/robots.txt",
    "/.well-known",
    "/health",
    "/status",
    "/ping",
    "/debug",
    "/test",
    "/dev",
    "/stage",
    "/prod",
    "/internal",
    "/private",
    "/public",
    "/assets",
    "/static",
    "/media",
    "/images",
    "/img",
    "/css",
    "/js",
    "/fonts",
    "/docs",
    "/documentation",
    "/swagger",
    "/openapi",
    "/metrics",
    "/prometheus",
]

DEFAULT_API_PARAMS = ["id", "user", "page", "limit", "offset", "sort", "filter"]


class URLEnumerator:
    """Discovers candidate URLs using multiple passive and active techniques."""

    def __init__(
        self,
        domain: str,
        *,
        max_urls: int,
        aggressive: bool,
        logger: Logger,
        common_paths: Optional[list[str]] = None,
        api_params: Optional[list[str]] = None,
    ) -> None:
        self.domain = domain
        self.max_urls = max_urls
        self.aggressive = aggressive
        self.logger = logger
        self.common_paths = common_paths or DEFAULT_COMMON_PATHS
        self.api_params = api_params or DEFAULT_API_PARAMS
        self.discovered: Set[str] = set()

    async def enumerate(self) -> Set[str]:
        """Run the five-stage enumeration pipeline."""
        self.logger.info(
            "Starting enumeration",
            extra={"domain": self.domain, "max_urls": self.max_urls, "aggressive": self.aggressive},
        )

        async with aiohttp.ClientSession() as session:
            robots = await self.parse_robots_txt(session)
            self.discovered.update(robots)
            self.logger.info("Robots parsed", extra={"count": len(robots)})

            sitemap_urls = await self.parse_sitemap(session)
            self.discovered.update(sitemap_urls)
            self.logger.info("Sitemap parsed", extra={"count": len(sitemap_urls)})

            if self.aggressive:
                common = await self.discover_common_endpoints(session)
                self.discovered.update(common)
                self.logger.info("Common endpoint brute-force complete", extra={"count": len(common)})
            else:
                self.logger.debug("Skipping common endpoint brute-force (aggressive disabled)")

            seeds = self.discovered.copy() or {f"https://{self.domain}"}
            await self.crawl_with_depth(session, seeds, max_depth=3)
            self.logger.info("Crawling complete", extra={"count": len(self.discovered)})

            if self.aggressive and len(self.discovered) < self.max_urls:
                await self.parameter_discovery(session)
            else:
                self.logger.debug("Skipping parameter discovery")

        filtered = {url for url in self.discovered if self._is_scannable(url)}
        self.discovered = filtered
        self.logger.info("Enumeration complete", extra={"unique_urls": len(filtered)})
        return filtered

    async def parse_robots_txt(self, session: ClientSession) -> Set[str]:
        urls: Set[str] = set()
        timeout = ClientTimeout(total=5)
        target = f"https://{self.domain}/robots.txt"
        try:
            async with session.get(target, timeout=timeout) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith(("Disallow:", "Allow:")):
                            path = line.split(":", 1)[1].strip()
                            if not path or path == "/":
                                continue
                            path = path.replace("*", "").split("?")[0]
                            if path:
                                urls.add(f"https://{self.domain}{path}")
                        elif line.startswith("Sitemap:"):
                            sitemap = line.split(":", 1)[1].strip()
                            if sitemap:
                                urls.add(sitemap)
        except Exception as exc:  # pragma: no cover - network
            self.logger.debug("robots.txt fetch failed", extra={"error": str(exc)})
        return urls

    async def parse_sitemap(self, session: ClientSession) -> Set[str]:
        urls: Set[str] = set()
        timeout = ClientTimeout(total=5)
        candidates = [
            f"https://{self.domain}/sitemap.xml",
            f"https://{self.domain}/sitemap_index.xml",
            f"https://{self.domain}/sitemap-index.xml",
        ]
        for sitemap_url in candidates:
            try:
                async with session.get(sitemap_url, timeout=timeout) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        for match in re.findall(r"<loc>(.*?)</loc>", content):
                            parsed = urlparse(match)
                            if parsed.netloc == self.domain:
                                urls.add(match)
            except Exception:
                continue
        return urls

    async def discover_common_endpoints(self, session: ClientSession) -> Set[str]:
        urls: Set[str] = set()
        timeout = ClientTimeout(total=3)
        tasks = [self.check_endpoint(f"https://{self.domain}{path}", session, timeout) for path in self.common_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, str):
                urls.add(result)
        return urls

    async def check_endpoint(
        self,
        url: str,
        session: ClientSession,
        timeout: ClientTimeout,
    ) -> Optional[str]:
        try:
            async with session.head(url, timeout=timeout, allow_redirects=False) as resp:
                if resp.status in {200, 201, 202, 301, 302, 307, 308, 401, 403}:
                    self.logger.debug("Endpoint discovered", extra={"url": url, "status": resp.status})
                    return url
        except Exception:
            return None
        return None

    async def extract_js_urls(self, content: str, base_url: str) -> Set[str]:
        urls: Set[str] = set()
        patterns = [
            r'"([^"]+)"',
            r"'([^']+)'",
            r"fetch\([\"']([^\"']+)[\"']",
            r"axios\.[a-z]+\([\"']([^\"']+)[\"']",
            r"\.get\([\"']([^\"']+)[\"']",
            r"\.post\([\"']([^\"']+)[\"']",
        ]
        for pattern in patterns:
            for match in re.findall(pattern, content):
                candidate = match if isinstance(match, str) else match[0]
                if candidate.startswith("/"):
                    url = urljoin(base_url, candidate)
                else:
                    url = candidate
                parsed = urlparse(url)
                if parsed.scheme in {"http", "https"} and parsed.netloc == self.domain:
                    urls.add(url)
        return urls

    async def crawl_with_depth(
        self,
        session: ClientSession,
        seed_urls: Set[str],
        max_depth: int = 3,
    ) -> None:
        queue = [(url, 0) for url in seed_urls]
        visited: Set[str] = set()
        timeout = ClientTimeout(total=10)

        while queue and len(self.discovered) < self.max_urls:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            try:
                async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                    if resp.status == 200:
                        self.discovered.add(url)
                        content = await resp.text()
                        html_links = re.findall(r'href=["\'](.*?)["\']', content)
                        js_urls = await self.extract_js_urls(content, url)
                        for link in set(html_links) | js_urls:
                            if len(self.discovered) >= self.max_urls:
                                break
                            absolute = urljoin(url, link)
                            parsed = urlparse(absolute)
                            if parsed.scheme in {"http", "https"} and parsed.netloc == self.domain:
                                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                if parsed.query:
                                    clean += f"?{parsed.query}"
                                if clean not in visited:
                                    queue.append((clean, depth + 1))
                    elif resp.status in {301, 302, 307, 308}:
                        redirect = resp.headers.get("Location")
                        if redirect:
                            queue.append((urljoin(url, redirect), depth))
            except Exception:
                continue

    async def parameter_discovery(self, session: ClientSession) -> None:
        timeout = ClientTimeout(total=3)
        base_candidates = list(self.discovered)[:20]
        for base in base_candidates:
            if "?" in base:
                continue
            for param in self.api_params[:3]:
                candidate = f"{base}?{param}=1"
                result = await self.check_endpoint(candidate, session, timeout)
                if result:
                    self.discovered.add(result)

    def _is_scannable(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.path.endswith((".jpg", ".png", ".gif", ".css", ".js", ".woff", ".ttf", ".svg", ".ico")):
            return False
        return True
