"""Zaiflik tekshiruvlari to'plami.

Har bir tekshiruv `run(ctx)` metodiga ega bo'lib, `Finding` ro'yxatini
qaytaradi. `ALL_CHECKS` — barcha faol tekshiruvlar ro'yxati.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crawler import CrawlOutput
from ..http_client import HttpClient, Response
from ..models import Finding


@dataclass
class Context:
    """Tekshiruvlar uchun umumiy kontekst."""

    client: HttpClient
    target: str
    crawl: CrawlOutput
    home: Response
    active: bool = True  # aktiv (payload yuboradigan) testlar yoqilganmi

    def sample_pages(self, limit: int = 8):
        """Bir necha HTML sahifani tanlab qaytaradi (headerlar uchun)."""
        items = list(self.crawl.pages.items())
        return items[:limit]


class Check:
    name: str = "base"
    description: str = ""

    def run(self, ctx: Context) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError


from .headers import SecurityHeadersCheck  # noqa: E402
from .cookies import CookieCheck  # noqa: E402
from .tls import TlsCheck  # noqa: E402
from .info_disclosure import InfoDisclosureCheck  # noqa: E402
from .sensitive_files import SensitiveFilesCheck  # noqa: E402
from .sqli import SqlInjectionCheck  # noqa: E402
from .xss import ReflectedXssCheck  # noqa: E402
from .csrf import CsrfCheck  # noqa: E402
from .clickjacking import ClickjackingCheck  # noqa: E402
from .open_redirect import OpenRedirectCheck  # noqa: E402

ALL_CHECKS: list[Check] = [
    SecurityHeadersCheck(),
    CookieCheck(),
    TlsCheck(),
    InfoDisclosureCheck(),
    ClickjackingCheck(),
    SensitiveFilesCheck(),
    CsrfCheck(),
    OpenRedirectCheck(),
    ReflectedXssCheck(),
    SqlInjectionCheck(),
]

__all__ = ["Context", "Check", "ALL_CHECKS"]
