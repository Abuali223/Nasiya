"""Skanerlash dvigateli — kroul qiladi va barcha tekshiruvlarni ishga tushiradi."""

from __future__ import annotations

import datetime as _dt
from urllib.parse import urlparse

from .checks import ALL_CHECKS, Context
from .crawler import crawl
from .http_client import HttpClient
from .models import ScanResult


def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_target(url: str) -> str:
    url = url.strip()
    if not urlparse(url).scheme:
        url = "http://" + url
    return url


class Scanner:
    def __init__(
        self,
        *,
        client: HttpClient | None = None,
        max_pages: int = 40,
        max_depth: int = 3,
        active: bool = True,
        progress=None,
    ):
        self.client = client or HttpClient()
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.active = active
        self.progress = progress or (lambda msg: None)

    def scan(self, target: str) -> ScanResult:
        target = normalize_target(target)
        result = ScanResult(target=target, started_at=_now())

        self.progress(f"Nishon tekshirilmoqda: {target}")
        home = self.client.get(target)
        if not home.ok:
            result.errors.append(f"Nishonga ulanib bo'lmadi: {home.error}")
            result.finished_at = _now()
            self.progress(f"XATO: {home.error}")
            return result
        # yo'naltirilgan bo'lsa, yakuniy manzilni olamiz
        target = home.url

        self.progress("Sayt sahifalari yig'ilmoqda (crawl)...")
        crawl_out = crawl(
            self.client,
            target,
            max_pages=self.max_pages,
            max_depth=self.max_depth,
            on_page=lambda u, r: self.progress(f"  topildi: {u} [{r.status}]"),
        )
        result.pages_crawled = list(crawl_out.pages.keys())
        self.progress(
            f"{len(crawl_out.pages)} sahifa, {len(crawl_out.forms)} forma, "
            f"{len(crawl_out.links_with_params)} parametrli havola topildi."
        )

        ctx = Context(
            client=self.client,
            target=target,
            crawl=crawl_out,
            home=home,
            active=self.active,
        )

        for check in ALL_CHECKS:
            self.progress(f"Tekshirilmoqda: {check.name} ...")
            try:
                for finding in check.run(ctx):
                    result.add(finding)
            except Exception as exc:  # bitta tekshiruv yiqilsa, qolganlari davom etadi
                result.errors.append(f"{check.name} tekshiruvida xato: {exc}")
                self.progress(f"  ! {check.name}: {exc}")

        result.finished_at = _now()
        self.progress("Skanerlash tugadi.")
        return result
