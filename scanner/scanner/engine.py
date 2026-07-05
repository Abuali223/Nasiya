"""Skanerlash dvigateli — kroul qiladi va barcha tekshiruvlarni ishga tushiradi."""

from __future__ import annotations

import datetime as _dt
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        check_default_creds: bool = False,
        renderer=None,
        progress=None,
    ):
        self.client = client or HttpClient()
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.active = active
        self.check_default_creds = check_default_creds
        self.renderer = renderer
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
            renderer=self.renderer,
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
            check_default_creds=self.check_default_creds,
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


def scan_many(
    targets: list[str],
    *,
    concurrency: int = 3,
    client_factory=None,
    max_pages: int = 40,
    max_depth: int = 3,
    active: bool = True,
    check_default_creds: bool = False,
    renderer_factory=None,
    progress=None,
) -> list[ScanResult]:
    """Bir nechta saytni (ehtimol parallel) skanerlaydi.

    Har bir sayt uchun alohida HTTP mijoz (va kerak bo'lsa alohida renderer)
    yaratiladi, shunda ular bir-biriga xalaqit bermaydi.
    `renderer_factory` — har chaqiruvda yangi renderer qaytaruvchi funksiya yoki None.
    """
    progress = progress or (lambda msg: None)
    targets = [normalize_target(t) for t in targets if t.strip()]

    def _run_one(target: str) -> ScanResult:
        client = client_factory() if client_factory else HttpClient()
        renderer_cm = renderer_factory() if renderer_factory else None
        try:
            if renderer_cm is not None:
                with renderer_cm as renderer:
                    scanner = Scanner(
                        client=client, max_pages=max_pages, max_depth=max_depth,
                        active=active, check_default_creds=check_default_creds,
                        renderer=renderer,
                        progress=lambda m, t=target: progress(f"[{t}] {m}"),
                    )
                    return scanner.scan(target)
            scanner = Scanner(
                client=client, max_pages=max_pages, max_depth=max_depth,
                active=active, check_default_creds=check_default_creds,
                progress=lambda m, t=target: progress(f"[{t}] {m}"),
            )
            return scanner.scan(target)
        except Exception as exc:  # bitta sayt yiqilsa, boshqalari davom etadi
            res = ScanResult(target=target, started_at=_now(), finished_at=_now())
            res.errors.append(f"Skanerlashda xato: {exc}")
            return res

    results: list[ScanResult] = []
    if concurrency <= 1 or len(targets) == 1:
        for t in targets:
            progress(f"=== Sayt: {t} ===")
            results.append(_run_one(t))
        return results

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        future_map = {pool.submit(_run_one, t): t for t in targets}
        for fut in as_completed(future_map):
            results.append(fut.result())

    # kiritilgan tartibda qaytaramiz
    order = {t: i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order.get(r.target, 999))
    return results
