"""Ixtiyoriy JavaScript renderer (Playwright).

SPA (React/Vue/Angular kabi) saytlarda havolalar va formalar JavaScript orqali
yuklanadi — oddiy HTML tahlili ularni ko'rmaydi. Playwright o'rnatilgan bo'lsa,
sahifa brauzerda to'liq ishga tushiriladi va yakuniy DOM qaytariladi.

Playwright yo'q bo'lsa, `PlaywrightRenderer.available()` False qaytaradi va
skaner oddiy rejimga qaytadi.
"""

from __future__ import annotations

import glob
import os


def available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _find_chromium() -> str | None:
    """Playwright o'rnatgan brauzer versiyasi mos kelmaganda, mavjud Chromium
    binarisini qo'lda topamiz (PLAYWRIGHT_BROWSERS_PATH ostidan)."""
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")
    candidates: list[str] = []
    if root:
        candidates += glob.glob(os.path.join(root, "chromium-*/chrome-linux/chrome"))
        candidates += glob.glob(os.path.join(root, "chromium-*/chrome-linux/headless_shell"))
    # tizimdagi umumiy yo'llar
    for p in ("/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome"):
        if os.path.exists(p):
            candidates.append(p)
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


class PlaywrightRenderer:
    """Sahifani brauzerda ishga tushirib, render qilingan HTML'ni qaytaradi."""

    def __init__(self, *, timeout: float = 15.0, verify_tls: bool = True):
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._pw = None
        self._browser = None
        self._context = None

    def __enter__(self):
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        launch_kwargs = {"headless": True}
        exe = _find_chromium()
        if exe:
            launch_kwargs["executable_path"] = exe
        self._browser = self._pw.chromium.launch(**launch_kwargs)
        self._context = self._browser.new_context(
            ignore_https_errors=not self.verify_tls
        )
        return self

    def __exit__(self, *exc):
        try:
            if self._context:
                self._context.close()
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        except Exception:
            pass

    def render(self, url: str) -> str | None:
        """URL'ni render qilib, yakuniy HTML'ni qaytaradi (xatoda None)."""
        if self._context is None:
            return None
        page = self._context.new_page()
        try:
            page.goto(url, timeout=int(self.timeout * 1000), wait_until="networkidle")
            return page.content()
        except Exception:
            try:
                return page.content()
            except Exception:
                return None
        finally:
            page.close()
