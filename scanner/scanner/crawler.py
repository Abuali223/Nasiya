"""Sayt bo'ylab yuruvchi (crawler) va HTML tahlilchi (parser).

Tashqi kutubxonasiz — faqat standart `html.parser` ishlatiladi.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag

from .http_client import HttpClient, Response


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class Form:
    """HTML formasi haqidagi ma'lumot."""

    action: str            # to'liq (absolute) URL
    method: str = "get"
    fields: list[FormField] = field(default_factory=list)
    source_url: str = ""

    def input_names(self) -> list[str]:
        return [f.name for f in self.fields if f.name]


class _LinkFormParser(HTMLParser):
    """HTML'dan havolalar va formalarni ajratib oladi."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()
        self.forms: list[Form] = []
        self._cur_form: Form | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.add(urljoin(self.base_url, a["href"]))
        elif tag in ("script", "img", "iframe", "link") and a.get("src"):
            self.links.add(urljoin(self.base_url, a["src"]))
        elif tag == "form":
            action = urljoin(self.base_url, a.get("action", "") or self.base_url)
            self._cur_form = Form(
                action=action,
                method=(a.get("method") or "get").lower(),
                source_url=self.base_url,
            )
        elif tag in ("input", "textarea", "select") and self._cur_form is not None:
            name = a.get("name")
            if name:
                self._cur_form.fields.append(
                    FormField(
                        name=name,
                        type=(a.get("type") or ("textarea" if tag == "textarea" else "text")).lower(),
                        value=a.get("value", ""),
                    )
                )

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


def parse_page(base_url: str, html: str) -> tuple[set[str], list[Form]]:
    parser = _LinkFormParser(base_url)
    try:
        parser.feed(html)
    except Exception:
        pass  # buzuq HTML — bor narsani qaytaramiz
    if parser._cur_form is not None:  # yopilmagan form
        parser.forms.append(parser._cur_form)
    return parser.links, parser.forms


def same_domain(url: str, base: str) -> bool:
    try:
        return urlparse(url).netloc.lower() == urlparse(base).netloc.lower()
    except ValueError:
        return False


def _is_crawlable(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False
    # ikkilik/media fayllarni tashlab yuboramiz
    bad_ext = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".pdf",
        ".zip", ".gz", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".css",
    )
    return not p.path.lower().endswith(bad_ext)


@dataclass
class CrawlOutput:
    pages: dict[str, Response] = field(default_factory=dict)
    forms: list[Form] = field(default_factory=list)
    links_with_params: set[str] = field(default_factory=set)


def crawl(
    client: HttpClient,
    start_url: str,
    *,
    max_pages: int = 40,
    max_depth: int = 3,
    on_page=None,
) -> CrawlOutput:
    """Bir domen doirasida saytni aylanib chiqadi (BFS)."""

    out = CrawlOutput()
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])

    while queue and len(out.pages) < max_pages:
        url, depth = queue.popleft()
        url = urldefrag(url)[0]
        if url in seen or depth > max_depth:
            continue
        seen.add(url)

        resp = client.get(url)
        if not resp.ok:
            continue
        out.pages[url] = resp
        if on_page:
            on_page(url, resp)

        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype and resp.text[:200].lstrip()[:1] != "<":
            continue

        if urlparse(url).query:
            out.links_with_params.add(url)

        links, forms = parse_page(url, resp.text)
        for form in forms:
            if same_domain(form.action, start_url):
                out.forms.append(form)

        for link in links:
            link = urldefrag(link)[0]
            if link in seen:
                continue
            if urlparse(link).query and same_domain(link, start_url):
                out.links_with_params.add(link)
            if (
                same_domain(link, start_url)
                and _is_crawlable(link)
                and link not in seen
            ):
                queue.append((link, depth + 1))

    return out
