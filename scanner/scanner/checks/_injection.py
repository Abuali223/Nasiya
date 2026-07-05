"""Inyeksiya nuqtalari (injection points) uchun umumiy yordamchilar.

GET parametrlari va HTML formalarini bitta umumiy "nuqta" ko'rinishiga keltiradi,
shunda SQLi va XSS tekshiruvlari bir xil interfeys bilan ishlaydi.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..crawler import Form
from ..http_client import HttpClient, Response


@dataclass
class InjectionPoint:
    """Bitta sinaladigan kirish nuqtasi (parametr)."""

    method: str            # "get" yoki "post"
    url: str               # so'rov yuboriladigan manzil
    param: str             # sinaladigan parametr nomi
    base_params: dict      # boshqa parametrlarning asosiy qiymatlari
    source: str            # bu nuqta topilgan sahifa

    def send(self, client: HttpClient, payload: str) -> Response:
        params = dict(self.base_params)
        params[self.param] = payload
        if self.method == "post":
            return client.post(self.url, data=params)
        # GET: parametrlarni URL query'ga joylaymiz
        parsed = urlparse(self.url)
        return client.get(urlunparse(parsed._replace(query=urlencode(params))))


def _fill_default(field_type: str) -> str:
    """Forma maydoni uchun aqlli standart qiymat."""
    return {
        "email": "test@example.com",
        "number": "1",
        "tel": "1000000",
        "url": "https://example.com",
        "password": "Test1234!",
        "date": "2024-01-01",
    }.get(field_type, "test")


def points_from_url(url: str, source: str = "") -> list[InjectionPoint]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return []
    base = {k: v[0] for k, v in qs.items()}
    clean_url = urlunparse(parsed._replace(query=""))
    return [
        InjectionPoint("get", clean_url, name, base, source or url)
        for name in qs
    ]


def points_from_form(form: Form) -> list[InjectionPoint]:
    base: dict[str, str] = {}
    testable: list[str] = []
    for f in form.fields:
        if not f.name:
            continue
        if f.type in ("submit", "button", "image", "file", "reset"):
            base[f.name] = f.value
            continue
        base[f.name] = f.value or _fill_default(f.type)
        if f.type not in ("hidden",):
            testable.append(f.name)
    return [
        InjectionPoint(form.method, form.action, name, base, form.source_url)
        for name in testable
    ]


def collect_points(crawl) -> list[InjectionPoint]:
    """Kroul natijasidan barcha inyeksiya nuqtalarini yig'adi."""
    points: list[InjectionPoint] = []
    seen: set[tuple] = set()

    for url in crawl.links_with_params:
        for p in points_from_url(url):
            k = (p.method, p.url, p.param)
            if k not in seen:
                seen.add(k)
                points.append(p)

    for form in crawl.forms:
        for p in points_from_form(form):
            k = (p.method, p.url, p.param)
            if k not in seen:
                seen.add(k)
                points.append(p)

    return points
