"""Reflected XSS (aks etuvchi cross-site scripting) tekshiruvi."""

from __future__ import annotations

import re

from ..models import Finding, Severity
from . import Check, Context
from ._injection import collect_points

# noyob marker — javobda qidiramiz
MARKER = "nsq7x1z"
# turli kontekstlarga mo'ljallangan payloadlar
PAYLOADS = [
    f"<{MARKER}>",                         # HTML teg konteksti
    f'"{MARKER}<',                          # atribut qiymati / teg chegarasi
    f"'{MARKER}<",
    f"</title><{MARKER}>",                 # title ichidan chiqish
]


class ReflectedXssCheck(Check):
    name = "Reflected XSS"
    description = "Kiritilgan HTML/JS javobda filtrlanmasdan aks etishini tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.active:
            return []
        findings: list[Finding] = []
        points = collect_points(ctx.crawl)
        reported: set[tuple] = set()

        for point in points:
            key = (point.method, point.url, point.param)
            if key in reported:
                continue

            for payload in PAYLOADS:
                resp = point.send(ctx.client, payload)
                if not resp.ok or not resp.text:
                    continue

                # payloadning xavfli ko'rinishi javobda aynan (kodlanmagan) uchradimi?
                dangerous = f"<{MARKER}>"
                if dangerous in resp.text:
                    ctype = resp.headers.get("Content-Type", "")
                    if "html" not in ctype and ctype:
                        continue  # HTML bo'lmagan javobda XSS ijro etilmaydi
                    idx = resp.text.find(dangerous)
                    snippet = resp.text[max(0, idx - 40): idx + 40].replace("\n", " ")
                    findings.append(
                        Finding(
                            check=self.name,
                            title=f"Reflected XSS — '{point.param}' parametri",
                            severity=Severity.HIGH,
                            url=point.url,
                            param=point.param,
                            description=f"'{point.param}' parametriga yuborilgan HTML "
                            "javobda kodlanmagan holda aks etdi. Hujumchi bu orqali "
                            "brauzerda ixtiyoriy JavaScript ishga tushirib, sessiya "
                            "cookie'larini o'g'irlashi yoki foydalanuvchi nomidan amal "
                            "bajarishi mumkin.",
                            remediation="Chiqishni kontekstga mos ravishda kodlang "
                            "(HTML-encode), Content-Security-Policy qo'shing va ishonchli "
                            "shablon tizimidan foydalaning.",
                            cwe="CWE-79",
                            evidence=f"Payload: {payload!r} javobda topildi: ...{snippet}...",
                        )
                    )
                    reported.add(key)
                    break
        return findings
