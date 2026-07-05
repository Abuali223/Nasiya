"""Path Traversal / LFI — fayl yo'liga aralashib server fayllarini o'qish."""

from __future__ import annotations

import re

from ..models import Finding, Severity
from . import Check, Context
from ._injection import collect_points

PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../windows/win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
]

# muvaffaqiyat imzolari
SIGNATURES = [
    ("Linux /etc/passwd", re.compile(r"root:.*?:0:0:", re.M)),
    ("Windows win.ini", re.compile(r"\[extensions\]|\[fonts\]|for 16-bit app support", re.I)),
]


class PathTraversalCheck(Check):
    name = "Path Traversal / LFI"
    description = "Parametr orqali server fayllarini o'qish mumkinligini tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.active:
            return []
        findings: list[Finding] = []
        reported: set[tuple] = set()

        for point in collect_points(ctx.crawl):
            key = (point.method, point.url, point.param)
            if key in reported:
                continue
            for payload in PAYLOADS:
                resp = point.send(ctx.client, payload)
                if not resp.ok or not resp.text:
                    continue
                for label, pattern in SIGNATURES:
                    m = pattern.search(resp.text)
                    if m:
                        findings.append(
                            Finding(
                                check=self.name,
                                title=f"Path Traversal — '{point.param}' parametri",
                                severity=Severity.CRITICAL,
                                url=point.url,
                                param=point.param,
                                description=f"'{point.param}' parametriga fayl yo'li "
                                f"yuborilganda server ichki fayli o'qildi ({label}). "
                                "Hujumchi bu orqali konfiguratsiya fayllari, parollar va "
                                "manba kodini o'qishi mumkin.",
                                remediation="Foydalanuvchi kiritmasini fayl yo'li sifatida "
                                "ishlatmang; qat'iy oq ro'yxat (whitelist) va "
                                "`basename()` qo'llang, `../` belgilarni rad eting.",
                                cwe="CWE-22",
                                evidence=f"Payload: {payload!r} -> {m.group(0)[:80]}",
                            )
                        )
                        reported.add(key)
                        break
                if key in reported:
                    break
        return findings
