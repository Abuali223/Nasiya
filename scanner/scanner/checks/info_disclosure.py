"""Ma'lumot oshkor bo'lishi — server/texnologiya versiyalari va batafsil xatolar."""

from __future__ import annotations

import re

from ..models import Finding, Severity
from . import Check, Context

# javob matnida uchraydigan xato/stack-trace izlari
ERROR_SIGNATURES = [
    ("PHP", re.compile(r"(?:Fatal error|Warning): .+ in .+ on line \d+", re.I)),
    ("PHP", re.compile(r"<b>(?:Notice|Warning|Fatal error)</b>:", re.I)),
    ("Java", re.compile(r"(?:javax?\.servlet|java\.lang\.\w+Exception|at [\w.]+\([\w.]+:\d+\))")),
    ("Python", re.compile(r"Traceback \(most recent call last\)")),
    ("ASP.NET", re.compile(r"(?:Server Error in|System\.\w+\.\w+Exception|Microsoft \.NET Framework)", re.I)),
    ("Ruby", re.compile(r"(?:ActionController|ActiveRecord)::\w+")),
    ("SQL", re.compile(r"SQL syntax.*?(?:MySQL|MariaDB|PostgreSQL|SQLite)", re.I)),
]

VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


class InfoDisclosureCheck(Check):
    name = "Ma'lumot oshkor bo'lishi"
    description = "Server versiyalari va batafsil xato xabarlarini aniqlaydi."

    def run(self, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        resp = ctx.home

        # 1) Versiya oshkor qiluvchi sarlavhalar
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for h in VERSION_HEADERS:
            val = headers.get(h)
            if val and re.search(r"\d", val):  # versiya raqami bor
                findings.append(
                    Finding(
                        check=self.name,
                        title=f"'{h}' sarlavhasi versiyani oshkor qilmoqda",
                        severity=Severity.LOW,
                        url=resp.url,
                        param=h,
                        description=f"'{h}: {val}' sarlavhasi ishlatilayotgan dasturiy "
                        "ta'minot va uning versiyasini oshkor qilmoqda. Hujumchi bundan "
                        "ma'lum zaifliklarni topish uchun foydalanadi.",
                        remediation=f"'{h}' sarlavhasini o'chirib qo'ying yoki versiya "
                        "raqamini yashiring.",
                        cwe="CWE-200",
                        evidence=f"{h}: {val}",
                    )
                )

        # 2) Batafsil xato/stack-trace (bir necha sahifada)
        reported: set[str] = set()
        for url, page in ctx.sample_pages(limit=12):
            if not page.ok:
                continue
            for tech, pattern in ERROR_SIGNATURES:
                m = pattern.search(page.text)
                if m and tech not in reported:
                    reported.add(tech)
                    snippet = m.group(0)[:200]
                    findings.append(
                        Finding(
                            check=self.name,
                            title=f"Batafsil {tech} xato xabari oshkor bo'lgan",
                            severity=Severity.MEDIUM,
                            url=url,
                            description=f"Sahifada ishlab chiqish (debug) rejimidagi {tech} "
                            "xato/stack-trace ko'rinib turibdi. Bu ichki fayl yo'llari, "
                            "kod tuzilishi va boshqa maxfiy ma'lumotlarni oshkor qiladi.",
                            remediation="Production muhitida batafsil xatolarni o'chiring; "
                            "foydalanuvchiga faqat umumiy xato sahifasini ko'rsating.",
                            cwe="CWE-209",
                            evidence=snippet,
                        )
                    )
        return findings
