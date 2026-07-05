"""Open Redirect — ochiq yo'naltirish zaifligi tekshiruvi."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

from ..models import Finding, Severity
from . import Check, Context

REDIRECT_PARAMS = {
    "url", "next", "redirect", "redirect_url", "redir", "return",
    "returnurl", "return_url", "goto", "dest", "destination", "continue",
    "target", "rurl", "u",
}

# tashqi manzil (bizning domenimizga tegishli emas)
EVIL = "https://example.org/nasiya-scanner-probe"


class OpenRedirectCheck(Check):
    name = "Ochiq yo'naltirish (Open Redirect)"
    description = "URL parametrlari orqali tashqi saytga yo'naltirish mumkinligini tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.active:
            return []
        findings: list[Finding] = []
        tested: set[str] = set()

        for url in ctx.crawl.links_with_params:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for param in qs:
                if param.lower() not in REDIRECT_PARAMS:
                    continue
                sig = f"{parsed.path}?{param}"
                if sig in tested:
                    continue
                tested.add(sig)

                new_qs = {k: v[0] for k, v in qs.items()}
                new_qs[param] = EVIL
                test_url = urlunparse(parsed._replace(query=urlencode(new_qs)))

                resp = ctx.client.get(test_url, allow_redirects=False)
                if not resp.ok:
                    continue
                location = resp.headers.get("Location", "")
                if 300 <= resp.status < 400 and location.startswith("https://example.org"):
                    findings.append(
                        Finding(
                            check=self.name,
                            title=f"'{param}' parametri ochiq yo'naltirishga imkon beradi",
                            severity=Severity.MEDIUM,
                            url=test_url,
                            param=param,
                            description="Sayt '{}' parametrining qiymatini tekshirmasdan "
                            "tashqi manzilga yo'naltirdi. Bu fishing va ishonchni "
                            "suiiste'mol qilish hujumlarida ishlatiladi.".format(param),
                            remediation="Yo'naltirish manzillarini oq ro'yxat (whitelist) "
                            "bilan tekshiring yoki faqat nisbiy (relative) yo'llarga ruxsat bering.",
                            cwe="CWE-601",
                            evidence=f"HTTP {resp.status} -> Location: {location}",
                        )
                    )
        return findings
