"""TLS/HTTPS tekshiruvi — HTTPS ishlatilishi va HTTP->HTTPS yo'naltirish."""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from ..models import Finding, Severity
from . import Check, Context


class TlsCheck(Check):
    name = "Transport xavfsizligi (TLS)"
    description = "HTTPS ishlatilishini va HTTP->HTTPS yo'naltirishni tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(ctx.target)

        if parsed.scheme != "https":
            findings.append(
                Finding(
                    check=self.name,
                    title="Sayt HTTPS ishlatmaydi",
                    severity=Severity.HIGH,
                    url=ctx.target,
                    description="Sayt shifrlanmagan HTTP orqali ishlamoqda. Barcha "
                    "ma'lumot (parollar, sessiya cookie'lari) ochiq matn ko'rinishida "
                    "uzatiladi va o'rtadagi hujum (MITM) orqali o'g'irlanishi mumkin.",
                    remediation="TLS sertifikat o'rnatib, saytni HTTPS'ga o'tkazing "
                    "va barcha HTTP so'rovlarini HTTPS'ga yo'naltiring.",
                    cwe="CWE-319",
                )
            )
            return findings

        # HTTP versiyasi HTTPS'ga yo'naltiriladimi?
        http_url = urlunparse(("http",) + parsed[1:])
        resp = ctx.client.get(http_url, allow_redirects=False)
        if resp.ok:
            location = resp.headers.get("Location", "")
            if not (300 <= resp.status < 400 and location.startswith("https")):
                findings.append(
                    Finding(
                        check=self.name,
                        title="HTTP HTTPS'ga yo'naltirilmaydi",
                        severity=Severity.MEDIUM,
                        url=http_url,
                        description="Saytning HTTP versiyasi avtomatik ravishda HTTPS'ga "
                        "yo'naltirilmayapti. Foydalanuvchilar shifrlanmagan aloqadan "
                        "foydalanishi mumkin.",
                        remediation="Barcha HTTP so'rovlarini 301 kodi bilan HTTPS'ga "
                        "yo'naltiring va HSTS sarlavhasini yoqing.",
                        cwe="CWE-319",
                        evidence=f"HTTP javob kodi: {resp.status}, Location: {location or 'yo‘q'}",
                    )
                )
        return findings
