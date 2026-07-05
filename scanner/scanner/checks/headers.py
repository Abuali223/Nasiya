"""Xavfsizlik sarlavhalari (security headers) tekshiruvi."""

from __future__ import annotations

from ..models import Finding, Severity
from . import Check, Context

# sarlavha -> (jiddiylik, tavsif, tavsiya, cwe)
REQUIRED_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Content-Security-Policy (CSP) sarlavhasi yo'q. Bu XSS va ma'lumot "
        "yuklash hujumlariga qarshi asosiy himoya qatlamining yo'qligini bildiradi.",
        "Kamida `default-src 'self'` bilan boshlanadigan CSP siyosatini qo'shing.",
        "CWE-693",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "Strict-Transport-Security (HSTS) yo'q. Foydalanuvchilar HTTPS o'rniga "
        "HTTP orqali ulanishga majburlanishi (downgrade) mumkin.",
        "`Strict-Transport-Security: max-age=31536000; includeSubDomains` qo'shing "
        "(faqat HTTPS saytlar uchun).",
        "CWE-319",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options yo'q. Brauzer MIME-turini taxmin qilib (sniffing) "
        "xavfli xatti-harakat qilishi mumkin.",
        "`X-Content-Type-Options: nosniff` qo'shing.",
        "CWE-693",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Referrer-Policy yo'q. Maxfiy URL parametrlari boshqa saytlarga "
        "sizib chiqishi mumkin.",
        "`Referrer-Policy: no-referrer-when-downgrade` yoki `strict-origin` qo'shing.",
        "CWE-200",
    ),
    "permissions-policy": (
        Severity.INFO,
        "Permissions-Policy yo'q. Kamera, mikrofon, geolokatsiya kabi brauzer "
        "imkoniyatlari cheklanmagan.",
        "Kerakli imkoniyatlarni cheklovchi Permissions-Policy qo'shing.",
        "CWE-693",
    ),
}


class SecurityHeadersCheck(Check):
    name = "Xavfsizlik sarlavhalari"
    description = "Muhim HTTP xavfsizlik sarlavhalari mavjudligini tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        resp = ctx.home
        if not resp.ok:
            return findings

        present = {k.lower() for k in resp.headers}
        for header, (sev, desc, fix, cwe) in REQUIRED_HEADERS.items():
            if header not in present:
                findings.append(
                    Finding(
                        check=self.name,
                        title=f"'{header}' sarlavhasi yo'q",
                        severity=sev,
                        url=resp.url,
                        description=desc,
                        remediation=fix,
                        cwe=cwe,
                        evidence=f"Javob sarlavhalarida '{header}' topilmadi.",
                    )
                )
        return findings
