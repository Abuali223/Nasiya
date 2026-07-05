"""Clickjacking (freym ichiga joylash) tekshiruvi."""

from __future__ import annotations

from ..models import Finding, Severity
from . import Check, Context


class ClickjackingCheck(Check):
    name = "Clickjacking"
    description = "Sahifani boshqa saytga freym qilib joylash mumkinligini tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        resp = ctx.home
        if not resp.ok:
            return []

        headers = {k.lower(): v for k, v in resp.headers.items()}
        xfo = headers.get("x-frame-options", "").lower()
        csp = headers.get("content-security-policy", "").lower()

        protected = bool(xfo) or "frame-ancestors" in csp
        if protected:
            return []

        return [
            Finding(
                check=self.name,
                title="Clickjacking himoyasi yo'q",
                severity=Severity.MEDIUM,
                url=resp.url,
                description="Sahifada X-Frame-Options ham, CSP frame-ancestors ham yo'q. "
                "Hujumchi saytingizni yashirin <iframe> ichiga joylab, foydalanuvchini "
                "ular ko'rmayotgan tugmalarni bosishga aldashi (clickjacking) mumkin.",
                remediation="`X-Frame-Options: DENY` (yoki SAMEORIGIN), yoki CSP'da "
                "`frame-ancestors 'self'` qo'shing.",
                cwe="CWE-1021",
            )
        ]
