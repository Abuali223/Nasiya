"""Cookie bayroqlari (Secure, HttpOnly, SameSite) tekshiruvi."""

from __future__ import annotations

from urllib.parse import urlparse

from ..models import Finding, Severity
from . import Check, Context


class CookieCheck(Check):
    name = "Cookie xavfsizligi"
    description = "Set-Cookie bayroqlarini (Secure/HttpOnly/SameSite) tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        is_https = urlparse(ctx.target).scheme == "https"

        # barcha to'plangan sahifalardagi cookie'larni ko'rib chiqamiz
        seen: set[str] = set()
        for url, resp in list(ctx.crawl.pages.items()) + [(ctx.home.url, ctx.home)]:
            if not resp.ok or resp.cookies is None:
                continue
            for cookie in resp.cookies:
                if cookie.name in seen:
                    continue
                seen.add(cookie.name)

                # RequestsCookieJar bayroqlarni _rest ichida saqlaydi
                rest = {k.lower(): v for k, v in (cookie._rest or {}).items()}
                secure = cookie.secure
                httponly = "httponly" in rest
                samesite = rest.get("samesite", "")

                if is_https and not secure:
                    findings.append(
                        Finding(
                            check=self.name,
                            title=f"'{cookie.name}' cookie'sida Secure bayrog'i yo'q",
                            severity=Severity.MEDIUM,
                            url=url,
                            param=cookie.name,
                            description="Cookie HTTPS'da uzatilmoqda, lekin Secure "
                            "bayrog'i yo'q — u shifrlanmagan HTTP orqali sizib chiqishi mumkin.",
                            remediation="Set-Cookie'ga `Secure` bayrog'ini qo'shing.",
                            cwe="CWE-614",
                        )
                    )
                if not httponly:
                    findings.append(
                        Finding(
                            check=self.name,
                            title=f"'{cookie.name}' cookie'sida HttpOnly bayrog'i yo'q",
                            severity=Severity.MEDIUM,
                            url=url,
                            param=cookie.name,
                            description="HttpOnly bo'lmagan cookie'ni JavaScript o'qiy oladi. "
                            "XSS zaifligi bilan birgalikda sessiya o'g'irlashga olib keladi.",
                            remediation="Sessiya cookie'lariga `HttpOnly` bayrog'ini qo'shing.",
                            cwe="CWE-1004",
                        )
                    )
                if not samesite:
                    findings.append(
                        Finding(
                            check=self.name,
                            title=f"'{cookie.name}' cookie'sida SameSite atributi yo'q",
                            severity=Severity.LOW,
                            url=url,
                            param=cookie.name,
                            description="SameSite atributi yo'q cookie CSRF hujumlariga "
                            "ochiqroq bo'ladi.",
                            remediation="`SameSite=Lax` yoki `SameSite=Strict` qo'shing.",
                            cwe="CWE-352",
                        )
                    )
        return findings
