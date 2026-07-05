"""CSRF — o'zgartiruvchi formalarda anti-CSRF token yo'qligini tekshiradi."""

from __future__ import annotations

import re

from ..models import Finding, Severity
from . import Check, Context

# token nomiga o'xshash maydonlar
TOKEN_HINT = re.compile(
    r"(csrf|xsrf|token|nonce|authenticity|_token|__requestverification)", re.I
)


class CsrfCheck(Check):
    name = "CSRF himoyasi"
    description = "POST formalarida anti-CSRF token mavjudligini tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for form in ctx.crawl.forms:
            if form.method != "post":
                continue
            key = form.action + "|" + ",".join(sorted(form.input_names()))
            if key in seen:
                continue
            seen.add(key)

            has_token = any(TOKEN_HINT.search(name) for name in form.input_names())
            # login formalari ba'zan tokensiz bo'ladi, lekin baribir ogohlantiramiz
            if not has_token:
                findings.append(
                    Finding(
                        check=self.name,
                        title="POST formasida CSRF token yo'q",
                        severity=Severity.MEDIUM,
                        url=form.source_url,
                        param=form.action,
                        description="Ma'lumot o'zgartiruvchi POST formasida yashirin "
                        "anti-CSRF token topilmadi. Hujumchi foydalanuvchi nomidan "
                        "so'rovni majburlashi (Cross-Site Request Forgery) mumkin.",
                        remediation="Har bir o'zgartiruvchi formaga noyob, tekshiriladigan "
                        "CSRF tokenini qo'shing va SameSite cookie'lardan foydalaning.",
                        cwe="CWE-352",
                        evidence=f"Forma amali: {form.action}, maydonlar: {form.input_names()}",
                    )
                )
        return findings
