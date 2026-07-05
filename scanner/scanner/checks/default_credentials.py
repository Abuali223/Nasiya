"""Standart/zaif parollar — login formalarda keng tarqalgan hisob ma'lumotlari.

DIQQAT: Bu tekshiruv login formaga bir necha marta so'rov yuboradi. Ba'zi
tizimlar bir necha xato urinishdan so'ng hisobni bloklashi mumkin. Shu sababli
u standart holatda O'CHIQ va faqat `check_default_creds=True` bo'lganda ishlaydi
(CLI'da `--check-default-creds` bayrog'i).
"""

from __future__ import annotations

import re

from ..crawler import Form
from ..models import Finding, Severity
from . import Check, Context

# keng tarqalgan (juda kichik) ro'yxat — hisob bloklanishini kamaytirish uchun
CRED_PAIRS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("root", "root"),
]

PASSWORD_INPUT = re.compile(r"type=[\"']password[\"']", re.I)
USER_HINT = re.compile(r"(user|login|email|name|phone|tel)", re.I)


class DefaultCredentialsCheck(Check):
    name = "Standart parollar"
    description = "Login formalarda keng tarqalgan standart parollarni sinaydi (opt-in)."

    def _login_forms(self, ctx: Context) -> list[Form]:
        out = []
        for form in ctx.crawl.forms:
            if form.method != "post":
                continue
            if any(f.type == "password" for f in form.fields):
                out.append(form)
        return out

    def _field_names(self, form: Form):
        user_field = pass_field = None
        for f in form.fields:
            if f.type == "password" and pass_field is None:
                pass_field = f.name
            elif f.type in ("text", "email", "tel") and USER_HINT.search(f.name or ""):
                user_field = user_field or f.name
        # foydalanuvchi maydoni topilmasa, birinchi parolsiz maydonni olamiz
        if user_field is None:
            for f in form.fields:
                if f.type in ("text", "email", "tel") and f.name:
                    user_field = f.name
                    break
        return user_field, pass_field

    def _submit(self, ctx: Context, form: Form, user_field, pass_field, user, pw):
        data = {f.name: f.value for f in form.fields if f.name}
        if user_field:
            data[user_field] = user
        data[pass_field] = pw
        return ctx.client.post(form.action, data=data)

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.active or not ctx.check_default_creds:
            return []
        findings: list[Finding] = []

        for form in self._login_forms(ctx):
            user_field, pass_field = self._field_names(form)
            if not pass_field:
                continue

            # 1) Ataylab noto'g'ri parol — "muvaffaqiyatsizlik" mezoni
            bad = self._submit(
                ctx, form, user_field, pass_field,
                "nsq_invalid_user", "nsq_invalid_pw_9182",
            )
            if not bad.ok:
                continue
            bad_has_pw = bool(PASSWORD_INPUT.search(bad.text))
            bad_len = len(bad.text)

            for user, pw in CRED_PAIRS:
                resp = self._submit(ctx, form, user_field, pass_field, user, pw)
                if not resp.ok:
                    continue
                still_login = bool(PASSWORD_INPUT.search(resp.text))
                # muvaffaqiyat belgilari: login formasi yo'qoldi, yoki javob
                # noto'g'ri urinishdan sezilarli farq qiladi
                success = (
                    (bad_has_pw and not still_login)
                    or (resp.status in (301, 302) and bad.status not in (301, 302))
                    or (abs(len(resp.text) - bad_len) > max(200, bad_len * 0.3) and not still_login)
                )
                if success:
                    findings.append(
                        Finding(
                            check=self.name,
                            title=f"Standart parol ishladi: {user}/{pw}",
                            severity=Severity.CRITICAL,
                            url=form.action,
                            param=user_field or pass_field,
                            description=f"Login formasi standart hisob ma'lumotlari "
                            f"('{user}' / '{pw}') bilan muvaffaqiyatli o'tdi. Hujumchi shu "
                            "orqali bevosita tizimga (ehtimol adminlikka) kirishi mumkin.",
                            remediation="Barcha standart parollarni darhol kuchli, noyob "
                            "parollarga o'zgartiring; login urinishlarini cheklang va 2FA yoqing.",
                            cwe="CWE-1392",
                            evidence=f"Hisob: {user}/{pw}, javob kodi {resp.status}",
                        )
                    )
                    break  # bitta forma uchun bittasi yetarli
        return findings
