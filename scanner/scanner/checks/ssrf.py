"""SSRF — Server-Side Request Forgery (server nomidan ichki so'rov yuborish).

Ishonchli SSRF aniqlash odatda tashqi (out-of-band) collaborator serverini
talab qiladi. Bu tekshiruv yengil variantni bajaradi: URL qabul qiluvchi
parametrlarga bulut metama'lumot manzillarini yuborib, javobda ularning
belgilari qaytishini qidiradi. Aniq dalil bo'lmasa, nomzod sifatida belgilaydi.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity
from . import Check, Context
from ._injection import collect_points

# odatda URL qabul qiluvchi parametr nomlari
URL_PARAMS = {
    "url", "uri", "link", "src", "source", "target", "dest", "redirect",
    "next", "data", "path", "file", "load", "page", "domain", "host",
    "callback", "webhook", "feed", "image", "img", "fetch", "proxy",
}

# ichki/metama'lumot manzillari
PROBES = [
    ("http://169.254.169.254/latest/meta-data/", re.compile(
        r"ami-id|instance-id|iam/|placement/|security-credentials", re.I)),
    ("http://metadata.google.internal/computeMetadata/v1/", re.compile(
        r"computeMetadata|project-id|service-accounts", re.I)),
    ("http://127.0.0.1:22/", re.compile(r"SSH-\d\.\d|OpenSSH", re.I)),
]


class SsrfCheck(Check):
    name = "SSRF"
    description = "URL parametrlari orqali server ichki manzillarga so'rov yuborishini tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.active:
            return []
        findings: list[Finding] = []
        reported: set[tuple] = set()

        for point in collect_points(ctx.crawl):
            if point.param.lower() not in URL_PARAMS:
                continue
            key = (point.method, point.url, point.param)
            if key in reported:
                continue

            confirmed = False
            for probe, sig in PROBES:
                resp = point.send(ctx.client, probe)
                # imzo mos kelsa-yu, lekin probe URL javobda aynan qaytarilgan
                # bo'lsa — bu haqiqiy SSRF emas, shunchaki reflection (soxta tasdiq).
                if (
                    resp.ok and resp.text
                    and sig.search(resp.text)
                    and probe not in resp.text
                ):
                    findings.append(
                        Finding(
                            check=self.name,
                            title=f"SSRF tasdiqlandi — '{point.param}' parametri",
                            severity=Severity.HIGH,
                            url=point.url,
                            param=point.param,
                            description=f"'{point.param}' parametriga ichki manzil "
                            f"yuborilganda server o'sha manzilga so'rov yubordi va javob "
                            "qaytardi. Bu SSRF — hujumchi ichki tarmoq va bulut "
                            "metama'lumotlariga (masalan IAM kalitlariga) kirishi mumkin.",
                            remediation="Server yuboradigan URL'larni oq ro'yxat bilan "
                            "cheklang, ichki IP diapazonlarini (169.254/16, 127/8, 10/8 ...) "
                            "bloklang va yo'naltirishlarni cheklang.",
                            cwe="CWE-918",
                            evidence=f"Probe: {probe}",
                        )
                    )
                    reported.add(key)
                    confirmed = True
                    break

            if not confirmed:
                # nomzod — qo'lda tekshirish uchun (past shovqin)
                findings.append(
                    Finding(
                        check=self.name,
                        title=f"SSRF nomzodi — '{point.param}' parametri (qo'lda tekshiring)",
                        severity=Severity.INFO,
                        url=point.url,
                        param=point.param,
                        description=f"'{point.param}' parametri URL qabul qilayotganga "
                        "o'xshaydi. Avtomatik tasdiq bo'lmadi, lekin bu SSRF uchun potensial "
                        "nuqta. Tashqi collaborator (masalan Burp Collaborator) bilan qo'lda "
                        "tekshirish tavsiya etiladi.",
                        remediation="Server yuboradigan manzillarni oq ro'yxat bilan "
                        "cheklang va ichki IP diapazonlariga so'rovlarni bloklang.",
                        cwe="CWE-918",
                    )
                )
                reported.add(key)
        return findings
