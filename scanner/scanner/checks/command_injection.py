"""OS Command Injection — parametr orqali server buyruqlarini bajarish."""

from __future__ import annotations

import re
import time

from ..models import Finding, Severity
from . import Check, Context
from ._injection import collect_points

# `id` / `ver` buyruqlari chiqishini keltiruvchi payloadlar
OUTPUT_PAYLOADS = [
    ";id",
    "|id",
    "`id`",
    "$(id)",
    "& whoami",
    "; echo NSQ-$((13*13))-END",   # arifmetik: NSQ-169-END
]

OUTPUT_SIGNATURES = [
    ("Unix id", re.compile(r"uid=\d+\(?\w*\)?\s+gid=\d+")),
    ("echo eval", re.compile(r"NSQ-169-END")),
    ("Windows", re.compile(r"Windows \[Version|Microsoft Windows")),
]

# vaqt asosidagi (blind) payloadlar
TIME_PAYLOADS = ["; sleep 6", "| sleep 6", "& ping -n 6 127.0.0.1", "`sleep 6`"]


class CommandInjectionCheck(Check):
    name = "Command Injection"
    description = "Parametr orqali operatsion tizim buyruqlarini bajarish mumkinligini tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.active:
            return []
        findings: list[Finding] = []
        reported: set[tuple] = set()

        for point in collect_points(ctx.crawl):
            key = (point.method, point.url, point.param)
            if key in reported:
                continue

            # 1) Chiqish asosidagi
            hit = False
            for payload in OUTPUT_PAYLOADS:
                resp = point.send(ctx.client, payload)
                if not resp.ok or not resp.text:
                    continue
                for label, pattern in OUTPUT_SIGNATURES:
                    m = pattern.search(resp.text)
                    if m:
                        findings.append(
                            Finding(
                                check=self.name,
                                title=f"Command Injection — '{point.param}' parametri",
                                severity=Severity.CRITICAL,
                                url=point.url,
                                param=point.param,
                                description=f"'{point.param}' parametriga buyruq belgisi "
                                f"yuborilganda server buyruq chiqishi qaytdi ({label}). "
                                "Hujumchi serverda ixtiyoriy buyruq bajarib, to'liq nazoratni "
                                "egallashi mumkin.",
                                remediation="Foydalanuvchi kiritmasini shell buyruqlariga "
                                "qo'shmang; xavfsiz API'lar (masalan argument ro'yxati bilan "
                                "`subprocess`, `shell=False`) ishlating.",
                                cwe="CWE-78",
                                evidence=f"Payload: {payload!r} -> {m.group(0)[:80]}",
                            )
                        )
                        reported.add(key)
                        hit = True
                        break
                if hit:
                    break
            if hit:
                continue

            # 2) Vaqt asosidagi (blind) — asosiy javob vaqtini o'lchaymiz
            base = point.send(ctx.client, "1")
            if not base.ok:
                continue
            baseline = base.elapsed
            for payload in TIME_PAYLOADS:
                t0 = time.monotonic()
                resp = point.send(ctx.client, payload)
                delay = time.monotonic() - t0
                if resp.ok and delay > baseline + 5 and delay >= 5.5:
                    findings.append(
                        Finding(
                            check=self.name,
                            title=f"Ehtimoliy (blind) Command Injection — '{point.param}'",
                            severity=Severity.HIGH,
                            url=point.url,
                            param=point.param,
                            description=f"'{point.param}' parametriga `sleep` buyrug'i "
                            "yuborilganda javob ~6 soniyaga kechikdi. Bu ko'r (blind) buyruq "
                            "inyeksiyasi belgisi — qo'lda tasdiqlash tavsiya etiladi.",
                            remediation="Kiruvchi ma'lumotni shell'ga uzatmang; "
                            "parametrlarni qat'iy tekshiring.",
                            cwe="CWE-78",
                            evidence=f"Payload: {payload!r}, kechikish={delay:.1f}s "
                            f"(asos={baseline:.1f}s)",
                        )
                    )
                    reported.add(key)
                    break
        return findings
