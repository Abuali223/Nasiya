"""SQL Injection tekshiruvi (xato asosidagi va mantiqiy/boolean).

Bu — adminlikni egallashga olib keladigan eng jiddiy zaifliklardan biri, shu
sababli topilsa CRITICAL jiddiylik beriladi.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity
from . import Check, Context
from ._injection import collect_points

# Turli DBMS xatolarining imzolari
SQL_ERRORS = [
    ("MySQL", re.compile(r"SQL syntax.*?MySQL|Warning.*?mysqli?_|MySqlException|valid MySQL result", re.I)),
    ("MariaDB", re.compile(r"check the manual that corresponds to your (?:MySQL|MariaDB)", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL.*?ERROR|pg_query\(\)|PSQLException|unterminated quoted string", re.I)),
    ("MS SQL", re.compile(r"Microsoft SQL Server|ODBC SQL Server Driver|SQLServerException|Unclosed quotation mark", re.I)),
    ("Oracle", re.compile(r"ORA-\d{5}|Oracle error|quoted string not properly terminated", re.I)),
    ("SQLite", re.compile(r"SQLite/JDBCDriver|SQLite\.Exception|sqlite3\.OperationalError|unrecognized token", re.I)),
    ("Generic", re.compile(r"SQLSTATE\[|syntax error at or near|Dynamic SQL Error", re.I)),
]

# xato chiqarish uchun payloadlar
ERROR_PAYLOADS = ["'", '"', "')", "';", "\\", "' OR '1"]

# mantiqiy (boolean) test juftliklari: (rost, yolg'on)
BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' AND '1'='1", "' AND '1'='2"),
    (" OR 1=1-- -", " OR 1=2-- -"),
]


def _similar(a: str, b: str) -> float:
    """Ikki javob uzunligiga asoslangan qo'pol o'xshashlik koeffitsienti."""
    la, lb = len(a), len(b)
    if la == 0 and lb == 0:
        return 1.0
    return 1 - abs(la - lb) / max(la, lb, 1)


class SqlInjectionCheck(Check):
    name = "SQL Injection"
    description = "Parametrlar orqali SQL so'roviga aralashish mumkinligini tekshiradi."

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.active:
            return []
        findings: list[Finding] = []
        points = collect_points(ctx.crawl)
        reported: set[tuple] = set()

        for point in points:
            key = (point.method, point.url, point.param)
            if key in reported:
                continue

            # --- 1) Xato asosidagi test ---
            found = False
            for payload in ERROR_PAYLOADS:
                resp = point.send(ctx.client, payload)
                if not resp.ok:
                    continue
                for dbms, pattern in SQL_ERRORS:
                    if pattern.search(resp.text):
                        m = pattern.search(resp.text)
                        findings.append(
                            Finding(
                                check=self.name,
                                title=f"SQL Injection ({dbms}) — '{point.param}' parametri",
                                severity=Severity.CRITICAL,
                                url=point.url,
                                param=point.param,
                                description=f"'{point.param}' parametriga maxsus belgi "
                                f"yuborilganda {dbms} ma'lumotlar bazasi xatosi qaytdi. Bu "
                                "so'zma-so'z SQL inyeksiyasi mavjudligini bildiradi — hujumchi "
                                "ma'lumotlar bazasini o'qishi, o'zgartirishi yoki admin sifatida "
                                "kirishi mumkin.",
                                remediation="Parametrlashtirilgan so'rovlar (prepared statements) "
                                "va ORM ishlating; foydalanuvchi kiritmasini hech qachon SQL "
                                "matniga to'g'ridan-to'g'ri qo'shmang.",
                                cwe="CWE-89",
                                evidence=f"Payload: {payload!r} -> {m.group(0)[:160]}",
                            )
                        )
                        found = True
                        break
                if found:
                    break

            if found:
                reported.add(key)
                continue

            # --- 2) Mantiqiy (boolean) test ---
            for true_p, false_p in BOOLEAN_PAIRS:
                r_true = point.send(ctx.client, true_p)
                r_false = point.send(ctx.client, false_p)
                if not (r_true.ok and r_false.ok):
                    continue
                # rost va yolg'on javoblari sezilarli farq qilsa — shubhali
                sim = _similar(r_true.text, r_false.text)
                same_status = r_true.status == r_false.status
                if same_status and sim < 0.95 and abs(len(r_true.text) - len(r_false.text)) > 40:
                    findings.append(
                        Finding(
                            check=self.name,
                            title=f"Ehtimoliy (boolean) SQL Injection — '{point.param}'",
                            severity=Severity.HIGH,
                            url=point.url,
                            param=point.param,
                            description=f"'{point.param}' parametriga mantiqan rost va yolg'on "
                            "shartlar yuborilganda javob sezilarli darajada o'zgardi. Bu "
                            "ko'r (blind) SQL inyeksiyasi belgisi bo'lishi mumkin — qo'lda "
                            "tasdiqlash tavsiya etiladi.",
                            remediation="Parametrlashtirilgan so'rovlardan foydalaning va "
                            "kiruvchi ma'lumotlarni qat'iy tekshiring.",
                            cwe="CWE-89",
                            evidence=f"rost='{true_p}' ({len(r_true.text)} b), "
                            f"yolg'on='{false_p}' ({len(r_false.text)} b), o'xshashlik≈{sim:.2f}",
                        )
                    )
                    reported.add(key)
                    break
        return findings
