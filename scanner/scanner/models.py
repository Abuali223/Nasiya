"""Topilma (finding) va jiddiylik (severity) modellari."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Zaiflik jiddiylik darajalari (yuqoridan pastga)."""

    CRITICAL = "Kritik"
    HIGH = "Yuqori"
    MEDIUM = "O'rta"
    LOW = "Past"
    INFO = "Ma'lumot"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return order[self]

    @property
    def color(self) -> str:
        """ANSI rang kodi (terminal uchun)."""
        return {
            Severity.CRITICAL: "\033[95m",  # magenta
            Severity.HIGH: "\033[91m",       # red
            Severity.MEDIUM: "\033[93m",     # yellow
            Severity.LOW: "\033[94m",        # blue
            Severity.INFO: "\033[90m",       # grey
        }[self]


@dataclass
class Finding:
    """Bitta aniqlangan zaiflik yoki muammo."""

    check: str                     # tekshiruv nomi (masalan "SQL Injection")
    title: str                     # qisqa sarlavha
    severity: Severity
    url: str                       # muammo topilgan manzil
    description: str               # muammoning tavsifi
    remediation: str               # tuzatish bo'yicha tavsiya
    param: str = ""                # zaif parametr (agar bo'lsa)
    evidence: str = ""             # dalil (javob parchasi, payload va h.k.)
    cwe: str = ""                  # CWE identifikatori (masalan "CWE-89")

    def key(self) -> tuple:
        """Dublikatlarni yo'qotish uchun noyob kalit."""
        return (self.check, self.url, self.param, self.title)


@dataclass
class ScanResult:
    """Skanerlash yakuniy natijasi."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    pages_crawled: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        # dublikatlarni tashlab yuboramiz
        if any(f.key() == finding.key() for f in self.findings):
            return
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.check, f.url))

    def counts(self) -> dict[Severity, int]:
        out: dict[Severity, int] = {s: 0 for s in Severity}
        for f in self.findings:
            out[f.severity] += 1
        return out
