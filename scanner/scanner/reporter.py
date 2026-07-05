"""Natijalarni chiqarish: konsol, JSON va HTML hisobot."""

from __future__ import annotations

import html
import json

from .models import ScanResult, Severity

RESET = "\033[0m"
BOLD = "\033[1m"


def _supports_color(stream) -> bool:
    try:
        return stream.isatty()
    except Exception:
        return False


def print_console(result: ScanResult, stream, use_color: bool | None = None) -> None:
    if use_color is None:
        use_color = _supports_color(stream)

    def c(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if use_color else text

    w = stream.write
    counts = result.counts()
    w("\n" + "=" * 64 + "\n")
    w(c(f" NASIYA SKANER — HISOBOT: {result.target}\n", BOLD))
    w("=" * 64 + "\n")
    w(f"Tekshirilgan sahifalar: {len(result.pages_crawled)}\n")
    w(f"Boshlandi: {result.started_at}   Tugadi: {result.finished_at}\n")
    if result.errors:
        w(c(f"Ogohlantirishlar: {len(result.errors)}\n", Severity.LOW.color))

    w("\nJiddiylik bo'yicha:\n")
    for sev in Severity:
        n = counts[sev]
        line = f"  {sev.value:<10} : {n}\n"
        w(c(line, sev.color) if n and use_color else line)

    findings = result.sorted_findings()
    if not findings:
        w(c("\n✔ Hech qanday zaiflik topilmadi (yoki sayt javob bermadi).\n", "\033[92m"))
        w("=" * 64 + "\n")
        return

    w("\n" + "-" * 64 + "\n")
    for i, f in enumerate(findings, 1):
        head = f"[{i}] [{f.severity.value}] {f.title}"
        w(c(head + "\n", f.severity.color + BOLD) if use_color else head + "\n")
        w(f"    Tekshiruv : {f.check}\n")
        w(f"    Manzil    : {f.url}\n")
        if f.param:
            w(f"    Parametr  : {f.param}\n")
        if f.cwe:
            w(f"    CWE       : {f.cwe}\n")
        w(f"    Tavsif    : {f.description}\n")
        if f.evidence:
            w(f"    Dalil     : {f.evidence}\n")
        w(f"    Yechim    : {f.remediation}\n")
        w("-" * 64 + "\n")
    w("\n")


def to_json(result: ScanResult) -> str:
    data = {
        "target": result.target,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "pages_crawled": result.pages_crawled,
        "summary": {s.value: result.counts()[s] for s in Severity},
        "errors": result.errors,
        "findings": [
            {
                "check": f.check,
                "title": f.title,
                "severity": f.severity.value,
                "url": f.url,
                "param": f.param,
                "cwe": f.cwe,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in result.sorted_findings()
        ],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


_SEV_HTML = {
    Severity.CRITICAL: "#7c3aed",
    Severity.HIGH: "#dc2626",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}


def to_html(result: ScanResult) -> str:
    e = html.escape
    counts = result.counts()
    rows = []
    for i, f in enumerate(result.sorted_findings(), 1):
        color = _SEV_HTML[f.severity]
        rows.append(f"""
        <div class="finding">
          <div class="fhead" style="border-left:6px solid {color}">
            <span class="badge" style="background:{color}">{e(f.severity.value)}</span>
            <span class="ftitle">{i}. {e(f.title)}</span>
          </div>
          <table class="meta">
            <tr><th>Tekshiruv</th><td>{e(f.check)}</td></tr>
            <tr><th>Manzil</th><td><code>{e(f.url)}</code></td></tr>
            {f'<tr><th>Parametr</th><td><code>{e(f.param)}</code></td></tr>' if f.param else ''}
            {f'<tr><th>CWE</th><td>{e(f.cwe)}</td></tr>' if f.cwe else ''}
            <tr><th>Tavsif</th><td>{e(f.description)}</td></tr>
            {f'<tr><th>Dalil</th><td><code>{e(f.evidence)}</code></td></tr>' if f.evidence else ''}
            <tr><th>Yechim</th><td>{e(f.remediation)}</td></tr>
          </table>
        </div>""")

    summary_cells = "".join(
        f'<div class="scard" style="border-top:4px solid {_SEV_HTML[s]}">'
        f'<div class="snum">{counts[s]}</div><div class="slbl">{e(s.value)}</div></div>'
        for s in Severity
    )

    return f"""<!doctype html>
<html lang="uz"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nasiya Skaner hisoboti — {e(result.target)}</title>
<style>
  body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#f3f4f6;color:#111827}}
  header{{background:#111827;color:#fff;padding:24px 32px}}
  header h1{{margin:0 0 4px;font-size:20px}}
  header .muted{{color:#9ca3af;font-size:13px}}
  .wrap{{max-width:960px;margin:0 auto;padding:24px 16px}}
  .summary{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
  .scard{{background:#fff;border-radius:10px;padding:16px 20px;min-width:110px;text-align:center;box-shadow:0 1px 2px rgba(0,0,0,.06)}}
  .snum{{font-size:28px;font-weight:700}}
  .slbl{{font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.04em}}
  .finding{{background:#fff;border-radius:10px;margin-bottom:16px;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.06)}}
  .fhead{{padding:14px 18px;display:flex;align-items:center;gap:12px}}
  .badge{{color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:999px;text-transform:uppercase}}
  .ftitle{{font-weight:600}}
  table.meta{{width:100%;border-collapse:collapse}}
  table.meta th{{text-align:left;width:120px;vertical-align:top;padding:8px 18px;color:#6b7280;font-weight:600;font-size:13px}}
  table.meta td{{padding:8px 18px;font-size:14px}}
  code{{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:12px;word-break:break-all}}
  .ok{{background:#fff;padding:24px;border-radius:10px;text-align:center;color:#059669;font-weight:600}}
  footer{{text-align:center;color:#9ca3af;font-size:12px;padding:24px}}
</style></head><body>
<header>
  <h1>🛡️ Nasiya Web Zaiflik Skaneri — Hisobot</h1>
  <div class="muted">Nishon: {e(result.target)} &nbsp;•&nbsp; {e(result.started_at)} → {e(result.finished_at)} &nbsp;•&nbsp; {len(result.pages_crawled)} sahifa</div>
</header>
<div class="wrap">
  <div class="summary">{summary_cells}</div>
  {''.join(rows) if rows else '<div class="ok">✔ Hech qanday zaiflik topilmadi.</div>'}
</div>
<footer>Nasiya Scanner v1.0 — faqat ruxsat etilgan xavfsizlik tekshiruvi uchun.</footer>
</body></html>"""
