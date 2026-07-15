#!/usr/bin/env python3
"""Nasiya skaneri — mahalliy (local) veb-interfeys.

Bu dastur SIZNING kompyuteringizda ishlaydi. Ishga tushirsangiz, brauzeringizda
oddiy sahifa ochiladi: sayt manzilini yozib "Skanerlash" tugmasini bosasiz,
natija (zaifliklar hisoboti) shu yerda chiqadi. Hech qanday internet-hosting,
pul yoki ro'yxatdan o'tish kerak emas.

Ishga tushirish:
    python3 webapp.py
    (brauzer avtomatik ochiladi: http://127.0.0.1:8777)

DIQQAT: faqat o'zingizga tegishli yoki ruxsat etilgan saytlarni tekshiring.
"""

from __future__ import annotations

import html
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from scanner import __version__
from scanner.engine import Scanner
from scanner.http_client import HttpClient
from scanner.reporter import to_html

# Hosting muhitida (Render, Hugging Face ...) PORT o'zgaruvchisi beriladi.
# U bo'lsa — hamma manzildan (0.0.0.0) tinglaymiz; bo'lmasa — faqat mahalliy.
_ENV_PORT = os.environ.get("PORT")
HOSTED = bool(_ENV_PORT)
HOST = "0.0.0.0" if HOSTED else "127.0.0.1"
PORT = int(_ENV_PORT) if _ENV_PORT else 8777

# Ixtiyoriy kirish kodi (maxfiylik uchun). Render'da ACCESS_KEY o'zgaruvchisini
# o'rnatsangiz, faqat shu kodni bilgan odam skanerdan foydalana oladi.
ACCESS_KEY = os.environ.get("ACCESS_KEY", "").strip()

PAGE = """<!doctype html>
<html lang="uz"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nasiya Skaner — Mahalliy interfeys</title>
<style>
  body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0b1220;color:#e5e7eb}}
  .wrap{{max-width:720px;margin:0 auto;padding:40px 20px}}
  h1{{font-size:22px;margin:0 0 4px}}
  .muted{{color:#9ca3af;font-size:13px;margin-bottom:28px}}
  form{{background:#111827;border:1px solid #1f2937;border-radius:14px;padding:24px}}
  label{{display:block;font-size:13px;color:#9ca3af;margin:14px 0 6px}}
  input[type=text],input[type=number]{{width:100%;box-sizing:border-box;background:#0b1220;
    border:1px solid #374151;border-radius:9px;padding:12px 14px;color:#e5e7eb;font-size:15px}}
  .row{{display:flex;gap:18px;flex-wrap:wrap;margin-top:6px}}
  .chk{{display:flex;align-items:center;gap:8px;font-size:14px;color:#d1d5db}}
  .chk input{{width:18px;height:18px}}
  button{{margin-top:22px;width:100%;background:#22c55e;color:#052e12;border:0;border-radius:10px;
    padding:14px;font-size:16px;font-weight:700;cursor:pointer}}
  button:hover{{background:#16a34a}}
  .warn{{background:#7c2d12;color:#fed7aa;border-radius:9px;padding:12px 14px;font-size:13px;margin-top:18px}}
  .foot{{text-align:center;color:#6b7280;font-size:12px;margin-top:24px}}
  #load{{display:none;text-align:center;margin-top:22px;color:#9ca3af}}
  .spin{{display:inline-block;width:22px;height:22px;border:3px solid #374151;border-top-color:#22c55e;
    border-radius:50%;animation:sp 0.8s linear infinite;vertical-align:middle;margin-right:8px}}
  @keyframes sp{{to{{transform:rotate(360deg)}}}}
</style></head><body>
<div class="wrap">
  <h1>🛡️ Nasiya Web Zaiflik Skaneri</h1>
  <div class="muted">Mahalliy interfeys • v{ver} • dastur sizning kompyuteringizda ishlaydi</div>
  <form method="post" action="/scan" onsubmit="document.getElementById('load').style.display='block';this.querySelector('button').disabled=true;">
    <label>Sayt manzili (URL)</label>
    <input type="text" name="target" placeholder="https://saytim.uz" required autofocus>
    {access_field}
    <div class="row">
      <label class="chk"><input type="checkbox" name="passive"> Passiv rejim (payloadsiz, xavfsizroq)</label>
      <label class="chk"><input type="checkbox" name="creds"> Standart parollarni sinash</label>
    </div>

    <label>Maksimal sahifa soni</label>
    <input type="number" name="max_pages" value="40" min="1" max="200">

    <div class="warn">⚠️ Faqat O'ZINGIZGA tegishli yoki tekshirishga ruxsatingiz bor
      saytlarni skanerlang.</div>
    <label class="chk" style="margin-top:14px"><input type="checkbox" name="authorized" required>
      Men bu saytni tekshirishga ruxsatim borligini tasdiqlayman</label>

    <button type="submit">Skanerlash</button>
    <div id="load"><span class="spin"></span>Skanerlanmoqda... (bir necha daqiqa olishi mumkin)</div>
  </form>
  <div class="foot">Faqat ruxsat etilgan xavfsizlik tekshiruvi uchun.</div>
</div>
</body></html>"""


def _render_page() -> str:
    access_field = ""
    if ACCESS_KEY:
        access_field = (
            '<label>Kirish kodi</label>'
            '<input type="password" name="access_key" placeholder="Maxfiy kod" required>'
        )
    return PAGE.format(ver=__version__, access_field=access_field)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _html(self, body: str, code: int = 200):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._html(_render_page())
        else:
            self._html("<h1>404</h1>", 404)

    def do_POST(self):
        if self.path != "/scan":
            self._html("<h1>404</h1>", 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        target = (form.get("target", [""])[0] or "").strip()
        if not target:
            self._html(_render_page())
            return

        # kirish kodi (agar o'rnatilgan bo'lsa)
        if ACCESS_KEY and form.get("access_key", [""])[0] != ACCESS_KEY:
            self._html(
                "<div style='font-family:system-ui;padding:40px'>"
                "<h2>Kirish kodi noto'g'ri</h2><a href='/'>← Orqaga</a></div>", 403
            )
            return

        # ruxsat tasdig'i majburiy
        if "authorized" not in form:
            self._html(
                "<div style='font-family:system-ui;padding:40px'>"
                "<h2>Ruxsat tasdiqlanmadi</h2><p>Skanerlash uchun ruxsat belgisini "
                "belgilashingiz kerak.</p><a href='/'>← Orqaga</a></div>", 400
            )
            return

        passive = "passive" in form
        creds = "creds" in form
        try:
            max_pages = max(1, min(200, int(form.get("max_pages", ["40"])[0])))
        except ValueError:
            max_pages = 40

        client = HttpClient(delay=0.3, verify_tls=True)
        scanner = Scanner(
            client=client,
            max_pages=max_pages,
            active=not passive,
            check_default_creds=creds,
        )
        try:
            result = scanner.scan(target)
            report = to_html(result)
            # hisobotga "orqaga" tugmasini qo'shamiz
            back = ('<div style="position:fixed;top:14px;left:14px;z-index:99">'
                    '<a href="/" style="background:#111827;color:#fff;padding:10px 16px;'
                    'border-radius:8px;text-decoration:none;font-family:system-ui">← Yangi skan</a></div>')
            report = report.replace("<body>", "<body>" + back, 1)
            self._html(report)
        except Exception as exc:  # skan yiqilsa, xatoni ko'rsatamiz
            self._html(
                f"<div style='font-family:system-ui;padding:40px'>"
                f"<h2>Skanerlashda xato</h2><p>{html.escape(str(exc))}</p>"
                f"<a href='/'>← Orqaga</a></div>", 500
            )


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    if HOSTED:
        # internet-hostingda ishlayapti — brauzer ochmaymiz
        print(f"Nasiya Skaner hosting rejimida ishga tushdi (port {PORT}).")
        if ACCESS_KEY:
            print("Kirish kodi (ACCESS_KEY) yoqilgan.")
    else:
        url = f"http://127.0.0.1:{PORT}"
        print("=" * 56)
        print("  Nasiya Skaner — mahalliy interfeys ishga tushdi")
        print(f"  Brauzerda oching:  {url}")
        print("  To'xtatish uchun:  Ctrl+C")
        print("=" * 56)
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nTo'xtatildi.")
        server.shutdown()


if __name__ == "__main__":
    main()
