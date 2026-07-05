#!/usr/bin/env python3
"""Nasiya Web Zaiflik Skaneri — buyruq qatori interfeysi (CLI).

Foydalanish:
    # Bitta sayt
    python3 nasiya_scan.py https://saytim.uz

    # Bir nechta sayt (loyihalaringiz ko'p bo'lsa)
    python3 nasiya_scan.py https://sayt1.uz https://sayt2.uz https://sayt3.uz

    # Sayt ro'yxatini fayldan o'qish (har qatorda bitta manzil)
    python3 nasiya_scan.py --targets-file saytlar.txt --html hisobot.html

    # SPA (JavaScript) saytlar uchun brauzer bilan
    python3 nasiya_scan.py https://app.saytim.uz --render

DIQQAT — QONUNIY OGOHLANTIRISH:
    Bu vositani FAQAT o'zingizga tegishli yoki tekshirishga YOZMA RUXSATingiz bor
    saytlarda ishlating. Begona saytni ruxsatsiz skanerlash ko'p mamlakatlarda
    jinoiy javobgarlikka olib keladi.
"""

from __future__ import annotations

import argparse
import sys

from scanner import __version__
from scanner.engine import normalize_target, scan_many
from scanner.http_client import HttpClient
from scanner.models import Severity
from scanner.reporter import (
    print_console,
    print_console_multi,
    to_html,
    to_html_multi,
    to_json,
    to_json_multi,
)


BANNER = r"""
  _  _          _             ___
 | \| |__ _ ___(_)_  _ __ _  / __| __ __ _ _ _  _ _  ___ _ _
 | .` / _` (_-<| | || / _` | \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |_|\_\__,_/__/|_|\_, \__,_| |___/\__\__,_|_||_|_||_\___|_|
                  |__/   Web Zaiflik Skaneri v%s
""" % __version__


def read_targets_file(path: str) -> list[str]:
    targets = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def confirm_authorization(targets: list[str], assume_yes: bool) -> bool:
    if assume_yes:
        return True
    listing = "\n".join(f"      - {t}" for t in targets)
    print(
        "\n⚠️  RUXSAT TASDIG'I\n"
        f"    Tekshiriladigan saytlar ({len(targets)} ta):\n{listing}\n\n"
        "    Bu vosita nishon saytlarga faol so'rovlar (test payloadlari) yuboradi.\n"
        "    Faqat O'ZINGIZGA tegishli yoki yozma ruxsatingiz bor saytlarni tekshiring.\n"
    )
    try:
        answer = input("    Ushbu saytlarni tekshirishga ruxsatingiz bormi? (ha/yo'q): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("ha", "h", "yes", "y")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nasiya_scan",
        description="O'z saytlaringizdagi keng tarqalgan xavfsizlik zaifliklarini aniqlaydi.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Faqat ruxsat etilgan xavfsizlik tekshiruvi uchun.",
    )
    p.add_argument("targets", nargs="*", help="Bir yoki bir nechta sayt manzili")
    p.add_argument("--targets-file", metavar="FAYL",
                   help="Sayt ro'yxati fayli (har qatorda bitta manzil, # — izoh)")
    p.add_argument("--html", metavar="FAYL", help="HTML hisobotni shu faylga yozish")
    p.add_argument("--json", metavar="FAYL", help="JSON natijani shu faylga yozish")
    p.add_argument("--concurrency", type=int, default=3,
                   help="Nechta saytni bir vaqtda skanerlash (standart: 3)")
    p.add_argument("--max-pages", type=int, default=40, help="Har sayt uchun maks. sahifa (standart: 40)")
    p.add_argument("--max-depth", type=int, default=3, help="Maksimal kroul chuqurligi (standart: 3)")
    p.add_argument("--delay", type=float, default=0.3, help="So'rovlar orasidagi kutish, soniya (standart: 0.3)")
    p.add_argument("--timeout", type=float, default=10.0, help="So'rov timeouti, soniya (standart: 10)")
    p.add_argument("--passive", action="store_true",
                   help="Faqat passiv tekshiruvlar (payload yubormaydi, xavfsizroq)")
    p.add_argument("--render", action="store_true",
                   help="SPA saytlar uchun Playwright brauzeri bilan render qilish")
    p.add_argument("--check-default-creds", action="store_true",
                   help="Login formalarda standart parollarni sinash (ehtiyot bo'ling — hisob bloklanishi mumkin)")
    p.add_argument("--insecure", action="store_true", help="TLS sertifikatini tekshirmaslik")
    p.add_argument("--user-agent", help="Maxsus User-Agent qatori")
    p.add_argument("-y", "--yes", action="store_true", help="Ruxsat so'rovini o'tkazib yuborish (avtomatik ha)")
    p.add_argument("--no-color", action="store_true", help="Rangsiz chiqarish")
    p.add_argument("-q", "--quiet", action="store_true", help="Jarayon xabarlarini ko'rsatmaslik")
    p.add_argument("-V", "--version", action="version", version=f"Nasiya Scanner {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if not args.quiet:
        print(BANNER)

    # nishonlarni yig'amiz
    targets = list(args.targets)
    if args.targets_file:
        try:
            targets += read_targets_file(args.targets_file)
        except OSError as exc:
            print(f"Faylni o'qib bo'lmadi: {exc}", file=sys.stderr)
            return 2
    targets = [normalize_target(t) for t in targets]
    # dublikatlarni tartibni saqlab olib tashlaymiz
    targets = list(dict.fromkeys(targets))

    if not targets:
        print("Xato: kamida bitta sayt manzili kerak. Yordam: --help", file=sys.stderr)
        return 2

    if not confirm_authorization(targets, args.yes):
        print("Bekor qilindi — ruxsat tasdiqlanmadi.")
        return 2

    # renderer (SPA) tayyorlash
    renderer_factory = None
    if args.render:
        from scanner import render as render_mod
        if not render_mod.available():
            print("[!] Playwright o'rnatilmagan — render rejimi o'chirildi.\n"
                  "    O'rnatish: pip install playwright && playwright install chromium",
                  file=sys.stderr)
        else:
            def renderer_factory():
                return render_mod.PlaywrightRenderer(
                    timeout=args.timeout, verify_tls=not args.insecure
                )

    def client_factory():
        return HttpClient(
            timeout=args.timeout,
            delay=args.delay,
            user_agent=args.user_agent,
            verify_tls=not args.insecure,
        )

    def progress(msg: str) -> None:
        if not args.quiet:
            print(f"[*] {msg}", file=sys.stderr)

    results = scan_many(
        targets,
        concurrency=args.concurrency,
        client_factory=client_factory,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        active=not args.passive,
        check_default_creds=args.check_default_creds,
        renderer_factory=renderer_factory,
        progress=progress,
    )

    use_color = False if args.no_color else None
    multi = len(results) > 1
    if multi:
        print_console_multi(results, sys.stdout, use_color=use_color)
    else:
        print_console(results[0], sys.stdout, use_color=use_color)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json_multi(results) if multi else to_json(results[0]))
        print(f"[+] JSON hisobot saqlandi: {args.json}", file=sys.stderr)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html_multi(results) if multi else to_html(results[0]))
        print(f"[+] HTML hisobot saqlandi: {args.html}", file=sys.stderr)

    # chiqish kodi: biror saytda kritik/yuqori topilsa 1
    for r in results:
        c = r.counts()
        if c[Severity.CRITICAL] or c[Severity.HIGH]:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
