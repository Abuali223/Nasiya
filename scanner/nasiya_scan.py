#!/usr/bin/env python3
"""Nasiya Web Zaiflik Skaneri — buyruq qatori interfeysi (CLI).

Foydalanish:
    python3 nasiya_scan.py https://saytim.uz
    python3 nasiya_scan.py https://saytim.uz --html hisobot.html --json natija.json
    python3 nasiya_scan.py https://saytim.uz --passive        # payloadsiz (xavfsiz) rejim

DIQQAT — QONUNIY OGOHLANTIRISH:
    Bu vositani FAQAT o'zingizga tegishli yoki tekshirishga YOZMA RUXSATingiz bor
    saytlarda ishlating. Begona saytni ruxsatsiz skanerlash ko'p mamlakatlarda
    jinoiy javobgarlikka olib keladi.
"""

from __future__ import annotations

import argparse
import sys

from scanner import __version__
from scanner.engine import Scanner, normalize_target
from scanner.http_client import HttpClient
from scanner.reporter import print_console, to_html, to_json


BANNER = r"""
  _  _          _             ___
 | \| |__ _ ___(_)_  _ __ _  / __| __ __ _ _ _  _ _  ___ _ _
 | .` / _` (_-<| | || / _` | \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |_|\_\__,_/__/|_|\_, \__,_| |___/\__\__,_|_||_|_||_\___|_|
                  |__/   Web Zaiflik Skaneri v%s
""" % __version__


def confirm_authorization(target: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    print(
        "\n⚠️  RUXSAT TASDIG'I\n"
        f"    Nishon: {target}\n"
        "    Bu vosita nishon saytga faol so'rovlar (test payloadlari) yuboradi.\n"
        "    Faqat O'ZINGIZGA tegishli yoki yozma ruxsatingiz bor saytni tekshiring.\n"
    )
    try:
        answer = input("    Ushbu saytni tekshirishga ruxsatingiz bormi? (ha/yo'q): ").strip().lower()
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
    p.add_argument("target", help="Tekshiriladigan sayt manzili (masalan https://saytim.uz)")
    p.add_argument("--html", metavar="FAYL", help="HTML hisobotni shu faylga yozish")
    p.add_argument("--json", metavar="FAYL", help="JSON natijani shu faylga yozish")
    p.add_argument("--max-pages", type=int, default=40, help="Maksimal sahifa soni (standart: 40)")
    p.add_argument("--max-depth", type=int, default=3, help="Maksimal kroul chuqurligi (standart: 3)")
    p.add_argument("--delay", type=float, default=0.3, help="So'rovlar orasidagi kutish, soniya (standart: 0.3)")
    p.add_argument("--timeout", type=float, default=10.0, help="So'rov timeouti, soniya (standart: 10)")
    p.add_argument("--passive", action="store_true",
                   help="Faqat passiv tekshiruvlar (payload yubormaydi, xavfsizroq)")
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

    target = normalize_target(args.target)

    if not confirm_authorization(target, args.yes):
        print("Bekor qilindi — ruxsat tasdiqlanmadi.")
        return 2

    client = HttpClient(
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent,
        verify_tls=not args.insecure,
    )

    def progress(msg: str) -> None:
        if not args.quiet:
            print(f"[*] {msg}", file=sys.stderr)

    scanner = Scanner(
        client=client,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        active=not args.passive,
        progress=progress,
    )

    result = scanner.scan(target)

    # konsol hisoboti
    print_console(result, sys.stdout, use_color=None if not args.no_color else False)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(result))
        print(f"[+] JSON hisobot saqlandi: {args.json}", file=sys.stderr)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(result))
        print(f"[+] HTML hisobot saqlandi: {args.html}", file=sys.stderr)

    # chiqish kodi: kritik/yuqori topilsa 1
    counts = result.counts()
    from scanner.models import Severity
    if counts[Severity.CRITICAL] or counts[Severity.HIGH]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
