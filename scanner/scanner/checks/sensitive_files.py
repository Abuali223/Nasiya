"""Maxfiy fayllar va boshqaruv panellari — ochiq qolgan xavfli manzillarni izlaydi.

Bu tekshiruv adminlikni egallab olishga olib keladigan eng jiddiy zaifliklarni
(masalan ochiq .env, .git, zaxira nusxalar, himoyasiz admin panellar) aniqlaydi.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..models import Finding, Severity
from . import Check, Context

# (yo'l, jiddiylik, tavsif, tasdiqlovchi belgi yoki None)
PROBES = [
    (".env", Severity.CRITICAL,
     "Muhit sozlamalari fayli (.env) ochiq — bu odatda ma'lumotlar bazasi parollari, "
     "API kalitlari va maxfiy tokenlarni saqlaydi.",
     re.compile(r"(?:DB_PASSWORD|APP_KEY|SECRET|API_KEY|PASSWORD)\s*=", re.I)),
    (".git/HEAD", Severity.HIGH,
     "Git repozitoriysi ochiq (.git/). Butun manba kodini va tarixini yuklab olish mumkin.",
     re.compile(r"ref:\s*refs/", re.I)),
    (".git/config", Severity.HIGH,
     "Git config fayli ochiq — repozitoriya URL'lari va ba'zan hisob ma'lumotlari oshkor.",
     re.compile(r"\[core\]|\[remote", re.I)),
    ("config.php.bak", Severity.CRITICAL,
     "Konfiguratsiya faylining zaxira nusxasi ochiq — parollar oshkor bo'lishi mumkin.", None),
    ("config.php~", Severity.HIGH,
     "Konfiguratsiya faylining tahrirlovchi zaxirasi ochiq.", None),
    ("backup.zip", Severity.HIGH, "Sayt zaxira arxivi ochiq.", None),
    ("backup.sql", Severity.CRITICAL, "Ma'lumotlar bazasi dampi (.sql) ochiq.", None),
    ("db.sql", Severity.CRITICAL, "Ma'lumotlar bazasi dampi ochiq.", None),
    ("dump.sql", Severity.CRITICAL, "Ma'lumotlar bazasi dampi ochiq.", None),
    (".htaccess", Severity.LOW, ".htaccess fayli o'qilishi mumkin.", None),
    ("phpinfo.php", Severity.MEDIUM,
     "phpinfo() sahifasi ochiq — server konfiguratsiyasi to'liq oshkor.",
     re.compile(r"phpinfo\(\)|PHP Version", re.I)),
    ("server-status", Severity.MEDIUM,
     "Apache server-status sahifasi ochiq — barcha faol so'rovlar ko'rinadi.", None),
    ("info.php", Severity.MEDIUM, "info.php (phpinfo) sahifasi ochiq bo'lishi mumkin.",
     re.compile(r"PHP Version", re.I)),
    ("wp-config.php.bak", Severity.CRITICAL,
     "WordPress konfiguratsiyasi zaxirasi ochiq — DB parollari oshkor.", None),
    (".DS_Store", Severity.LOW, ".DS_Store fayli fayl tuzilishini oshkor qiladi.", None),
    ("composer.json", Severity.INFO, "composer.json ochiq — ishlatilayotgan paketlar ko'rinadi.", None),
    ("package.json", Severity.INFO, "package.json ochiq — bog'liqliklar ko'rinadi.", None),
    (".svn/entries", Severity.HIGH, "SVN metama'lumotlari ochiq — manba kodi tiklanishi mumkin.", None),
    ("robots.txt", Severity.INFO,
     "robots.txt topildi — yashirin manzillarga ishoralar bo'lishi mumkin.", None),
]

# Boshqaruv (admin) panellari — himoyasi tekshiriladi
ADMIN_PANELS = [
    "admin", "administrator", "admin/login", "admin.php", "wp-admin/",
    "wp-login.php", "manager/html", "phpmyadmin/", "adminer.php",
    "cpanel", "user/login", "login", "dashboard",
]

DIR_LISTING = re.compile(r"<title>\s*Index of /|<h1>\s*Index of /", re.I)
LOGIN_FORM = re.compile(r"type=[\"']password[\"']", re.I)


class SensitiveFilesCheck(Check):
    name = "Maxfiy fayllar va panellar"
    description = "Ochiq qolgan maxfiy fayllar, zaxiralar va admin panellarni izlaydi."

    def _looks_like_page(self, resp) -> bool:
        """Haqiqiy mavjud sahifami yoki soft-404?"""
        if resp.status != 200 or not resp.text:
            return False
        # umumiy 404/xato sahifasi belgisi
        low = resp.text.lower()
        if "not found" in low[:1000] or "404" in resp.text[:200]:
            return False
        return True

    def run(self, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        base = ctx.target if ctx.target.endswith("/") else ctx.target + "/"

        # 1) Maxfiy fayllarni tekshirish
        for path, sev, desc, sig in PROBES:
            resp = ctx.client.get(urljoin(base, path))
            if not self._looks_like_page(resp):
                continue
            # tasdiqlovchi belgi bo'lsa, mos kelishini talab qilamiz (soft-404'dan himoya)
            if sig is not None and not sig.search(resp.text):
                continue
            findings.append(
                Finding(
                    check=self.name,
                    title=f"Ochiq maxfiy fayl: /{path}",
                    severity=sev,
                    url=resp.url,
                    description=desc,
                    remediation="Bu faylni public papkadan olib tashlang yoki veb-server "
                    "sozlamalarida unga kirishni bloklang (masalan `deny from all`).",
                    cwe="CWE-538",
                    evidence=f"HTTP {resp.status}, {len(resp.text)} bayt",
                )
            )

        # 2) Katalog ro'yxati (directory listing) ochiqmi
        listing_reported = 0
        for url, page in list(ctx.crawl.pages.items())[:15]:
            if page.ok and DIR_LISTING.search(page.text) and listing_reported < 3:
                listing_reported += 1
                findings.append(
                    Finding(
                        check=self.name,
                        title="Katalog ro'yxati ochiq (Directory Listing)",
                        severity=Severity.MEDIUM,
                        url=url,
                        description="Veb-server katalog tarkibini ro'yxat qilib "
                        "ko'rsatmoqda. Bu maxfiy fayllarni oshkor qilishi mumkin.",
                        remediation="Veb-serverda katalog ro'yxatini o'chiring "
                        "(Apache: `Options -Indexes`).",
                        cwe="CWE-548",
                    )
                )

        # 3) Admin panellarini topish
        for path in ADMIN_PANELS:
            resp = ctx.client.get(urljoin(base, path))
            if resp.status == 200 and resp.text:
                has_login = bool(LOGIN_FORM.search(resp.text))
                sev = Severity.LOW if has_login else Severity.MEDIUM
                detail = (
                    "Login formasi mavjud — kuchli parol va brute-force himoyasi borligiga ishonch hosil qiling."
                    if has_login
                    else "Sahifa ochiq va parol so'ralmayotganga o'xshaydi — kirish nazoratini tekshiring."
                )
                findings.append(
                    Finding(
                        check=self.name,
                        title=f"Boshqaruv paneli topildi: /{path}",
                        severity=sev,
                        url=resp.url,
                        description=f"Boshqaruv/kirish paneli ochiq holatda topildi. {detail}",
                        remediation="Admin panelni IP bo'yicha cheklang, ikki bosqichli "
                        "autentifikatsiya (2FA) qo'shing va login urinishlarini cheklang.",
                        cwe="CWE-284",
                        evidence=f"HTTP {resp.status}",
                    )
                )
        return findings
