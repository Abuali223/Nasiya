# 🛡️ Nasiya Web Zaiflik Skaneri

O'z saytlaringizdagi keng tarqalgan xavfsizlik **zaifliklarini avtomatik
aniqlaydigan** yengil vosita. Sayt manzilini (silka) berasiz — dastur saytga
kirib, sahifalarni aylanib chiqadi va zaifliklar qayerda ekanini, qanchalik
jiddiy ekanini hamda qanday tuzatishni aytib beradi.

> ⚠️ **QONUNIY OGOHLANTIRISH**
> Bu vositani **faqat o'zingizga tegishli** yoki tekshirishga **yozma
> ruxsatingiz bor** saytlarda ishlating. Begona saytni ruxsatsiz skanerlash
> ko'p mamlakatlarda jinoiy javobgarlikka olib keladi. Mualliflar noqonuniy
> foydalanish uchun javobgar emas.

---

## Nimalarni aniqlaydi

Dastur OWASP Top 10 asosidagi eng muhim zaifliklarni qidiradi — jumladan
**adminlikni egallab olishga** olib keladigan jiddiy kamchiliklarni:

| Tekshiruv | Zaiflik | Jiddiylik |
|-----------|---------|-----------|
| **SQL Injection** | Ma'lumotlar bazasiga aralashish (xato asosidagi + boolean) | 🟣 Kritik |
| **Maxfiy fayllar** | Ochiq `.env`, `.git/`, `.sql` zaxiralar, `config` fayllar | 🟣 Kritik / 🔴 Yuqori |
| **Reflected XSS** | Brauzerda begona JavaScript ishga tushirish | 🔴 Yuqori |
| **Admin panellar** | Ochiq boshqaruv/kirish panellari (`/admin`, `/wp-admin` ...) | 🟠 O'rta |
| **CSRF** | Formalarda anti-CSRF token yo'qligi | 🟠 O'rta |
| **Open Redirect** | Tashqi saytga soxta yo'naltirish | 🟠 O'rta |
| **Clickjacking** | Sahifani yashirin `<iframe>` ichiga joylash | 🟠 O'rta |
| **TLS/HTTPS** | Shifrlanmagan HTTP, HTTPS'ga yo'naltirmaslik | 🔴 Yuqori / 🟠 O'rta |
| **Cookie bayroqlari** | `Secure` / `HttpOnly` / `SameSite` yo'qligi | 🟠 O'rta / 🔵 Past |
| **Xavfsizlik sarlavhalari** | CSP, HSTS, X-Content-Type-Options ... yo'qligi | 🟠 O'rta / 🔵 Past |
| **Ma'lumot oshkorligi** | Server versiyalari, batafsil xato / stack-trace | 🔵 Past / 🟠 O'rta |
| **Directory Listing** | Ochiq katalog ro'yxati | 🟠 O'rta |

Har bir topilma uchun beriladi: **manzil** (qayerda), **parametr**, **dalil**
(payload va javob parchasi), **tavsif** va **tuzatish yo'li**, hamda **CWE**
raqami.

---

## O'rnatish

Faqat bitta tashqi kutubxona kerak — `requests`. Qolgan hammasi Python
standart kutubxonasida.

```bash
cd scanner
python3 -m pip install -r requirements.txt
```

Python 3.9+ talab qilinadi.

---

## Foydalanish

```bash
# Oddiy skanerlash
python3 nasiya_scan.py https://saytim.uz

# HTML va JSON hisobot bilan
python3 nasiya_scan.py https://saytim.uz --html hisobot.html --json natija.json

# Xavfsiz (passiv) rejim — hech qanday test payload yubormaydi
python3 nasiya_scan.py https://saytim.uz --passive

# Ruxsat so'rovini o'tkazib yuborish (o'z saytingiz uchun)
python3 nasiya_scan.py https://saytim.uz -y
```

### Asosiy parametrlar

| Parametr | Vazifasi | Standart |
|----------|----------|----------|
| `--html FAYL` | HTML hisobotni saqlash | — |
| `--json FAYL` | JSON natijani saqlash | — |
| `--passive` | Faqat passiv tekshiruvlar (payloadsiz) | o'chiq |
| `--max-pages N` | Maksimal sahifa soni | 40 |
| `--max-depth N` | Kroul chuqurligi | 3 |
| `--delay S` | So'rovlar orasidagi kutish (soniya) | 0.3 |
| `--timeout S` | So'rov kutish vaqti (soniya) | 10 |
| `--insecure` | TLS sertifikatini tekshirmaslik | o'chiq |
| `-y, --yes` | Ruxsat so'rovini avtomatik tasdiqlash | o'chiq |
| `-q, --quiet` | Jarayon xabarlarini yashirish | o'chiq |

### Chiqish kodlari

- `0` — kritik/yuqori zaiflik topilmadi
- `1` — kamida bitta kritik yoki yuqori zaiflik topildi (CI/CD uchun qulay)
- `2` — ruxsat tasdiqlanmadi

---

## Loyiha tuzilishi

```
scanner/
├── nasiya_scan.py          # CLI kirish nuqtasi
├── requirements.txt
├── scanner/
│   ├── models.py           # Finding / Severity / ScanResult
│   ├── http_client.py      # rate-limit + timeout bilan HTTP mijoz
│   ├── crawler.py          # sayt bo'ylab yuruvchi + HTML parser
│   ├── engine.py           # orkestratsiya
│   ├── reporter.py         # konsol / JSON / HTML hisobot
│   └── checks/             # har bir zaiflik uchun alohida modul
│       ├── sqli.py
│       ├── xss.py
│       ├── sensitive_files.py
│       ├── csrf.py
│       ├── open_redirect.py
│       ├── clickjacking.py
│       ├── headers.py
│       ├── cookies.py
│       ├── tls.py
│       └── info_disclosure.py
└── tests/
    └── test_scanner.py     # lokal zaif server bilan integratsiya testi
```

Yangi tekshiruv qo'shish uchun `scanner/checks/` ichida `Check` klassidan meros
oluvchi modul yozib, uni `checks/__init__.py` dagi `ALL_CHECKS` ro'yxatiga
qo'shing.

---

## Cheklovlar

Bu vosita boshlang'ich (baseline) tekshiruv uchun mo'ljallangan. U:

- JavaScript orqali dinamik yuklanadigan (SPA) kontentni to'liq ko'rmaydi —
  faqat serverdan kelgan HTML'ni tahlil qiladi.
- Autentifikatsiyani talab qiladigan sahifalar ortidagi zaifliklarni sinamaydi.
- Murakkab, chuqur (second-order, time-based blind) inyeksiyalarni topa olmaydi.

Jiddiy loyihalar uchun buni professional vositalar (OWASP ZAP, Burp Suite,
`nuclei`, `sqlmap`) va qo'lda tekshiruv bilan **to'ldiring** — o'rniga
ishlatmang.

---

## Test

```bash
cd scanner
python3 -m unittest discover -s tests -v
```

Test ataylab zaif qilingan lokal server ishga tushirib, skaner uni to'g'ri
aniqlashini tekshiradi.
