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

## 🖥️ Kompyuterda ishlatish (eng oson — brauzer interfeysi)

Terminalni bilmasangiz ham bo'ladi. Dastur **sizning kompyuteringizda** ishlaydi —
hosting, pul yoki ro'yxatdan o'tish **kerak emas**.

1. Python o'rnatilgan bo'lsin (https://python.org — "Add to PATH" ni belgilang).
2. Bu papkani kompyuterga yuklab oling (GitHub'da **Code → Download ZIP**, so'ng arxivni oching).
3. Ishga tushiring:
   - **Windows:** `run.bat` faylini **ikki marta bosing**.
   - **Mac/Linux:** terminalda `./run.sh` yoki `python3 webapp.py`.
4. Brauzer avtomatik ochiladi: **http://127.0.0.1:8777**
5. Sayt manzilini yozib **"Skanerlash"** tugmasini bosing — natija shu yerda chiqadi.

To'xtatish uchun terminal oynasida **Ctrl+C** bosing.

---

## Nimalarni aniqlaydi

Dastur OWASP Top 10 asosidagi eng muhim zaifliklarni qidiradi — jumladan
**adminlikni egallab olishga** olib keladigan jiddiy kamchiliklarni:

| Tekshiruv | Zaiflik | Jiddiylik |
|-----------|---------|-----------|
| **SQL Injection** | Ma'lumotlar bazasiga aralashish (xato asosidagi + boolean) | 🟣 Kritik |
| **Command Injection** | Serverda OS buyruqlarini bajarish (chiqish + vaqt asosidagi) | 🟣 Kritik |
| **Path Traversal / LFI** | Server fayllarini (`/etc/passwd` ...) o'qish | 🟣 Kritik |
| **XXE** | XML tashqi entity orqali fayl o'qish / SSRF | 🟣 Kritik |
| **Standart parollar** | Login formada `admin/admin` kabi standart hisoblar (opt-in) | 🟣 Kritik |
| **Maxfiy fayllar** | Ochiq `.env`, `.git/`, `.sql` zaxiralar, `config` fayllar | 🟣 Kritik / 🔴 Yuqori |
| **SSRF** | Server nomidan ichki/bulut manzillarga so'rov | 🔴 Yuqori / ℹ️ nomzod |
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
# Bitta sayt
python3 nasiya_scan.py https://saytim.uz

# Bir nechta sayt (loyihalaringiz ko'p bo'lsa) — parallel skanerlaydi
python3 nasiya_scan.py https://sayt1.uz https://sayt2.uz https://sayt3.uz

# Sayt ro'yxatini fayldan o'qish (har qatorda bitta manzil, # — izoh)
python3 nasiya_scan.py --targets-file saytlar.txt --html hisobot.html

# HTML va JSON hisobot bilan
python3 nasiya_scan.py https://saytim.uz --html hisobot.html --json natija.json

# Xavfsiz (passiv) rejim — hech qanday test payload yubormaydi
python3 nasiya_scan.py https://saytim.uz --passive

# SPA (React/Vue/Angular) saytlar — brauzer bilan render qilish
python3 nasiya_scan.py https://app.saytim.uz --render

# Standart parollarni ham sinash (ehtiyot bo'ling — hisob bloklanishi mumkin)
python3 nasiya_scan.py https://saytim.uz --check-default-creds
```

### `saytlar.txt` namunasi

```
# Mening loyihalarim
https://sayt1.uz
https://dukon.sayt2.uz
https://api.sayt3.uz
```

### Bir nechta sayt hisoboti

Bir nechta sayt berilganda dastur har birini alohida skanerlaydi va **umumiy
yakuniy jadval** chiqaradi (qaysi saytda nechta kritik/yuqori zaiflik borligini
bir qarashda ko'rasiz). `--html` berilsa, yuqorisida indeks-jadval bo'lgan
yagona umumiy hisobot fayli yaratiladi.

### Asosiy parametrlar

| Parametr | Vazifasi | Standart |
|----------|----------|----------|
| `--targets-file FAYL` | Sayt ro'yxati faylidan o'qish | — |
| `--concurrency N` | Nechta saytni bir vaqtda skanerlash | 3 |
| `--html FAYL` | HTML hisobotni saqlash | — |
| `--json FAYL` | JSON natijani saqlash | — |
| `--passive` | Faqat passiv tekshiruvlar (payloadsiz) | o'chiq |
| `--render` | SPA saytlarni Playwright brauzeri bilan render qilish | o'chiq |
| `--check-default-creds` | Login formada standart parollarni sinash | o'chiq |
| `--max-pages N` | Har sayt uchun maksimal sahifa soni | 40 |
| `--max-depth N` | Kroul chuqurligi | 3 |
| `--delay S` | So'rovlar orasidagi kutish (soniya) | 0.3 |
| `--timeout S` | So'rov kutish vaqti (soniya) | 10 |
| `--insecure` | TLS sertifikatini tekshirmaslik | o'chiq |
| `-y, --yes` | Ruxsat so'rovini avtomatik tasdiqlash | o'chiq |
| `-q, --quiet` | Jarayon xabarlarini yashirish | o'chiq |

### SPA (JavaScript) saytlar uchun `--render`

React/Vue/Angular kabi saytlarda havolalar va formalar JavaScript orqali
yuklanadi. `--render` bayrog'i sahifani haqiqiy brauzer (Chromium) ichida ishga
tushirib, JS bilan qo'shilgan havola va formalarni ham aniqlaydi. Buning uchun
Playwright kerak:

```bash
pip install playwright
playwright install chromium
```

Playwright o'rnatilmagan bo'lsa, dastur ogohlantirib, oddiy rejimga qaytadi.

### Chiqish kodlari

- `0` — kritik/yuqori zaiflik topilmadi
- `1` — kamida bitta kritik yoki yuqori zaiflik topildi (CI/CD uchun qulay)
- `2` — ruxsat tasdiqlanmadi

---

## Loyiha tuzilishi

```
scanner/
├── nasiya_scan.py          # CLI kirish nuqtasi (terminal)
├── webapp.py               # mahalliy brauzer interfeysi (http://127.0.0.1:8777)
├── run.bat / run.sh        # bir bosishda ishga tushirish (Windows / Mac-Linux)
├── requirements.txt
├── scanner/
│   ├── models.py           # Finding / Severity / ScanResult
│   ├── http_client.py      # rate-limit + timeout bilan HTTP mijoz
│   ├── crawler.py          # sayt bo'ylab yuruvchi + HTML parser
│   ├── render.py           # ixtiyoriy Playwright renderer (SPA)
│   ├── engine.py           # orkestratsiya + ko'p saytli scan_many()
│   ├── reporter.py         # konsol / JSON / HTML (bir va ko'p saytli)
│   └── checks/             # har bir zaiflik uchun alohida modul
│       ├── _injection.py   # inyeksiya nuqtalari (umumiy yordamchi)
│       ├── sqli.py
│       ├── command_injection.py
│       ├── path_traversal.py
│       ├── xss.py
│       ├── ssrf.py
│       ├── xxe.py
│       ├── default_credentials.py
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
