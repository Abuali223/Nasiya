# Firebase Hosting'ga deploy qilish

Bu loyiha (`Nasiya` — Kirim/Chiqim PWA) statik sayt, shuning uchun Firebase
Hosting'ga oson joylanadi. Quyida **ikki xil** usul bor.

---

## ⚠️ Avval: oshkor bo'lgan kalitni bekor qiling

Agar siz service account kalitini biror joyga (chat, xabar, skrinshot) joylagan
bo'lsangiz, u **buzilgan** hisoblanadi. Deploy qilishdan oldin:

1. [Google Cloud Console → Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts?project=oqhaker-fbe2e)
2. `firebase-adminsdk-...` hisobini oching → **Keys** bo'limi
3. Eski kalitni **o'chiring (Delete)**, so'ng **Add Key → Create new key → JSON** orqali yangisini yarating
4. Yangi JSON faylni **hech qachon** kod yoki git ichiga qo'ymang

`.gitignore` allaqachon `*serviceAccount*.json`, `firebase-adminsdk*.json`,
`.env` kabi fayllarni bloklaydi.

---

## A usul — kompyuteringizdan qo'lda deploy (eng oddiy)

Service account kalitiga **umuman ehtiyoj yo'q** — brauzer orqali kirasiz.

```bash
# 1. Firebase CLI o'rnatish (bir marta)
npm install -g firebase-tools

# 2. Firebase hisobingizga kirish (brauzer ochiladi)
firebase login

# 3. Loyiha papkasiga o'ting va deploy qiling
cd Nasiya
firebase deploy --only hosting
```

Tugagach, sayt manzili ko'rsatiladi, masalan:
`https://oqhaker-fbe2e.web.app`

> `firebase.json` va `.firebaserc` fayllari allaqachon sozlangan — loyiha ID
> (`oqhaker-fbe2e`) va hosting sozlamalari tayyor.

---

## B usul — GitHub Actions orqali avtomatik deploy

Har safar `main` branchга push qilganingizda sayt avtomatik yangilanadi.

### 1. Yangi service account kalitini GitHub Secrets'ga qo'shing

1. GitHub'da repozitoriyni oching → **Settings** → **Secrets and variables** → **Actions**
2. **New repository secret** bosing
3. Nomi: `FIREBASE_SERVICE_ACCOUNT`
4. Qiymati: yangi service account **JSON faylining to'liq mazmuni** (butun `{...}`)
5. **Add secret**

> Kalit faqat shu yerda — shifrlangan holda — saqlanadi. Kodда yoki logда
> hech qachon ko'rinmaydi.

### 2. Tayyor

`.github/workflows/firebase-hosting.yml` allaqachon qo'shilgan. Endi `main`ga
har push avtomatik deploy qiladi. Qo'lda ishga tushirish uchun: repozitoriya →
**Actions** → *Firebase Hosting'ga deploy* → **Run workflow**.

---

## Sozlangan narsalar

`firebase.json` quyidagilarni ta'minlaydi:

- **Xavfsizlik sarlavhalari** — `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, `Permissions-Policy` va `Content-Security-Policy`. (Ya'ni
  saytingiz o'zimiz qurgan zaiflik skanerining ko'p tekshiruvlaridan o'tadi.)
  Firebase Hosting HTTPS va HSTS'ni avtomatik qo'shadi.
- **Kesh (cache) sozlamalari** — `sw.js` keshlanmaydi (yangilanishlar darhol
  yetadi), ikonlar uzoq keshlanadi.
- `scanner/`, `README.md` kabi web'ga taalluqli bo'lmagan fayllar deploy'ga
  kirmaydi.

## Tuzatilgan xato

Ilgari `index.html`, `manifest.webmanifest` va `sw.js` ikonlarni `icons/`
papkasidan qidirar edi, lekin fayllar loyiha ildizida (root) yotardi — natijada
ikonlar **404** qaytarar va service worker (offline rejim) **ishlamas** edi.
Ikonlar `icons/` papkasiga ko'chirildi, endi PWA to'g'ri ishlaydi.
