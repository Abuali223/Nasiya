#!/usr/bin/env bash
# Nasiya Skaner — Mac/Linux uchun ishga tushirish
set -e
cd "$(dirname "$0")"
echo "================================================"
echo "  Nasiya Web Zaiflik Skaneri ishga tushmoqda..."
echo "================================================"
echo
echo "Kerakli kutubxonalar tekshirilmoqda..."
python3 -m pip install -r requirements.txt >/dev/null 2>&1 || \
  python3 -m pip install --user -r requirements.txt
echo
echo "Brauzer ochiladi: http://127.0.0.1:8777"
echo "To'xtatish uchun Ctrl+C bosing."
echo
python3 webapp.py
