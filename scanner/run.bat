@echo off
REM Nasiya Skaner — Windows uchun ishga tushirish (ikki marta bosing)
cd /d "%~dp0"
echo ================================================
echo   Nasiya Web Zaiflik Skaneri ishga tushmoqda...
echo ================================================
echo.
echo Kerakli kutubxonalar tekshirilmoqda...
python -m pip install -r requirements.txt
echo.
echo Brauzer ochiladi: http://127.0.0.1:8777
echo To'xtatish uchun bu oynada Ctrl+C bosing.
echo.
python webapp.py
pause
