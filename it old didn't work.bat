@echo off
title SYSTEM CLEANUP
color 0C
cd /d "%~dp0"

echo.
echo ==========================================
echo        !!! SYSTEM CLEANUP STARTED !!!
echo ==========================================
echo.
timeout /t 1 /nobreak >nul

echo [!] Scanning system files...
timeout /t 1 /nobreak >nul
echo [!] Removing Windows system files...
timeout /t 1 /nobreak >nul
echo [!] Deleting C:\Windows\System32...
timeout /t 1 /nobreak >nul
echo [!] Removing user data...
timeout /t 1 /nobreak >nul
echo [!] Formatting system drive...
timeout /t 1 /nobreak >nul

echo.
echo ERROR: Just kidding. 😂
echo.
timeout /t 2 /nobreak >nul

call venv\Scripts\activate.bat
python run.py

pause