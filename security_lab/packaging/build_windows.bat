@echo off
REM Build the CyberLLMv1 Security Lab exe.
REM Run this from the SentientAI project root on Windows.
REM The build venv lives in %TEMP% so the repo stays clean.
setlocal

where python >nul 2>&1
if errorlevel 1 (
  echo Python 3.11 or 3.12 is required. Install it, then re-run this script.
  exit /b 1
)

set VENV=%TEMP%\seclab-build-venv
if not exist "%VENV%\Scripts\python.exe" (
  echo Creating build venv at %VENV% ...
  python -m venv "%VENV%"
)
call "%VENV%\Scripts\activate.bat"

echo Installing GUI dependencies ...
python -m pip install --upgrade pip
REM --upgrade: a reused build venv must not silently keep older GUI
REM packages than a fresh build would install.
pip install --upgrade -r security_lab\packaging\requirements-gui.txt
pip install pyinstaller

echo Building exe (this takes a few minutes) ...
pyinstaller --noconfirm security_lab\packaging\security-lab.spec

echo.
echo Build finished. Double-click:
echo   dist\CyberLLMv1-Security-Lab.exe
echo.
echo The exe needs the SentientAI project and its venv on the same
echo machine (see security_lab\packaging\BUILD_GUIDE.md). It does not
echo bundle the backend or any model weights.
endlocal
