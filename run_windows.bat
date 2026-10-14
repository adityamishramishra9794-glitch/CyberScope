@echo off
REM CyberScope V4 launcher for Windows. Creates a virtual environment on first run.
cd /d "%~dp0\.."
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.11 or newer was not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause
  exit /b 1
)
if not exist .venv (
  echo Creating virtual environment...
  python -m venv .venv
  call .venv\Scripts\activate.bat
  python -m pip install --upgrade pip
  pip install -r requirements.txt
) else (
  call .venv\Scripts\activate.bat
)
python main.py
if errorlevel 1 pause
