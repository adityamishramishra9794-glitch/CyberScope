@echo off
REM OPTIONAL: builds dist\CyberScope\CyberScope.exe with PyInstaller. Not needed to run from source.
cd /d "%~dp0\.."
call .venv\Scripts\activate.bat
pip install pyinstaller
pyinstaller --noconfirm --windowed --name CyberScope --collect-submodules PySide6 main.py
echo Done. See dist\CyberScope\CyberScope.exe
pause
