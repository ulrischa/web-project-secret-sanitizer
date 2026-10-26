@echo off
setlocal
cd /d "%~dp0"
py -3.12 -m venv .venv
if errorlevel 1 goto failed
.venv\Scripts\python.exe -m pip install --only-binary=:all: -r requirements.txt
if errorlevel 1 goto failed
echo Installation complete. Run sanitizer.cmd --help
exit /b 0
:failed
echo Installation failed. Install Python 3.12 or create .venv manually with Python 3.12 or newer.
exit /b 1
