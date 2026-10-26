@echo off
setlocal
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Run install.cmd first.
  exit /b 1
)
"%~dp0.venv\Scripts\python.exe" "%~dp0sanitizer.py" %*
exit /b %errorlevel%
