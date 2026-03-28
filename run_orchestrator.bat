@echo off
cd /d "%~dp0"

if not exist ".venv\Scripts\activate.bat" (
    echo ERROR: Virtual environment not found at .venv\
    echo Please run: py -3.11 -m venv .venv
    echo Then run:   .venv\Scripts\activate ^&^& pip install -r requirements.txt
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat
echo Using Python: && python --version
echo.
python orchestrator.py
