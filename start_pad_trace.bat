@echo off
setlocal ENABLEDELAYEDEXPANSION
set "SCRIPT_DIR=%~dp0"
set "DEFAULT_VENV=%SCRIPT_DIR%.pad-trace-venv\Scripts\python.exe"

if exist "%DEFAULT_VENV%" (
    set "PYTHON_EXEC=%DEFAULT_VENV%"
) else (
    set "PYTHON_EXEC=%PYTHON%"
    if "!PYTHON_EXEC!"=="" set "PYTHON_EXEC=python"
)

echo Using Python: %PYTHON_EXEC%
cd /d "%SCRIPT_DIR%"
"%PYTHON_EXEC%" "%SCRIPT_DIR%trace_pad_http_full.py" %*

if errorlevel 1 (
    echo.
    echo Tracer exited with error level %errorlevel%.
)

pause
