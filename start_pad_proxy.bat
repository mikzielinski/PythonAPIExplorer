@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "DEFAULT_VENV=%SCRIPT_DIR%.pad-trace-venv\Scripts\python.exe"
set "PAD_PROXY_SCRIPT=%SCRIPT_DIR%pad_rest_inspector.py"
set "PYTHON_EXEC=%PYTHON%"
if "%PYTHON_EXEC%"=="" set "PYTHON_EXEC=python"
if exist "%DEFAULT_VENV%" set "PYTHON_EXEC=%DEFAULT_VENV%"

if not exist "%PAD_PROXY_SCRIPT%" (
    echo Unable to find pad_rest_inspector.py at "%PAD_PROXY_SCRIPT%"
    exit /b 1
)

echo Using Python: %PYTHON_EXEC%
cd /d "%SCRIPT_DIR%"
"%PYTHON_EXEC%" "%PAD_PROXY_SCRIPT%" %*

if errorlevel 1 (
    echo.
    echo Proxy exited with error level %errorlevel%.
) else (
    echo.
    echo Proxy stopped. Requests were logged to pad_http_log.jsonl.
)

pause
