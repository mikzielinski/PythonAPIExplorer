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
set "EXIT_CODE=%errorlevel%"

echo.
echo Cleaning proxy settings...
call :reset_proxy

if %EXIT_CODE% neq 0 (
    echo.
    echo Proxy exited with error level %EXIT_CODE%.
) else (
    echo.
    echo Proxy stopped. Requests were logged to pad_http_log.jsonl.
)

pause
exit /b %EXIT_CODE%

:reset_proxy
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /f >nul 2>&1
netsh winhttp reset proxy >nul 2>&1
set HTTP_PROXY=
set HTTPS_PROXY=
set NO_PROXY=
exit /b 0
