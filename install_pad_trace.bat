@echo off
setlocal ENABLEDELAYEDEXPANSION
set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%.pad-trace-venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"
set "REQUIREMENTS=%SCRIPT_DIR%requirements.txt"

if not exist "%REQUIREMENTS%" (
    echo Requirements file not found at %REQUIREMENTS%
    exit /b 1
)

if not exist "%VENV_PY%" (
    set "PYTHON_BIN=%PYTHON%"
    if "!PYTHON_BIN!"=="" set "PYTHON_BIN=python"
    echo Creating virtual environment under %VENV_DIR%
    "!PYTHON_BIN!" -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo Failed to create virtual environment.
        exit /b %errorlevel%
    )
) else (
    echo Reusing existing virtual environment at %VENV_DIR%
)

call "%VENV_DIR%\Scripts\activate.bat"
if errorlevel 1 (
    echo Unable to activate virtual environment.
    exit /b %errorlevel%
)

echo Upgrading pip...
python -m pip install --upgrade pip
if errorlevel 1 goto install_error

echo Installing Python dependencies...
pip install -r "%REQUIREMENTS%"
if errorlevel 1 goto install_error

echo.
echo ✅ Dependencies installed. Use start_pad_trace.bat to run the tracer.
endlocal
exit /b 0

:install_error
echo.
echo ❌ Failed to install dependencies.
endlocal
exit /b 1
