@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%.pad-trace-venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"
set "REQUIREMENTS=%SCRIPT_DIR%requirements.txt"

if not exist "%REQUIREMENTS%" goto missing_requirements

if exist "%VENV_PY%" goto have_venv

set "PYTHON_BIN=%PYTHON%"
if "%PYTHON_BIN%"=="" set "PYTHON_BIN=python"

echo Creating virtual environment under "%VENV_DIR%"
"%PYTHON_BIN%" -m venv "%VENV_DIR%"
if errorlevel 1 goto venv_error

goto activate_venv

:have_venv
echo Reusing existing virtual environment at "%VENV_DIR%"

goto activate_venv

:activate_venv
call "%VENV_DIR%\Scripts\activate.bat"
if errorlevel 1 goto activate_error

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

:missing_requirements
echo Requirements file not found at "%REQUIREMENTS%"
endlocal
exit /b 1

:venv_error
echo Failed to create virtual environment.
endlocal
exit /b 1

:activate_error
echo Unable to activate virtual environment.
endlocal
exit /b 1

:install_error
echo.
echo ❌ Failed to install dependencies.
endlocal
exit /b 1
