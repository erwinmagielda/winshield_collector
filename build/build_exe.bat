@echo off
setlocal

title Build WinShield+ Collector EXE

REM ------------------------------------------------------------
REM WinShield+ Collector Builder
REM ------------------------------------------------------------
REM Builds:
REM     src\core\winshield_collector.py
REM
REM Into:
REM     src\core\winshield_collector.exe
REM ------------------------------------------------------------

cd /d "%~dp0\.."

set "SOURCE_FILE=src\core\winshield_collector.py"
set "OUTPUT_DIR=src\core"
set "WORK_DIR=build\pyinstaller"
set "SPEC_DIR=build\pyinstaller"
set "EXE_NAME=winshield_collector"

echo.
echo ============================================================
echo  Build WinShield+ Collector EXE
echo ============================================================
echo.

REM ------------------------------------------------------------
REM SOURCE CHECK
REM ------------------------------------------------------------

if not exist "%SOURCE_FILE%" (
    echo [X] Source file not found:
    echo %SOURCE_FILE%
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM PYTHON CHECK
REM ------------------------------------------------------------

where python.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python was not found.
    echo.
    echo Install Python, then rerun:
    echo build\build_exe.bat
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM PYINSTALLER CHECK
REM ------------------------------------------------------------

python -m pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] PyInstaller is not installed.
    echo [*] Installing PyInstaller...
    echo.

    python -m pip install pyinstaller

    if %errorlevel% neq 0 (
        echo.
        echo [X] Failed to install PyInstaller.
        echo.
        pause
        exit /b 1
    )
)

REM ------------------------------------------------------------
REM CLEAN PREVIOUS BUILD FILES
REM ------------------------------------------------------------

if exist "%OUTPUT_DIR%\%EXE_NAME%.exe" (
    del /f /q "%OUTPUT_DIR%\%EXE_NAME%.exe" >nul 2>&1
)

if exist "%WORK_DIR%" (
    rmdir /s /q "%WORK_DIR%" >nul 2>&1
)

REM ------------------------------------------------------------
REM BUILD EXE
REM ------------------------------------------------------------

echo [*] Building executable...
echo.

python -m PyInstaller ^
    --onefile ^
    --clean ^
    --name "%EXE_NAME%" ^
    --distpath "%OUTPUT_DIR%" ^
    --workpath "%WORK_DIR%" ^
    --specpath "%SPEC_DIR%" ^
    "%SOURCE_FILE%"

if %errorlevel% neq 0 (
    echo.
    echo [X] Build failed.
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM VERIFY OUTPUT
REM ------------------------------------------------------------

if not exist "%OUTPUT_DIR%\%EXE_NAME%.exe" (
    echo.
    echo [X] Build completed, but executable was not found:
    echo %OUTPUT_DIR%\%EXE_NAME%.exe
    echo.
    pause
    exit /b 1
)

echo.
echo [+] Build completed successfully.
echo [+] Executable created:
echo %OUTPUT_DIR%\%EXE_NAME%.exe
echo.
pause
exit /b 0