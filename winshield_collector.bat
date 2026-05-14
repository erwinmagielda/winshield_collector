@echo off
setlocal

title WinShield Collector

REM ------------------------------------------------------------
REM WinShield Collector Launcher
REM ------------------------------------------------------------
REM Runs the portable collector executable and writes JSON output
REM into the output folder.
REM ------------------------------------------------------------

cd /d "%~dp0"

set "APP_NAME=WinShield Collector"
set "EXE_PATH=src\core\winshield_collector.exe"
set "PY_PATH=src\core\winshield_collector.py"
set "POWERSHELL_DIR=src\powershell"
set "OUTPUT_DIR=output"

echo.
echo ============================================================
echo  WinShield+ Collector
echo ============================================================
echo.

REM ------------------------------------------------------------
REM WINDOWS CHECK
REM ------------------------------------------------------------

if /i not "%OS%"=="Windows_NT" (
    echo [X] This collector must be run on Windows.
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM ADMIN CHECK
REM ------------------------------------------------------------

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Administrator privileges are required.
    echo.
    echo Right-click winshield_collector.bat and choose:
    echo Run as administrator
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM POWERSHELL CHECK
REM ------------------------------------------------------------

where powershell.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] PowerShell was not found on this system.
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM REQUIRED FILE CHECKS
REM ------------------------------------------------------------

if not exist "%POWERSHELL_DIR%\winshield_baseline.ps1" (
    echo [X] Missing PowerShell script:
    echo %POWERSHELL_DIR%\winshield_baseline.ps1
    echo.
    pause
    exit /b 1
)

if not exist "%POWERSHELL_DIR%\winshield_inventory.ps1" (
    echo [X] Missing PowerShell script:
    echo %POWERSHELL_DIR%\winshield_inventory.ps1
    echo.
    pause
    exit /b 1
)

if not exist "%POWERSHELL_DIR%\winshield_adapter.ps1" (
    echo [X] Missing PowerShell script:
    echo %POWERSHELL_DIR%\winshield_adapter.ps1
    echo.
    pause
    exit /b 1
)

REM ------------------------------------------------------------
REM OUTPUT DIRECTORY
REM ------------------------------------------------------------

if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%" >nul 2>&1
)

REM ------------------------------------------------------------
REM COLLECTOR EXECUTION
REM ------------------------------------------------------------

if exist "%EXE_PATH%" (
    echo [*] Running collector executable...
    echo.

    "%EXE_PATH%"

    if %errorlevel% neq 0 (
        echo.
        echo [X] Collector failed.
        echo.
        pause
        exit /b 1
    )

    echo.
    echo [+] Scan completed successfully.
    echo [+] JSON output saved in: %OUTPUT_DIR%
    echo.
    pause
    exit /b 0
)

REM ------------------------------------------------------------
REM SOURCE FALLBACK
REM ------------------------------------------------------------

if exist "%PY_PATH%" (
    where python.exe >nul 2>&1
    if %errorlevel% neq 0 (
        echo [X] Collector executable was not found:
        echo %EXE_PATH%
        echo.
        echo [X] Python fallback is unavailable because Python is not installed.
        echo.
        echo Build the executable first using:
        echo build\build_exe.bat
        echo.
        pause
        exit /b 1
    )

    echo [!] Collector executable was not found.
    echo [*] Running readable Python source fallback...
    echo.

    python "%PY_PATH%"

    if %errorlevel% neq 0 (
        echo.
        echo [X] Collector failed.
        echo.
        pause
        exit /b 1
    )

    echo.
    echo [+] Scan completed successfully.
    echo [+] JSON output saved in: %OUTPUT_DIR%
    echo.
    pause
    exit /b 0
)

REM ------------------------------------------------------------
REM NOTHING RUNNABLE FOUND
REM ------------------------------------------------------------

echo [X] No runnable collector found.
echo.
echo Expected executable:
echo %EXE_PATH%
echo.
echo Expected Python fallback:
echo %PY_PATH%
echo.
pause
exit /b 1