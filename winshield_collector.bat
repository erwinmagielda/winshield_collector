@echo off
setlocal

title WinShield+ Collector

REM ------------------------------------------------------------
REM WinShield+ Collector Launcher
REM ------------------------------------------------------------
REM Runs the portable collector executable and writes scan JSON to:
REM     data\runtime   - latest scan workspace
REM     data\collected - persistent scan archive
REM ------------------------------------------------------------

cd /d "%~dp0"

set "APP_NAME=WinShield+ Collector"
set "EXE_PATH=src\core\winshield_collector.exe"
set "PY_PATH=src\core\winshield_collector.py"
set "POWERSHELL_DIR=src\powershell"
set "RUNTIME_DIR=data\runtime"
set "COLLECTED_DIR=data\collected"

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
REM ADMIN ELEVATION
REM ------------------------------------------------------------

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges are required.
    echo [*] Requesting elevation...
    echo.

    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"

    exit /b
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
REM MSRC POWERSHELL MODULE CHECK
REM ------------------------------------------------------------

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (Get-Module -ListAvailable -Name MsrcSecurityUpdates) { exit 0 } else { exit 1 }" >nul 2>&1

if %errorlevel% neq 0 (
    echo [!] Required PowerShell module is missing:
    echo     MsrcSecurityUpdates
    echo.
    echo This module is required to query Microsoft Security Response Center data.
    echo.
    choice /C YN /M "Install MsrcSecurityUpdates for the current user now?"

    if errorlevel 2 (
        echo.
        echo [X] Dependency installation declined.
        echo.
        echo Install it manually with:
        echo powershell -NoProfile -Command "Install-Module MsrcSecurityUpdates -Scope CurrentUser"
        echo.
        pause
        exit /b 1
    )

    echo.
    echo [*] Installing MsrcSecurityUpdates...
    echo.

    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue; Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force; Install-Module MsrcSecurityUpdates -Scope CurrentUser -Force -AllowClobber"

    if %errorlevel% neq 0 (
        echo.
        echo [X] Failed to install MsrcSecurityUpdates.
        echo.
        echo Install it manually with:
        echo powershell -NoProfile -Command "Install-Module MsrcSecurityUpdates -Scope CurrentUser"
        echo.
        pause
        exit /b 1
    )

    echo.
    echo [+] MsrcSecurityUpdates installed successfully.
    echo.
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
REM DATA DIRECTORIES
REM ------------------------------------------------------------

if not exist "%RUNTIME_DIR%" (
    mkdir "%RUNTIME_DIR%" >nul 2>&1
)

if not exist "%COLLECTED_DIR%" (
    mkdir "%COLLECTED_DIR%" >nul 2>&1
)

REM ------------------------------------------------------------
REM COLLECTOR EXECUTION - EXE FIRST
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
    echo [+] Runtime JSON saved in: %RUNTIME_DIR%
    echo [+] Archived copy saved in: %COLLECTED_DIR%
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
    echo [+] Runtime JSON saved in: %RUNTIME_DIR%
    echo [+] Archived copy saved in: %COLLECTED_DIR%
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