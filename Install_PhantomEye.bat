@echo off
:: =============================================================================
::  PhantomEye v2.1.0 — Installer
::  Red Parrot Accounting Ltd
::
::  What this does:
::    1. Checks Python is installed
::    2. Creates log, feeds, and gui directories
::    3. Copies all modules to permanent location
::    4. Downloads threat feeds
::    5. Creates scheduled tasks (runs as current user, NOT SYSTEM)
::    6. Launches the GUI
:: =============================================================================

title PhantomEye v2.1.0 — Installer

echo.
echo  ============================================================
echo   PhantomEye v2.1.0 — Threat Intelligence Platform
echo   Red Parrot Accounting Ltd
echo  ============================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Please right-click and "Run as administrator"
    pause & exit /b 1
)

echo  [1/5] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python not found. Download from https://www.python.org/downloads/
    echo  Tick "Add Python to PATH" during install.
    pause & exit /b 1
)
python --version
echo  Python OK.
echo.

echo  [2/5] PhantomEye uses only Python built-in libraries. No pip required.
echo.

echo  [3/5] Creating directories...
if not exist "C:\SecurityLogs\PhantomEye\feeds" mkdir "C:\SecurityLogs\PhantomEye\feeds"
if not exist "C:\SecurityLogs\PhantomEye\gui"   mkdir "C:\SecurityLogs\PhantomEye\gui"
echo  Directories ready.
echo.

echo  [4/5] Copying PhantomEye modules...
for %%f in (main.py config.py logger.py database.py utils.py feeds.py lookup.py alerts.py scanner.py geolocation.py reports.py monitor.py custom_feeds.py) do (
    copy /Y "%~dp0%%f" "C:\SecurityLogs\PhantomEye\%%f" >nul
    if %errorlevel% neq 0 (
        echo  [ERROR] Could not copy %%f
        pause & exit /b 1
    )
)
:: Copy gui package
copy /Y "%~dp0gui\__init__.py"      "C:\SecurityLogs\PhantomEye\gui\__init__.py"      >nul
copy /Y "%~dp0gui\app.py"           "C:\SecurityLogs\PhantomEye\gui\app.py"           >nul
copy /Y "%~dp0gui\theme.py"         "C:\SecurityLogs\PhantomEye\gui\theme.py"         >nul
copy /Y "%~dp0gui\tab_dashboard.py" "C:\SecurityLogs\PhantomEye\gui\tab_dashboard.py" >nul
copy /Y "%~dp0gui\tab_lookup.py"    "C:\SecurityLogs\PhantomEye\gui\tab_lookup.py"    >nul
copy /Y "%~dp0gui\tab_email.py"     "C:\SecurityLogs\PhantomEye\gui\tab_email.py"     >nul
copy /Y "%~dp0gui\tab_alerts.py"    "C:\SecurityLogs\PhantomEye\gui\tab_alerts.py"    >nul
copy /Y "%~dp0gui\tab_feeds.py"     "C:\SecurityLogs\PhantomEye\gui\tab_feeds.py"     >nul
copy /Y "%~dp0gui\tab_monitor.py"  "C:\SecurityLogs\PhantomEye\gui\tab_monitor.py"  >nul
copy /Y "%~dp0gui\tooltip.py"      "C:\SecurityLogs\PhantomEye\gui\tooltip.py"      >nul
echo  All modules copied.
echo.

echo  [5/5] Creating scheduled tasks (running as %USERNAME%, not SYSTEM)...
schtasks /delete /tn "PhantomEye Feed Update"  /f >nul 2>&1
schtasks /delete /tn "PhantomEye Morning Scan" /f >nul 2>&1

:: Feed update every 6 hours — runs as current user
schtasks /create ^
    /tn "PhantomEye Feed Update" ^
    /tr "python C:\SecurityLogs\PhantomEye\main.py --update-feeds" ^
    /sc HOURLY /mo 6 ^
    /ru "%USERNAME%" /f >nul
if %errorlevel% equ 0 (
    echo  Task created: Feed update every 6 hours
) else (
    echo  [WARNING] Could not create feed update task. Run --update-feeds manually.
)

:: Morning scan at 6 AM daily — runs as current user
schtasks /create ^
    /tn "PhantomEye Morning Scan" ^
    /tr "python C:\SecurityLogs\PhantomEye\main.py --scan" ^
    /sc DAILY /st 06:00 ^
    /ru "%USERNAME%" /f >nul
if %errorlevel% equ 0 (
    echo  Task created: Network scan daily at 6:00 AM
) else (
    echo  [WARNING] Could not create morning scan task. Run --scan manually.
)
echo.

echo  ============================================================
echo   Downloading threat feeds (requires internet, 1-2 minutes)...
echo  ============================================================
echo.
python "C:\SecurityLogs\PhantomEye\main.py" --update-feeds
echo.

echo  ============================================================
echo   INSTALLATION COMPLETE
echo   Red Parrot Accounting Ltd
echo  ============================================================
echo.
echo   Launching PhantomEye GUI...
echo.
start "" python "C:\SecurityLogs\PhantomEye\main.py" --gui
echo.
echo   To open PhantomEye at any time:
echo     python C:\SecurityLogs\PhantomEye\main.py --gui
echo.
echo   IMPORTANT — Email alerts (optional):
echo   If you enable EMAIL_ENABLED = True in config.py, set your password
echo   as an environment variable (never put it in the script):
echo     PowerShell (run as admin):
echo     [System.Environment]::SetEnvironmentVariable(
echo       'PHANTOMEYE_EMAIL_PASSWORD','your_password','Machine')
echo.
echo   Log: C:\SecurityLogs\PhantomEye\phantom_eye.log
echo.
pause
