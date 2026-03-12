@echo off
:: =============================================================================
::  PhantomEye v1.2 — Uninstaller
::  Red Parrot Accounting Ltd
:: =============================================================================

title PhantomEye v1.2 — Uninstaller

echo.
echo  ============================================================
echo   PhantomEye v1.2 — Uninstaller
echo   Red Parrot Accounting Ltd
echo  ============================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Must be run as Administrator.
    pause & exit /b 1
)

echo  Removing scheduled tasks...
schtasks /delete /tn "PhantomEye Feed Update"  /f >nul 2>&1
schtasks /delete /tn "PhantomEye Morning Scan" /f >nul 2>&1
echo  Scheduled tasks removed.

echo.
set /p KEEP_LOGS="Keep log files, database, and reports? (Y/N): "
if /i "%KEEP_LOGS%"=="N" (
    echo  Removing C:\SecurityLogs\PhantomEye\...
    rmdir /s /q "C:\SecurityLogs\PhantomEye" >nul 2>&1
    echo  Removed.
) else (
    echo  Logs and database kept at: C:\SecurityLogs\PhantomEye\
)

echo.
echo  PhantomEye v1.2 has been uninstalled.
echo.
pause
