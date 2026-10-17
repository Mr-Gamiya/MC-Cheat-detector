@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "POWERSHELL_EXE=powershell.exe"
where pwsh.exe >nul 2>nul
if not errorlevel 1 set "POWERSHELL_EXE=pwsh.exe"
if /i "%POWERSHELL_EXE%"=="pwsh.exe" (
    pwsh.exe -NoLogo -NoProfile -Command "exit 0" >nul 2>nul
    if errorlevel 1 set "POWERSHELL_EXE=powershell.exe"
)

echo Minecraft Cheat Scanner v7.2 - unified automatic scan
echo This scan checks Minecraft files offline and attempts runtime checks automatically when Minecraft is running.
echo Script folder: "%SCRIPT_DIR%"
"%POWERSHELL_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scan-cheats.ps1" -OutputDirectory "%SCRIPT_DIR%Reports"
set "SCAN_EXIT=%ERRORLEVEL%"

echo.
if "%SCAN_EXIT%"=="0" (
    echo Scanner completed. TXT, HTML, and JSON reports are listed above.
) else (
    echo Scanner exited with code %SCAN_EXIT%. Review the error shown above and scanner.log in reports or the TEMP fallback folder.
)
echo.
set /p "CONTINUE=Press Enter to close this window..."
exit /b %SCAN_EXIT%


