@echo off
rem Updates a SECURED ColdPunk device (secure boot + flash encryption already
rem on) with the signed and encrypted images in update\ (Windows).
rem
rem   flash.bat                 asks for the port (Enter: esptool finds it)
rem   flash.bat COM5            this port
rem   flash.bat COM5 460800     a lower speed, if 921600 fails
rem
rem The chip is in Secure Download Mode: esptool runs without its stub, cannot
rem read the flash and cannot verify what it wrote. The wallets (NVS) and the
rem storage partition are not touched. For a device that is NOT secured yet
rem use secure-first-flash.bat: these encrypted images do not boot there.
setlocal
cd /d "%~dp0"

set "ESPTOOL="
if exist "esptool.exe" set "ESPTOOL=esptool.exe"
if not defined ESPTOOL (
    where esptool >nul 2>nul && set "ESPTOOL=esptool"
)
if not defined ESPTOOL (
    echo esptool.exe is missing from this folder and esptool is not in PATH.
    goto :fail
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$bad = 0; foreach ($l in Get-Content 'SHA256SUMS.txt') { if ($l -match '^([0-9a-f]{64})\s+\*?(.+)$') { $f = $Matches[2]; $want = $Matches[1]; if (-not (Test-Path -LiteralPath $f)) { Write-Host ('missing: ' + $f); $bad = 1 } elseif ((Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLower() -ne $want) { Write-Host ('damaged: ' + $f); $bad = 1 } } }; exit $bad"
if errorlevel 1 (
    echo The firmware files do not match SHA256SUMS.txt - not flashing.
    goto :fail
)

set "PORT=%~1"
if "%PORT%"=="" (
    echo Port of the board, e.g. COM5 ^(Device Manager -^> Ports^).
    set /p "PORT=Port, or Enter to let esptool find it: "
)
set "PORT_ARGS="
if not "%PORT%"=="" set "PORT_ARGS=--port %PORT%"
set "BAUD=%~2"
if "%BAUD%"=="" set "BAUD=921600"

"%ESPTOOL%" --chip esp32s3 %PORT_ARGS% --baud %BAUD% --no-stub --before default-reset --after hard-reset write-flash -z --flash-mode keep --flash-freq keep --flash-size keep 0x0 update\bootloader.bin 0x8000 update\partitions.bin 0xe000 update\boot_app0.bin 0x10000 update\coldpunk.bin
if errorlevel 1 goto :fail

echo.
echo Done. The board restarts with the new firmware.
pause
exit /b 0

:fail
echo.
echo Flashing failed.
pause
exit /b 1
