@echo off
rem Flashes the ColdPunk firmware in this folder (Windows).
rem
rem   flash.bat                 asks for the port (Enter: esptool finds it)
rem   flash.bat COM5            this port
rem   flash.bat COM5 460800     a lower speed, if 921600 fails
rem
rem The port is the board's USB-UART bridge (CH340 / CP210x, UART0), not the
rem native USB of the wallet; Device Manager -> Ports shows it. Only the
rem bootloader, the partition table and the program are written: the wallets
rem (NVS) and the storage partition are kept, exactly as with an upload from
rem the Arduino IDE.
rem
rem Uses esptool.exe from this folder, or esptool (v5) from PATH.
setlocal
cd /d "%~dp0"

set "ESPTOOL="
if exist "esptool.exe" set "ESPTOOL=esptool.exe"
if not defined ESPTOOL (
    where esptool >nul 2>nul && set "ESPTOOL=esptool"
)
if not defined ESPTOOL (
    echo esptool.exe is missing from this folder and esptool is not in PATH.
    echo Build on Windows with build.bat, or: pip install esptool
    goto :fail
)

rem The images must be the ones the build wrote.
if not exist "SHA256SUMS.txt" goto :sums_done
powershell -NoProfile -ExecutionPolicy Bypass -Command "$bad = 0; foreach ($l in Get-Content 'SHA256SUMS.txt') { if ($l -match '^([0-9a-f]{64})\s+\*?(.+)$') { $f = $Matches[2]; $want = $Matches[1]; if (-not (Test-Path -LiteralPath $f)) { Write-Host ('missing: ' + $f); $bad = 1 } elseif ((Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLower() -ne $want) { Write-Host ('damaged: ' + $f); $bad = 1 } } }; exit $bad"
if errorlevel 1 (
    echo The firmware files do not match SHA256SUMS.txt - not flashing.
    goto :fail
)
:sums_done

set "PORT=%~1"
if "%PORT%"=="" (
    echo Port of the board, e.g. COM5 ^(Device Manager -^> Ports^).
    set /p "PORT=Port, or Enter to let esptool find it: "
)
set "PORT_ARGS="
if not "%PORT%"=="" set "PORT_ARGS=--port %PORT%"
set "BAUD=%~2"
if "%BAUD%"=="" set "BAUD=921600"

"%ESPTOOL%" --chip esp32s3 %PORT_ARGS% --baud %BAUD% --before default-reset --after hard-reset write-flash -z --flash-mode keep --flash-freq keep --flash-size keep 0x0 bootloader.bin 0x8000 partitions.bin 0xe000 boot_app0.bin 0x10000 coldpunk.bin
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
