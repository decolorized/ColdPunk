@echo off
rem Updates a SECURED ColdPunk device (secure boot + flash encryption already
rem on) with the signed and encrypted images in update\ (Windows).
rem
rem   flash.bat                   the firmware only; asks for the port
rem   flash.bat COM5              this port
rem   flash.bat COM5 460800       a lower speed, if 921600 fails
rem   flash.bat full [COM5] [baud]   also the bootloader, partition table and
rem                               otadata - only when this folder's bootloader
rem                               must replace the one on the device
rem
rem Before writing it checks, and stops on any mismatch:
rem   * the images against SHA256SUMS.txt;
rem   * that the keys this folder was built with are YOUR keys: the signing key
rem     digest against keys\secure_boot_key_digest.txt and the flash
rem     encryption key file against flash_encryption_key_sha256.txt
rem     (keys folder: ..\..\keys, or COLDPUNK_KEYS);
rem   * keys\devices.txt (written by secure-first-flash): which bootloader the
rem     device got, so "full" is suggested only when it changed;
rem   * you confirm that the digest shown matches Settings -> About -> "SB key".
rem The chip is in Secure Download Mode: esptool runs without its stub, cannot
rem read the flash and cannot tell an encrypted image from a plain one, so it
rem refuses to write unless forced; the checks above are why --force is safe
rem here. The wallets (NVS) and the storage partition are never touched.
setlocal EnableExtensions
cd /d "%~dp0"

set "FULL=0"
set "PORT="
set "BAUD="
for %%A in (%*) do (
    if /i "%%~A"=="full" (
        set "FULL=1"
    ) else (
        if not defined PORT (set "PORT=%%~A") else (set "BAUD=%%~A")
    )
)
if not defined BAUD set "BAUD=921600"

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

rem ---- the keys ------------------------------------------------------------
if defined COLDPUNK_KEYS (set "KEYS=%COLDPUNK_KEYS%") else (set "KEYS=%~dp0..\..\keys")
set /p DIGEST=<secure_boot_key_digest.txt
set "DIGEST=%DIGEST: =%"
if not exist "%KEYS%\secure_boot_key_digest.txt" (
    echo No keys in %KEYS% ^(set COLDPUNK_KEYS to the keys folder of make-keys^).
    goto :fail
)
set /p KDIGEST=<"%KEYS%\secure_boot_key_digest.txt"
set "KDIGEST=%KDIGEST: =%"
if /i not "%KDIGEST%"=="%DIGEST%" (
    echo This folder is signed with a DIFFERENT key than %KEYS% - the device would not boot it.
    goto :fail
)
if not exist "%KEYS%\flash_encryption_key.bin" (
    echo No %KEYS%\flash_encryption_key.bin.
    goto :fail
)
set "HAVE="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%KEYS%\flash_encryption_key.bin" SHA256') do if not defined HAVE set "HAVE=%%H"
set "HAVE=%HAVE: =%"
set /p WANT=<flash_encryption_key_sha256.txt
set "WANT=%WANT: =%"
if /i not "%HAVE%"=="%WANT%" (
    echo This folder is encrypted with a DIFFERENT flash encryption key than %KEYS%.
    goto :fail
)

rem ---- the device registry -------------------------------------------------
set /p BLSHA=<bootloader_sha256.txt
set "BLSHA=%BLSHA: =%"
set "REG=%KEYS%\devices.txt"
set "KNOWN="
if exist "%REG%" (
    for /f "delims=" %%B in ('powershell -NoProfile -ExecutionPolicy Bypass -File devices.ps1 lookup "%REG%" %DIGEST%') do set "KNOWN=%%B"
)
if exist "%REG%" if not defined KNOWN echo keys\devices.txt lists no device secured with these keys.
if "%FULL%"=="0" if defined KNOWN if /i not "%KNOWN%"=="%BLSHA%" (
    echo Note: this folder's bootloader differs from the one recorded for your device.
    echo       Only the firmware is written; the bootloader on the device keeps working.
    echo       Run with "full" only if the new bootloader is needed.
)

rem ---- confirm ---------------------------------------------------------------
echo.
echo   Signing key digest: %DIGEST:~0,8%...%DIGEST:~56,8%
echo   On the device: Settings -^> About -^> "SB key" must show the same.
if "%FULL%"=="1" (
    echo   Writing: bootloader, partition table, otadata and firmware.
) else (
    echo   Writing: firmware only.
)
set "ANSWER="
set /p "ANSWER=Same digest on the device? Type y to write: "
if /i not "%ANSWER%"=="y" (
    echo Cancelled, nothing was written.
    goto :fail
)

if not defined PORT (
    echo Port of the board, e.g. COM5 ^(Device Manager -^> Ports^).
    set /p "PORT=Port, or Enter to let esptool find it: "
)
set "PORT_ARGS="
if defined PORT set "PORT_ARGS=--port %PORT%"

rem 0.3.6: a board without a USB-UART bridge is put into the ROM download
rem mode by hand: hold BOOT, plug in or press RESET, release BOOT. The chip
rem then already waits, and esptool must not reset it first - after "Flash
rem only with BOOT" (DIS_FORCE_DOWNLOAD) a reset from the host may not bring
rem it back into the download mode. So: talk to it as it is; only if nothing
rem answers, let esptool reset it the usual way (USB-UART auto-reset).
set "BEFORE=no-reset"
"%ESPTOOL%" --chip esp32s3 %PORT_ARGS% --no-stub --connect-attempts 2 --before no-reset --after no-reset get-security-info >nul 2>nul || set "BEFORE=default-reset"
if "%BEFORE%"=="default-reset" echo Not in the download mode yet: esptool resets the board ^(or hold BOOT and press RESET, then run this again^).

if "%FULL%"=="1" (
    set "IMAGES=0x0 update\bootloader.bin 0x8000 update\partitions.bin 0xe000 update\boot_app0.bin 0x10000 update\coldpunk.bin"
) else (
    set "IMAGES=0x10000 update\coldpunk.bin"
)
"%ESPTOOL%" --chip esp32s3 %PORT_ARGS% --baud %BAUD% --no-stub --before %BEFORE% --after hard-reset write-flash --force -z --flash-mode keep --flash-freq keep --flash-size keep %IMAGES%
if errorlevel 1 goto :fail

if "%FULL%"=="1" if exist "%REG%" powershell -NoProfile -ExecutionPolicy Bypass -File devices.ps1 set "%REG%" %DIGEST% %BLSHA%

echo.
echo Done. The board restarts with the new firmware.
pause
exit /b 0

:fail
echo.
echo Nothing was flashed.
pause
exit /b 1
