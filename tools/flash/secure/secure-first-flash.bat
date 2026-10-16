@echo off
rem Turns on Secure Boot V2 and flash encryption on a ColdPunk device
rem (Windows). IRREVERSIBLE: afterwards the chip runs only firmware signed
rem with your key, and accepts only images encrypted with your key.
rem
rem   secure-first-flash.bat [COMx] [baud]
rem
rem What it does:
rem   1. checks the images (SHA256SUMS.txt) and that the flash encryption key
rem      file is the one this folder was built with
rem      (..\..\keys\flash_encryption_key.bin, or COLDPUNK_KEYS);
rem   2. reads the chip's eFuses and stops when: secure boot or flash
rem      encryption is already on (use flash.bat), the wallet's own eFuse key
rem      (HMAC_UP) is missing (start the normal firmware once and finish the
rem      first start - it cannot be burned afterwards), or fewer than two key
rem      blocks are free;
rem   3. after you type SECURE, burns the flash encryption key into the lowest
rem      free key block (espefuse asks once more: type BURN);
rem   4. writes the signed images from first\.
rem On that start the bootloader burns the digest of your signing key, revokes
rem the other two digest slots, encrypts the bootloader, partition table,
rem otadata and firmware in place and locks the chip down (JTAG off, Secure
rem Download Mode). This takes up to a minute with a dark screen: do not cut
rem the power. The wallets (NVS, storage) are kept.
setlocal EnableExtensions
cd /d "%~dp0"

if not exist "esptool.exe"  ( echo esptool.exe is missing from this folder. & goto :fail )
if not exist "espefuse.exe" ( echo espefuse.exe is missing from this folder. & goto :fail )

powershell -NoProfile -ExecutionPolicy Bypass -Command "$bad = 0; foreach ($l in Get-Content 'SHA256SUMS.txt') { if ($l -match '^([0-9a-f]{64})\s+\*?(.+)$') { $f = $Matches[2]; $want = $Matches[1]; if (-not (Test-Path -LiteralPath $f)) { Write-Host ('missing: ' + $f); $bad = 1 } elseif ((Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLower() -ne $want) { Write-Host ('damaged: ' + $f); $bad = 1 } } }; exit $bad"
if errorlevel 1 (
    echo The firmware files do not match SHA256SUMS.txt - not flashing.
    goto :fail
)

if defined COLDPUNK_KEYS (set "KEYS=%COLDPUNK_KEYS%") else (set "KEYS=%~dp0..\..\keys")
set "FE_KEY=%KEYS%\flash_encryption_key.bin"
if not exist "%FE_KEY%" (
    echo No %FE_KEY% ^(set COLDPUNK_KEYS to the keys folder^).
    goto :fail
)
set "HAVE="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%FE_KEY%" SHA256') do if not defined HAVE set "HAVE=%%H"
set "HAVE=%HAVE: =%"
set /p WANT=<flash_encryption_key_sha256.txt
if /i not "%HAVE%"=="%WANT%" (
    echo %FE_KEY% is not the key this folder was built with.
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

rem ---- the chip's state --------------------------------------------------------
set "STATE=%TEMP%\coldpunk-efuse-%RANDOM%.json"
espefuse.exe --chip esp32s3 %PORT_ARGS% summary --format json --file "%STATE%" >nul
if errorlevel 1 (
    echo Cannot read the eFuses ^(port? BOOT button? see README.txt^).
    goto :fail
)
for /f "tokens=1,* delims==" %%A in ('powershell -NoProfile -ExecutionPolicy Bypass -File efuse-state.ps1 "%STATE%"') do set "EF_%%A=%%B"
del "%STATE%" 2>nul
if not defined EF_SB_EN (
    echo Could not read the eFuse summary.
    goto :fail
)
if /i not "%EF_SB_EN%"=="false" goto :already
if /i not "%EF_CRYPT%"=="Disable" goto :already
if not defined EF_HMAC goto :nohmac

set "NFREE=0"
set "FIRST_FREE="
for %%B in (%EF_FREE%) do (
    set /a NFREE+=1
    if not defined FIRST_FREE set "FIRST_FREE=%%B"
)
set "BURN_BLOCK="
if defined EF_XTS (
    echo A flash encryption key is already burned in BLOCK_KEY%EF_XTS% ^(an interrupted
    echo earlier run?^). It is used as it is; if it is not your key, the update
    echo images will not boot later.
    if %NFREE% LSS 1 ( echo No free key block left for the secure boot digest. & goto :fail )
) else (
    if %NFREE% LSS 2 ( echo Need two free key blocks ^(flash encryption key, secure boot digest^); free: %EF_FREE% & goto :fail )
    set "BURN_BLOCK=%FIRST_FREE%"
)

rem ---- confirm -------------------------------------------------------------------
set /p DIGEST=<secure_boot_key_digest.txt
echo.
echo   Wallet eFuse key:          BLOCK_KEY%EF_HMAC% (HMAC_UP) - kept
if defined BURN_BLOCK (
    echo   Flash encryption key:      BLOCK_KEY%BURN_BLOCK% ^(burned now^)
) else (
    echo   Flash encryption key:      already burned
)
echo   Secure boot key digest:    %DIGEST%
echo                              (burned by the bootloader on the first start)
echo.
echo   THIS CANNOT BE UNDONE. Afterwards the device:
echo     * runs only firmware signed with keys\secure_boot_signing_key.pem
echo     * takes updates only as images encrypted with keys\flash_encryption_key.bin
echo       (build-secure.bat, flash.bat in its folder)
echo     * has JTAG off and the ROM download mode in its secure variant
echo   Lose the keys and the device can never be updated again.
echo   Have the seed words of every wallet on paper before you go on.
echo.
set "ANSWER="
set /p "ANSWER=Type SECURE to continue: "
if not "%ANSWER%"=="SECURE" (
    echo Cancelled, nothing was changed.
    goto :fail
)

rem ---- burn the key, write the images ------------------------------------------
if not defined BURN_BLOCK goto :write
espefuse.exe --chip esp32s3 %PORT_ARGS% burn-key BLOCK_KEY%BURN_BLOCK% "%FE_KEY%" XTS_AES_128_KEY
if errorlevel 1 (
    echo Burning the key failed or was cancelled - nothing was written to the flash.
    goto :fail
)
:write
esptool.exe --chip esp32s3 %PORT_ARGS% --baud %BAUD% --before default-reset --after hard-reset write-flash -z --flash-mode keep --flash-freq keep --flash-size keep 0x0 first\bootloader.bin 0x8000 first\partitions.bin 0xe000 first\boot_app0.bin 0x10000 first\coldpunk.bin
if errorlevel 1 (
    echo Writing failed. Run this script again ^(the key is kept^), or flash a normal build to undo.
    goto :fail
)

echo.
echo Written. The board restarts and the bootloader now turns on secure boot and
echo flash encryption: the screen stays dark for up to a minute. DO NOT unplug it.
echo Then the device starts as usual (the game screen).
echo.
echo From now on update it only with flash.bat from a build-secure folder.
pause
exit /b 0

:already
echo Secure boot or flash encryption is already on - use flash.bat for updates.
goto :fail

:nohmac
echo The wallet's eFuse key (HMAC_UP) is not burned yet. Flash the normal
echo firmware, finish its first start (it burns the key), then run this again:
echo after this script the chip can no longer read-protect a new key.
goto :fail

:fail
echo.
echo Nothing more was done.
pause
exit /b 1
