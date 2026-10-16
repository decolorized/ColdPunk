@echo off
rem ColdPunk: creates the two keys build-secure.bat needs, once.
rem
rem   keys\secure_boot_signing_key.pem   RSA-3072, signs the bootloader and the
rem                                      firmware (Secure Boot V2)
rem   keys\flash_encryption_key.bin      256-bit XTS-AES-128 key, encrypts the
rem                                      images for updates; secure-first-flash
rem                                      burns it into the chip
rem
rem The folder can be set with COLDPUNK_KEYS. The script never overwrites a
rem key: if either file exists it stops and changes nothing. A device secured
rem with these keys accepts firmware ONLY signed and encrypted with them - lose
rem them and the device can never be updated again; leak them and anyone can
rem build firmware the device will run. Keep copies offline.
setlocal EnableExtensions

set "PAUSE_AT_END="
echo %CMDCMDLINE% | findstr /i /c:" /c " >nul && set "PAUSE_AT_END=1"

cd /d "%~dp0"
set "ROOT=%CD%"
set "LIB=%ROOT%\tools\build\lib.bat"
call "%LIB%" :init make-keys.bat release || goto :fail
call "%LIB%" :keys_dir

for %%K in ("%SB_KEY%" "%FE_KEY%") do (
    if exist "%%~K" (
        echo %%~K already exists - nothing was changed.
        echo The keys are made once. To start over with new keys ^(only for a
        echo device that was never secured with the old ones^) move the old
        echo files away yourself.
        goto :fail
    )
)

call "%LIB%" :esptool || goto :fail
if not exist "%KEYS%" mkdir "%KEYS%" || goto :fail
rem Only the current user may read the folder (best effort).
icacls "%KEYS%" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" >nul 2>nul
set "TMPK=%KEYS%\.new"
if exist "%TMPK%" rmdir /s /q "%TMPK%"
mkdir "%TMPK%" || goto :fail
"%ESPSECURE%" generate-signing-key --version 2 --scheme rsa3072 "%TMPK%\secure_boot_signing_key.pem" >nul || goto :fail
"%ESPSECURE%" generate-flash-encryption-key --keylen 256 "%TMPK%\flash_encryption_key.bin" >nul || goto :fail
"%ESPSECURE%" digest-sbv2-public-key --keyfile "%TMPK%\secure_boot_signing_key.pem" --output "%TMPK%\digest.bin" >nul || goto :fail
call "%LIB%" :hex "%TMPK%\digest.bin" || goto :fail
del "%TMPK%\digest.bin"
rem Moved in only when both were made: never half a set.
move "%TMPK%\secure_boot_signing_key.pem" "%SB_KEY%" >nul || goto :fail
move "%TMPK%\flash_encryption_key.bin" "%FE_KEY%" >nul || goto :fail
rmdir "%TMPK%"
attrib +r "%SB_KEY%"
attrib +r "%FE_KEY%"
> "%KEYS%\secure_boot_key_digest.txt" echo %HEX%

call "%LIB%" :unmap
echo.
echo Keys created in %KEYS%:
echo   secure_boot_signing_key.pem   (public key digest %HEX%)
echo   flash_encryption_key.bin
echo.
echo Back them up NOW to two offline places (e.g. two USB sticks).
echo Without them a secured device can never be updated.
if defined PAUSE_AT_END pause
exit /b 0

:fail
call "%LIB%" :unmap
echo.
echo make-keys failed or stopped.
if defined PAUSE_AT_END pause
exit /b 1
