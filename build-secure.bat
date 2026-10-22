@echo off
rem ColdPunk: firmware for a device with Secure Boot V2 and flash encryption
rem (release mode). Needs the keys from make-keys.bat.
rem
rem   build-secure.bat [release|debug|hid]
rem
rem Builds the firmware as build.bat does and a bootloader with ESP-IDF 5.5.5
rem (secure boot + flash encryption, tools\bootloader\sdkconfig.secure), signs
rem both with keys\secure_boot_signing_key.pem and encrypts copies with
rem keys\flash_encryption_key.bin. The result,
rem firmware\ColdPunk-<version>-<board>[-debug|-hid]-secure\, holds:
rem
rem   first\    signed, not encrypted: for secure-first-flash, which burns the
rem             flash encryption key into the chip and writes these; on that
rem             first start the bootloader turns on secure boot and flash
rem             encryption itself (irreversible)
rem   update\   signed and encrypted: for flash.bat / flash.sh on a device
rem             that is already secured
rem
rem The keys never go into the firmware folder. Downloads as
rem build-idf-bootloader.bat (ESP-IDF etc., about 3 GB once).
setlocal EnableExtensions

set "PAUSE_AT_END="
echo %CMDCMDLINE% | findstr /i /c:" /c " >nul && set "PAUSE_AT_END=1"

cd /d "%~dp0"
set "ROOT=%CD%"
set "LIB=%ROOT%\tools\build\lib.bat"
call "%LIB%" :init build-secure.bat %1 || goto :fail
call "%LIB%" :keys_dir
if not exist "%SB_KEY%" goto :nokeys
if not exist "%FE_KEY%" goto :nokeys

call "%LIB%" :arduino_cli || goto :fail
call "%LIB%" :esptool || goto :fail
call "%LIB%" :commit
call "%LIB%" :board_version || goto :fail
set "NAME=ColdPunk-%VERSION%-%BOARD%%SUFFIX%-secure"
echo Building %NAME% (profile %PROFILE%)
call "%LIB%" :arduino_build || goto :fail
call "%LIB%" :idf_bootloader secure || goto :fail

set "W=%TD%\secure\%PROFILE%"
if exist "%W%" rmdir /s /q "%W%"
mkdir "%W%" || goto :fail

rem ---- the app image, padded for the signature -------------------------------
rem The same elf2image call as the Arduino recipe, plus --secure-pad-v2.
rem Checked first without the padding: it must give exactly Arduino's image.
set "IMG_ARGS=--chip esp32s3 elf2image --flash-mode dio --flash-freq 80m --flash-size 16MB --elf-sha256-offset 0xb0"
"%ESPTOOL%" %IMG_ARGS% -o "%W%\app_check.bin" "%BUILD%\ColdPunk.ino.elf" >nul || goto :fail
fc /b "%W%\app_check.bin" "%BUILD%\ColdPunk.ino.bin" >nul || (
    echo The app image does not match the Arduino build ^(flash options changed? see IMG_ARGS^).
    goto :fail
)
"%ESPTOOL%" %IMG_ARGS% --secure-pad-v2 -o "%W%\app_padded.bin" "%BUILD%\ColdPunk.ino.elf" >nul || goto :fail

rem ---- signing -------------------------------------------------------------
"%ESPSECURE%" sign-data --version 2 --keyfile "%SB_KEY%" --output "%W%\bootloader.bin" "%BL_BIN%" >nul || goto :fail
"%ESPSECURE%" sign-data --version 2 --keyfile "%SB_KEY%" --output "%W%\coldpunk.bin" "%W%\app_padded.bin" >nul || goto :fail
for %%F in (bootloader.bin coldpunk.bin) do (
    "%ESPSECURE%" verify-signature --version 2 --keyfile "%SB_KEY%" "%W%\%%F" >nul || (
        echo Signature check of %%F failed.
        goto :fail
    )
)
for %%A in ("%W%\bootloader.bin") do set "BL_SIZE=%%~zA"
if %BL_SIZE% GTR 32768 (
    echo The signed bootloader is %BL_SIZE% bytes; it must fit below the partition table ^(32768^).
    goto :fail
)
copy /y "%BUILD%\ColdPunk.ino.partitions.bin" "%W%\partitions.bin" >nul || goto :fail
copy /y "%BUILD%\boot_app0.bin"               "%W%\boot_app0.bin"  >nul || goto :fail

rem ---- the firmware folder ----------------------------------------------------
call "%LIB%" :out "%NAME%" || goto :fail
mkdir "%OUT%\first" || goto :fail
mkdir "%OUT%\update" || goto :fail
for %%F in (bootloader.bin partitions.bin boot_app0.bin coldpunk.bin) do (
    copy /y "%W%\%%F" "%OUT%\first\%%F" >nul || goto :fail
)
call :enc 0x0     bootloader.bin || goto :fail
call :enc 0x8000  partitions.bin || goto :fail
call :enc 0xe000  boot_app0.bin  || goto :fail
call :enc 0x10000 coldpunk.bin   || goto :fail

copy /y "%ESPTOOL%"        "%OUT%\esptool.exe"  >nul || goto :fail
copy /y "%ESPEFUSE%"       "%OUT%\espefuse.exe" >nul || goto :fail
copy /y "%ET_DIR%\LICENSE" "%OUT%\esptool-LICENSE.txt" >nul
for %%F in (flash.bat flash.sh secure-first-flash.bat secure-first-flash.sh efuse-state.ps1 devices.ps1 README.txt) do (
    copy /y "tools\flash\secure\%%F" "%OUT%\" >nul || goto :fail
)
rem Which keys this folder belongs to: the digest of the signing key's public
rem part (what the chip will hold) and a hash of the encryption key (only to
rem recognise the right key file; it reveals nothing about the key).
"%ESPSECURE%" digest-sbv2-public-key --keyfile "%SB_KEY%" --output "%W%\digest.bin" >nul || goto :fail
call "%LIB%" :hex "%W%\digest.bin" || goto :fail
> "%OUT%\secure_boot_key_digest.txt" echo %HEX%
call "%LIB%" :sha256 "%FE_KEY%" || goto :fail
> "%OUT%\flash_encryption_key_sha256.txt" echo %SHA%
rem The bootloader in this folder (signed, before encryption) and the version:
rem secure-first-flash records them in keys\devices.txt, flash.bat compares.
call "%LIB%" :sha256 "%OUT%\first\bootloader.bin" || goto :fail
> "%OUT%\bootloader_sha256.txt" echo %SHA%
> "%OUT%\version.txt" echo %VERSION%
call "%LIB%" :sums "%OUT%" first/bootloader.bin first/partitions.bin first/boot_app0.bin first/coldpunk.bin update/bootloader.bin update/partitions.bin update/boot_app0.bin update/coldpunk.bin || goto :fail

call "%LIB%" :unmap
echo.
echo Done: firmware\%NAME%
echo   signed bootloader: %BL_SIZE% bytes; key digest %HEX%
echo First time (irreversible): firmware\%NAME%\secure-first-flash.bat [COMx]
echo Updates of a secured device: firmware\%NAME%\flash.bat [COMx]   (firmware only; "full" also writes the bootloader)
if defined PAUSE_AT_END pause
exit /b 0

rem ---- call :enc ADDRESS FILE: update\FILE, encrypted for that address -------
:enc
"%ESPSECURE%" encrypt-flash-data --aes-xts --keyfile "%FE_KEY%" --address %1 --output "%OUT%\update\%~2" "%W%\%~2" >nul
exit /b %errorlevel%

:nokeys
echo No keys in %KEYS% - run make-keys.bat once first.
:fail
call "%LIB%" :unmap
echo.
echo Build failed.
if defined PAUSE_AT_END pause
exit /b 1
