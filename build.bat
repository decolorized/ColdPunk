@echo off
rem ColdPunk: builds the firmware on Windows 10 / 11. Everything the build
rem needs is downloaded into toolchain\ next to this file - arduino-cli, the
rem ESP32 core with its compilers, the libraries and esptool - nothing is
rem installed into the system or the user profile. The first build downloads
rem about 1.5 GB; later builds reuse it.
rem
rem   build.bat            release build (sketch.yaml profile "coldpunk")
rem   build.bat debug      core log at Info level ("coldpunk-debug")
rem   build.bat hid        HID only, no serial transport ("coldpunk-hid")
rem
rem The board is the one selected in board_config.h. The result goes to
rem firmware\ColdPunk-<version>-<board>[-debug|-hid]\: the images, esptool.exe
rem and flash.bat / flash.sh, which flash the board without touching the
rem wallets.
rem
rem Uses curl, tar and certutil, which come with Windows 10 1803 and later.
setlocal EnableExtensions

rem Started by a double-click (cmd /c): keep the window open at the end.
set "PAUSE_AT_END="
echo %CMDCMDLINE% | findstr /i /c:" /c " >nul && set "PAUSE_AT_END=1"

set "CLI_VERSION=1.5.1"
set "CLI_SHA=fabe42e0eb04d00e776a66178299ff95a46c623dbc260f997e58fd514853dd40"
set "ESPTOOL_VERSION=5.3.1"
set "ET_SHA=2b4a73c45db27426685896f64ce3e557f63a64f43cc100cb65c0cc3486af96d3"

cd /d "%~dp0"
set "ROOT=%CD%"
set "TC=%ROOT%\toolchain"

set "KIND=%~1"
if "%KIND%"=="" set "KIND=release"
set "PROFILE="
set "SUFFIX="
if /i "%KIND%"=="release" (set "PROFILE=coldpunk")
if /i "%KIND%"=="debug"   (set "PROFILE=coldpunk-debug" & set "SUFFIX=-debug")
if /i "%KIND%"=="hid"     (set "PROFILE=coldpunk-hid" & set "SUFFIX=-hid")
if not defined PROFILE (
    echo Unknown build "%KIND%": use release, debug or hid.
    goto :fail
)

rem arduino-cli wants the sketch folder named after the .ino file.
for %%I in ("%ROOT%") do set "DIRNAME=%%~nxI"
if /i not "%DIRNAME%"=="ColdPunk" (
    echo The project folder must be named ColdPunk ^(it is %DIRNAME%^).
    goto :fail
)

for %%T in (curl tar certutil) do (
    where %%T >nul 2>nul || (
        echo %%T.exe is missing: Windows 10 1803 or later is needed.
        goto :fail
    )
)

if not exist "%TC%\downloads" mkdir "%TC%\downloads"

rem ---- a short drive letter for toolchain\ ---------------------------------
rem The ESP32 core has deeply nested folders and its compilers do not handle
rem paths over 260 characters. toolchain\ is mapped to a free drive letter
rem with subst for the build (the files stay in toolchain\), so the paths are
rem as short as they can be wherever the project lives. A mapping left by an
rem interrupted build is reused.
set "TD="
set "TD_MADE="
for /f "tokens=1" %%D in ('subst ^| findstr /i /e /c:"=> %TC%"') do if not defined TD set "TD=%%D"
if defined TD set "TD=%TD:~0,2%" & set "TD_MADE=1"
if not defined TD (
    for %%L in (T U V W X Y Z S R Q P O N M L K) do (
        if not defined TD if not exist %%L:\ (
            subst %%L: "%TC%" >nul 2>nul && set "TD=%%L:" && set "TD_MADE=1"
        )
    )
)
if not defined TD set "TD=%TC%"

rem ---- arduino-cli ---------------------------------------------------------
set "CLI=%TD%\arduino-cli-%CLI_VERSION%\arduino-cli.exe"
if exist "%CLI%" goto :cli_ok
set "F=%TD%\downloads\arduino-cli_%CLI_VERSION%_Windows_64bit.zip"
call :fetch "https://github.com/arduino/arduino-cli/releases/download/v%CLI_VERSION%/arduino-cli_%CLI_VERSION%_Windows_64bit.zip" "%F%" %CLI_SHA% || goto :fail
mkdir "%TD%\arduino-cli-%CLI_VERSION%" 2>nul
tar -xf "%F%" -C "%TD%\arduino-cli-%CLI_VERSION%" || goto :fail
:cli_ok

rem ---- esptool (for the flash script next to the firmware) -----------------
set "ET_DIR=%TD%\esptool-%ESPTOOL_VERSION%"
if exist "%ET_DIR%\esptool.exe" goto :et_ok
set "F=%TD%\downloads\esptool-v%ESPTOOL_VERSION%-windows-amd64.zip"
call :fetch "https://github.com/espressif/esptool/releases/download/v%ESPTOOL_VERSION%/esptool-v%ESPTOOL_VERSION%-windows-amd64.zip" "%F%" %ET_SHA% || goto :fail
if exist "%ET_DIR%.tmp" rmdir /s /q "%ET_DIR%.tmp"
mkdir "%ET_DIR%.tmp"
tar -xf "%F%" -C "%ET_DIR%.tmp" || goto :fail
if exist "%ET_DIR%" rmdir /s /q "%ET_DIR%"
move "%ET_DIR%.tmp\esptool-windows-amd64" "%ET_DIR%" >nul || goto :fail
rmdir /s /q "%ET_DIR%.tmp"
:et_ok

rem ---- arduino-cli configuration: every folder inside toolchain\ -----------
set "CFG=%TD%\arduino-cli.yaml"
> "%CFG%" echo # Written by build.bat: arduino-cli keeps everything inside the project.
>>"%CFG%" echo directories:
>>"%CFG%" echo   data: '%TD%\data'
>>"%CFG%" echo   downloads: '%TD%\downloads'
>>"%CFG%" echo   user: '%TD%\user'
>>"%CFG%" echo build_cache:
>>"%CFG%" echo   path: '%TD%\cache'
>>"%CFG%" echo updater:
>>"%CFG%" echo   enable_notification: false

rem ---- the commit shown in About (src\config\build_commit.h) ---------------
if not exist ".git" goto :commit_done
where git >nul 2>nul || goto :commit_done
set "COMMIT="
for /f %%C in ('git describe --always --dirty --abbrev^=7 2^>nul') do set "COMMIT=%%C"
if not defined COMMIT goto :commit_done
findstr /x /c:"#define MW_BUILD_COMMIT \"%COMMIT%\"" "src\config\build_commit.h" >nul 2>nul && goto :commit_done
> "src\config\build_commit.h" echo #define MW_BUILD_COMMIT "%COMMIT%"
:commit_done

rem ---- board and version ---------------------------------------------------
set "BOARD="
for /f "tokens=2" %%B in ('findstr /r /c:"^ *#define  *MW_BOARD_" board_config.h') do if not defined BOARD set "BOARD=%%B"
if not defined BOARD (
    echo No board selected in board_config.h.
    goto :fail
)
set "BOARD=%BOARD:MW_BOARD_=%"
set "VERSION="
for /f tokens^=2^ delims^=^" %%V in ('findstr /c:"#define MW_FIRMWARE_VERSION" src\config\app_config.h') do set "VERSION=%%V"
set "NAME=ColdPunk-%VERSION%-%BOARD%%SUFFIX%"
echo Building %NAME% (profile %PROFILE%)

rem ---- build ---------------------------------------------------------------
set "BUILD=%TD%\build\%PROFILE%"
"%CLI%" --config-file "%CFG%" compile --profile %PROFILE% --build-path "%BUILD%" --warnings default "%ROOT%" || goto :fail

rem ---- the firmware folder -------------------------------------------------
set "OUT=%ROOT%\firmware\%NAME%"
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%" || goto :fail
copy /y "%BUILD%\ColdPunk.ino.bootloader.bin" "%OUT%\bootloader.bin" >nul || goto :fail
copy /y "%BUILD%\ColdPunk.ino.partitions.bin" "%OUT%\partitions.bin" >nul || goto :fail
copy /y "%BUILD%\boot_app0.bin"               "%OUT%\boot_app0.bin"  >nul || goto :fail
copy /y "%BUILD%\ColdPunk.ino.bin"            "%OUT%\coldpunk.bin"   >nul || goto :fail
copy /y "%ET_DIR%\esptool.exe"                "%OUT%\esptool.exe"    >nul || goto :fail
copy /y "%ET_DIR%\LICENSE"                    "%OUT%\esptool-LICENSE.txt" >nul
copy /y "tools\flash\flash.bat"  "%OUT%\" >nul || goto :fail
copy /y "tools\flash\flash.sh"   "%OUT%\" >nul || goto :fail
copy /y "tools\flash\README.txt" "%OUT%\" >nul || goto :fail
type nul > "%OUT%\SHA256SUMS.txt"
for %%F in (bootloader.bin partitions.bin boot_app0.bin coldpunk.bin) do (
    call :sha256 "%OUT%\%%F" || goto :fail
    call :append_sum %%F
)

call :unmap
echo.
echo Done: firmware\%NAME%
echo Flash: firmware\%NAME%\flash.bat [COMx]   (wallets are kept)
if defined PAUSE_AT_END pause
exit /b 0

:append_sum
>>"%OUT%\SHA256SUMS.txt" echo %SHA%  %1
exit /b 0

:fail
call :unmap
echo.
echo Build failed.
if defined PAUSE_AT_END pause
exit /b 1

:unmap
if defined TD_MADE subst %TD% /d >nul 2>nul
exit /b 0

rem ---- call :fetch URL FILE SHA256 -----------------------------------------
rem Downloads once; checks the checksum every time.
:fetch
if exist "%~2" goto :fetch_check
echo Downloading %~1
curl -fL --retry 3 -o "%~2.part" "%~1" || (
    echo Download failed: %~1
    exit /b 1
)
move /y "%~2.part" "%~2" >nul
:fetch_check
call :sha256 "%~2" || exit /b 1
if /i not "%SHA%"=="%~3" (
    del "%~2"
    echo Checksum mismatch for %~nx2 ^(removed; run again^).
    exit /b 1
)
exit /b 0

rem ---- call :sha256 FILE: sets SHA (lower case hex) ------------------------
:sha256
set "SHA="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%~1" SHA256') do if not defined SHA set "SHA=%%H"
if not defined SHA exit /b 1
rem Older Windows prints the hash with spaces between the bytes.
set "SHA=%SHA: =%"
exit /b 0
