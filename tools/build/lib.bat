@rem ColdPunk build helpers for Windows, called by build.bat,
@rem build-idf-bootloader.bat, build-secure.bat and make-keys.bat:
@rem     call "%ROOT%\tools\build\lib.bat" :label args...
@rem Everything is downloaded into toolchain\; nothing goes into the system or
@rem the user profile. No setlocal here: the variables set by a label are
@rem meant for the caller. Not meant to be run by itself.
@rem
@rem Pinned versions (with the SHA-256 of every archive this file downloads):
@rem   arduino-cli 1.5.1        the Arduino build (core and libraries: sketch.yaml)
@rem   esptool 5.3.1            esptool, espsecure, espefuse (standalone)
@rem   ESP-IDF 5.5.5            the version the Arduino core 3.3.11 is built from
@rem   Python 3.12.13           python-build-standalone 20260610, for ESP-IDF
@call %*
@exit /b %errorlevel%

rem ---- :init SCRIPT KIND ---------------------------------------------------
rem ROOT (the caller's folder), TC, TD (short drive letter), PROFILE, SUFFIX.
:init
set "SCRIPT=%~1"
set "CLI_VERSION=1.5.1"
set "CLI_SHA=fabe42e0eb04d00e776a66178299ff95a46c623dbc260f997e58fd514853dd40"
set "ESPTOOL_VERSION=5.3.1"
set "ET_SHA=2b4a73c45db27426685896f64ce3e557f63a64f43cc100cb65c0cc3486af96d3"
set "IDF_VERSION=5.5.5"
set "IDF_SHA=48fffe90304573ef366bda06e38c92fd65c6f3636d785ce103ff82e4647964c8"
set "PY_RELEASE=20260610"
set "PY_VERSION=3.12.13"
set "PY_SHA=f5e4d9f856567493776f3d1e832c939fbaba5dcbcc5e0492a82ecfceea83b316"
set "IDF_GCC=esp-14.2.0_20260121"
set "IDF_CMAKE=3.30.2"
set "IDF_NINJA=1.12.1"
set "TC=%ROOT%\toolchain"

set "KIND=%~2"
if "%KIND%"=="" set "KIND=release"
set "PROFILE="
set "SUFFIX="
if /i "%KIND%"=="release" (set "PROFILE=coldpunk")
if /i "%KIND%"=="debug"   (set "PROFILE=coldpunk-debug" & set "SUFFIX=-debug")
if /i "%KIND%"=="hid"     (set "PROFILE=coldpunk-hid" & set "SUFFIX=-hid")
if not defined PROFILE (
    echo Unknown build "%KIND%": use release, debug or hid.
    exit /b 1
)

rem arduino-cli wants the sketch folder named after the .ino file.
for %%I in ("%ROOT%") do set "DIRNAME=%%~nxI"
if /i not "%DIRNAME%"=="ColdPunk" (
    echo The project folder must be named ColdPunk ^(it is %DIRNAME%^).
    exit /b 1
)
for %%T in (curl tar certutil) do (
    where %%T >nul 2>nul || (
        echo %%T.exe is missing: Windows 10 1803 or later is needed.
        exit /b 1
    )
)
if not exist "%TC%\downloads" mkdir "%TC%\downloads"

rem The ESP32 core and ESP-IDF have deeply nested folders and their compilers
rem do not handle paths over 260 characters. toolchain\ is mapped to a free
rem drive letter with subst while the script runs (the files stay in
rem toolchain\). A mapping left by an interrupted run is reused.
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
exit /b 0

:unmap
if defined TD_MADE subst %TD% /d >nul 2>nul
set "TD_MADE="
exit /b 0

rem ---- :fetch URL FILE SHA256: downloads once, checks every time ----------
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

rem ---- :sha256 FILE: sets SHA ---------------------------------------------
:sha256
set "SHA="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%~1" SHA256') do if not defined SHA set "SHA=%%H"
if not defined SHA exit /b 1
rem Older Windows prints the hash with spaces between the bytes.
set "SHA=%SHA: =%"
exit /b 0

rem ---- :esptool: ET_DIR, ESPTOOL, ESPSECURE, ESPEFUSE ---------------------
:esptool
set "ET_DIR=%TD%\esptool-%ESPTOOL_VERSION%"
set "ESPTOOL=%ET_DIR%\esptool.exe"
set "ESPSECURE=%ET_DIR%\espsecure.exe"
set "ESPEFUSE=%ET_DIR%\espefuse.exe"
if exist "%ESPTOOL%" exit /b 0
set "F=%TD%\downloads\esptool-v%ESPTOOL_VERSION%-windows-amd64.zip"
call :fetch "https://github.com/espressif/esptool/releases/download/v%ESPTOOL_VERSION%/esptool-v%ESPTOOL_VERSION%-windows-amd64.zip" "%F%" %ET_SHA% || exit /b 1
if exist "%ET_DIR%.tmp" rmdir /s /q "%ET_DIR%.tmp"
mkdir "%ET_DIR%.tmp"
tar -xf "%F%" -C "%ET_DIR%.tmp" || exit /b 1
if exist "%ET_DIR%" rmdir /s /q "%ET_DIR%"
move "%ET_DIR%.tmp\esptool-windows-amd64" "%ET_DIR%" >nul || exit /b 1
rmdir /s /q "%ET_DIR%.tmp"
exit /b 0

rem ---- :arduino_cli: CLI, CFG ----------------------------------------------
:arduino_cli
set "CLI=%TD%\arduino-cli-%CLI_VERSION%\arduino-cli.exe"
if exist "%CLI%" goto :cli_cfg
set "F=%TD%\downloads\arduino-cli_%CLI_VERSION%_Windows_64bit.zip"
call :fetch "https://github.com/arduino/arduino-cli/releases/download/v%CLI_VERSION%/arduino-cli_%CLI_VERSION%_Windows_64bit.zip" "%F%" %CLI_SHA% || exit /b 1
mkdir "%TD%\arduino-cli-%CLI_VERSION%" 2>nul
tar -xf "%F%" -C "%TD%\arduino-cli-%CLI_VERSION%" || exit /b 1
:cli_cfg
rem Every folder arduino-cli uses lies inside toolchain\.
set "CFG=%TD%\arduino-cli.yaml"
> "%CFG%" echo # Written by the build scripts: arduino-cli keeps everything inside the project.
>>"%CFG%" echo directories:
>>"%CFG%" echo   data: '%TD%\data'
>>"%CFG%" echo   downloads: '%TD%\downloads'
>>"%CFG%" echo   user: '%TD%\user'
>>"%CFG%" echo build_cache:
>>"%CFG%" echo   path: '%TD%\cache'
>>"%CFG%" echo updater:
>>"%CFG%" echo   enable_notification: false
exit /b 0

rem ---- :commit: the commit shown in About (src\config\build_commit.h) -------
:commit
if not exist "%ROOT%\.git" exit /b 0
where git >nul 2>nul || exit /b 0
set "COMMIT="
for /f %%C in ('git -C "%ROOT%" describe --always --dirty --abbrev^=7 2^>nul') do set "COMMIT=%%C"
if not defined COMMIT exit /b 0
findstr /x /c:"#define MW_BUILD_COMMIT \"%COMMIT%\"" "%ROOT%\src\config\build_commit.h" >nul 2>nul && exit /b 0
> "%ROOT%\src\config\build_commit.h" echo #define MW_BUILD_COMMIT "%COMMIT%"
exit /b 0

rem ---- :board_version: BOARD (board_config.h), VERSION ----------------------
:board_version
set "BOARD="
for /f "tokens=2" %%B in ('findstr /r /c:"^ *#define  *MW_BOARD_" "%ROOT%\board_config.h"') do if not defined BOARD set "BOARD=%%B"
if not defined BOARD (
    echo No board selected in board_config.h.
    exit /b 1
)
set "BOARD=%BOARD:MW_BOARD_=%"
set "VERSION="
for /f tokens^=2^ delims^=^" %%V in ('findstr /c:"#define MW_FIRMWARE_VERSION" "%ROOT%\src\config\app_config.h"') do set "VERSION=%%V"
exit /b 0

rem ---- :arduino_build: BUILD (ColdPunk.ino.bin, .elf, ...) ------------------
:arduino_build
set "BUILD=%TD%\build\%PROFILE%"
"%CLI%" --config-file "%CFG%" compile --profile %PROFILE% --build-path "%BUILD%" --warnings default "%ROOT%" || exit /b 1
exit /b 0

rem ---- :idf: ESP-IDF 5.5.5 with a portable Python, only for its bootloader --
rem About 3 GB downloaded once (ESP-IDF itself is 2 GB), 6 GB on disk.
:idf
set "PY_DIR=%TD%\python-%PY_VERSION%"
set "PY=%PY_DIR%\python.exe"
if exist "%PY%" goto :idf_src
set "F=%TD%\downloads\cpython-%PY_VERSION%+%PY_RELEASE%-x86_64-pc-windows-msvc-install_only.tar.gz"
call :fetch "https://github.com/astral-sh/python-build-standalone/releases/download/%PY_RELEASE%/cpython-%PY_VERSION%+%PY_RELEASE%-x86_64-pc-windows-msvc-install_only.tar.gz" "%F%" %PY_SHA% || exit /b 1
if exist "%PY_DIR%.tmp" rmdir /s /q "%PY_DIR%.tmp"
mkdir "%PY_DIR%.tmp"
tar -xzf "%F%" -C "%PY_DIR%.tmp" || exit /b 1
if exist "%PY_DIR%" rmdir /s /q "%PY_DIR%"
move "%PY_DIR%.tmp\python" "%PY_DIR%" >nul || exit /b 1
rmdir /s /q "%PY_DIR%.tmp"
:idf_src
set "IDF_PATH=%TD%\esp-idf-v%IDF_VERSION%"
if exist "%IDF_PATH%\tools\idf.py" goto :idf_tools
set "F=%TD%\downloads\esp-idf-v%IDF_VERSION%.zip"
echo ESP-IDF %IDF_VERSION% is a 2 GB download (once).
call :fetch "https://github.com/espressif/esp-idf/releases/download/v%IDF_VERSION%/esp-idf-v%IDF_VERSION%.zip" "%F%" %IDF_SHA% || exit /b 1
if exist "%IDF_PATH%.tmp" rmdir /s /q "%IDF_PATH%.tmp"
echo Unpacking ESP-IDF (a few minutes)...
"%PY%" -c "import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "%F%" "%IDF_PATH%.tmp" || (
    echo Unpacking ESP-IDF failed.
    exit /b 1
)
if exist "%IDF_PATH%" rmdir /s /q "%IDF_PATH%"
move "%IDF_PATH%.tmp\esp-idf-v%IDF_VERSION%" "%IDF_PATH%" >nul || exit /b 1
rmdir /s /q "%IDF_PATH%.tmp"
:idf_tools
set "IDF_TOOLS_PATH=%TD%\idf-tools"
set "PIP_CACHE_DIR=%TD%\pip-cache"
set "IDF_COMPONENT_MANAGER=0"
set "IDF_CCACHE_ENABLE=0"
set "IDF_COMPONENT_CACHE_PATH=%TD%\idf-component-cache"
set "STAMP=%IDF_TOOLS_PATH%\.coldpunk-%IDF_VERSION%-py%PY_VERSION%"
if exist "%STAMP%" goto :idf_env
"%PY%" "%IDF_PATH%\tools\idf_tools.py" --non-interactive install xtensa-esp-elf@%IDF_GCC% cmake@%IDF_CMAKE% ninja@%IDF_NINJA% || (
    echo Installing the ESP-IDF tools failed.
    exit /b 1
)
"%PY%" "%IDF_PATH%\tools\idf_tools.py" --non-interactive install-python-env || (
    echo Installing the ESP-IDF Python environment failed.
    exit /b 1
)
type nul > "%STAMP%"
:idf_env
set "IDF_PYTHON_ENV_PATH="
for /d %%E in ("%IDF_TOOLS_PATH%\python_env\idf5.5_py*_env") do if not defined IDF_PYTHON_ENV_PATH set "IDF_PYTHON_ENV_PATH=%%~fE"
if not defined IDF_PYTHON_ENV_PATH (
    echo No ESP-IDF Python environment in %IDF_TOOLS_PATH%.
    exit /b 1
)
set "VENV_PY=%IDF_PYTHON_ENV_PATH%\Scripts\python.exe"
set "CMAKE_BIN="
for /r "%IDF_TOOLS_PATH%\tools\cmake\%IDF_CMAKE%" %%F in (cmake.exe) do if exist "%%F" if not defined CMAKE_BIN set "CMAKE_BIN=%%~dpF"
set "IDF_PATHS=%IDF_TOOLS_PATH%\tools\xtensa-esp-elf\%IDF_GCC%\xtensa-esp-elf\bin;%CMAKE_BIN%;%IDF_TOOLS_PATH%\tools\ninja\%IDF_NINJA%;%IDF_PYTHON_ENV_PATH%\Scripts"
exit /b 0

rem ---- :idf_bootloader plain^|secure: BL_BIN (unsigned bootloader.bin) ------
:idf_bootloader
call :idf || exit /b 1
set "BL_PROJ=%TD%\bootloader\project"
if exist "%BL_PROJ%" rmdir /s /q "%BL_PROJ%"
mkdir "%BL_PROJ%"
xcopy /e /i /q /y "%ROOT%\tools\bootloader" "%BL_PROJ%" >nul || exit /b 1
set "BL_DEFAULTS=%BL_PROJ%\sdkconfig.defaults"
if /i "%~1"=="secure" set "BL_DEFAULTS=%BL_DEFAULTS%;%BL_PROJ%\sdkconfig.secure"
set "BL_OUT=%TD%\bootloader\%~1"
if exist "%BL_OUT%" rmdir /s /q "%BL_OUT%"
echo Building the ESP-IDF %IDF_VERSION% bootloader (%~1)
set "SAVED_PATH=%PATH%"
set "PATH=%IDF_PATHS%;%PATH%"
"%VENV_PY%" "%IDF_PATH%\tools\idf.py" -C "%BL_PROJ%" -B "%BL_OUT%" -D "SDKCONFIG=%BL_OUT%\sdkconfig" -D "SDKCONFIG_DEFAULTS=%BL_DEFAULTS%" bootloader
set "BL_RC=%errorlevel%"
set "PATH=%SAVED_PATH%"
if not "%BL_RC%"=="0" (
    echo The bootloader build failed.
    exit /b 1
)
set "BL_BIN=%BL_OUT%\bootloader\bootloader.bin"
if not exist "%BL_BIN%" (
    echo No bootloader.bin after the build.
    exit /b 1
)
exit /b 0

rem ---- :keys_dir: KEYS, SB_KEY, FE_KEY -------------------------------------
:keys_dir
if defined COLDPUNK_KEYS (set "KEYS=%COLDPUNK_KEYS%") else (set "KEYS=%ROOT%\keys")
set "SB_KEY=%KEYS%\secure_boot_signing_key.pem"
set "FE_KEY=%KEYS%\flash_encryption_key.bin"
exit /b 0

rem ---- :out NAME: a fresh firmware\NAME (OUT) -------------------------------
:out
set "OUT=%ROOT%\firmware\%~1"
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%" || exit /b 1
exit /b 0

rem ---- :sums DIR FILE...: SHA256SUMS.txt (paths relative to DIR, with /) -----
:sums
set "SUMS_DIR=%~1"
type nul > "%SUMS_DIR%\SHA256SUMS.txt"
:sums_next
shift
if "%~1"=="" exit /b 0
set "SUMS_FILE=%~1"
call :sha256 "%SUMS_DIR%\%SUMS_FILE:/=\%" || exit /b 1
>>"%SUMS_DIR%\SHA256SUMS.txt" echo %SHA%  %SUMS_FILE%
goto :sums_next

rem ---- :hex FILE: sets HEX (the file as lower-case hex) ---------------------
:hex
set "HEX="
certutil -f -encodehex "%~1" "%~1.hex" 12 >nul || exit /b 1
set /p HEX=<"%~1.hex"
del "%~1.hex"
exit /b 0
