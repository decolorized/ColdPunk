@echo off
rem ColdPunk: the normal firmware with a bootloader built by ESP-IDF 5.5.5
rem instead of the one the Arduino core ships - same version, same options,
rem no secure boot and no flash encryption. For checking that the device
rem behaves the same with an IDF-built bootloader before going to
rem build-secure.bat, which uses one too. Nothing is burned into eFuse;
rem flashing it is as reversible as a normal build.
rem
rem   build-idf-bootloader.bat [release|debug|hid]
rem
rem Besides what build.bat downloads, this one fetches ESP-IDF 5.5.5 (2 GB),
rem a portable Python, the ESP-IDF compiler, cmake and ninja into toolchain\
rem (about 3 GB downloaded once, 6 GB on disk). The result goes to
rem firmware\ColdPunk-<version>-<board>[-debug|-hid]-idfboot\ with the usual
rem flash.bat / flash.sh.
setlocal EnableExtensions

set "PAUSE_AT_END="
echo %CMDCMDLINE% | findstr /i /c:" /c " >nul && set "PAUSE_AT_END=1"

cd /d "%~dp0"
set "ROOT=%CD%"
set "LIB=%ROOT%\tools\build\lib.bat"
call "%LIB%" :init build-idf-bootloader.bat %1 || goto :fail
call "%LIB%" :arduino_cli || goto :fail
call "%LIB%" :esptool || goto :fail
call "%LIB%" :commit
call "%LIB%" :board_version || goto :fail
set "NAME=ColdPunk-%VERSION%-%BOARD%%SUFFIX%-idfboot"
echo Building %NAME% (profile %PROFILE%)
call "%LIB%" :arduino_build || goto :fail
call "%LIB%" :idf_bootloader plain || goto :fail

call "%LIB%" :out "%NAME%" || goto :fail
copy /y "%BL_BIN%"                            "%OUT%\bootloader.bin" >nul || goto :fail
copy /y "%BUILD%\ColdPunk.ino.partitions.bin" "%OUT%\partitions.bin" >nul || goto :fail
copy /y "%BUILD%\boot_app0.bin"               "%OUT%\boot_app0.bin"  >nul || goto :fail
copy /y "%BUILD%\ColdPunk.ino.bin"            "%OUT%\coldpunk.bin"   >nul || goto :fail
copy /y "%ESPTOOL%"                           "%OUT%\esptool.exe"    >nul || goto :fail
copy /y "%ET_DIR%\LICENSE"                    "%OUT%\esptool-LICENSE.txt" >nul
copy /y "tools\flash\flash.bat"  "%OUT%\" >nul || goto :fail
copy /y "tools\flash\flash.sh"   "%OUT%\" >nul || goto :fail
copy /y "tools\flash\README.txt" "%OUT%\" >nul || goto :fail
call "%LIB%" :sums "%OUT%" bootloader.bin partitions.bin boot_app0.bin coldpunk.bin || goto :fail

call "%LIB%" :unmap
echo.
echo Done: firmware\%NAME% (bootloader: ESP-IDF %IDF_VERSION%, no secure boot)
echo Flash: firmware\%NAME%\flash.bat [COMx]   (wallets are kept)
echo Back to the Arduino bootloader: flash a build.bat folder.
if defined PAUSE_AT_END pause
exit /b 0

:fail
call "%LIB%" :unmap
echo.
echo Build failed.
if defined PAUSE_AT_END pause
exit /b 1
