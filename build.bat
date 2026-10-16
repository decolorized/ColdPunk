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
rem See also build-idf-bootloader.bat and build-secure.bat.
rem Uses curl, tar and certutil, which come with Windows 10 1803 and later.
setlocal EnableExtensions

rem Started by a double-click (cmd /c): keep the window open at the end.
set "PAUSE_AT_END="
echo %CMDCMDLINE% | findstr /i /c:" /c " >nul && set "PAUSE_AT_END=1"

cd /d "%~dp0"
set "ROOT=%CD%"
set "LIB=%ROOT%\tools\build\lib.bat"
call "%LIB%" :init build.bat %1 || goto :fail
call "%LIB%" :arduino_cli || goto :fail
call "%LIB%" :esptool || goto :fail
call "%LIB%" :commit
call "%LIB%" :board_version || goto :fail
set "NAME=ColdPunk-%VERSION%-%BOARD%%SUFFIX%"
echo Building %NAME% (profile %PROFILE%)
call "%LIB%" :arduino_build || goto :fail

call "%LIB%" :out "%NAME%" || goto :fail
copy /y "%BUILD%\ColdPunk.ino.bootloader.bin" "%OUT%\bootloader.bin" >nul || goto :fail
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
echo Done: firmware\%NAME%
echo Flash: firmware\%NAME%\flash.bat [COMx]   (wallets are kept)
if defined PAUSE_AT_END pause
exit /b 0

:fail
call "%LIB%" :unmap
echo.
echo Build failed.
if defined PAUSE_AT_END pause
exit /b 1
