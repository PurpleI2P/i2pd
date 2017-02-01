@echo off
title Сборка i2pd

set "WD=C:\msys64"
set CHERE_INVOKING=enabled_from_arguments
set MSYSCON=mintty.exe

echo Сборка i2pd для win32. Нажмите Enter после окончания компиляции...
set "MSYSTEM=MINGW32"
set "CONTITLE=MinGW x32"
start "%CONTITLE%" /WAIT C:\msys64\usr\bin\mintty.exe -i /msys2.ico /usr/bin/bash --login build_mingw.sh
pause

echo Сборка i2pd для win64. Нажмите Enter после окончания компиляции...
set "MSYSTEM=MINGW64"
set "CONTITLE=MinGW x64"
start "%CONTITLE%" /WAIT C:\msys64\usr\bin\mintty.exe -i /msys2.ico /usr/bin/bash --login build_mingw.sh
pause

echo Сборка завершена...
pause
exit /b 0