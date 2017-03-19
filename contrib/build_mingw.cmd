@echo off
setlocal

title Building i2pd

set "WD=C:\msys64\usr\bin\"
set MSYS2_PATH_TYPE=inherit
set CHERE_INVOKING=enabled_from_arguments
set MSYSCON=

echo Building i2pd for win32. Press Enter after the end of compilation...
set MSYSTEM=MINGW32
set CONTITLE=MinGW x32
start "%CONTITLE%" /WAIT "%WD%bash" --login build_mingw.sh
pause > nul

echo Building i2pd for win64. Press Enter after the end of compilation...
set MSYSTEM=MINGW64
set CONTITLE=MinGW x64
start "%CONTITLE%" /WAIT "%WD%bash" --login build_mingw.sh
pause > nul

echo Build complete...
pause
exit /b 0