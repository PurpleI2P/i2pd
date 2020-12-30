@echo off
setlocal enableextensions enabledelayedexpansion
title Building i2pd

REM Copyright (c) 2013-2020, The PurpleI2P Project
REM This file is part of Purple i2pd project and licensed under BSD3
REM See full license text in LICENSE file at top of project tree

REM To use that script, you must have installed in your MSYS installation these packages:
REM Base: git make zip
REM x86_64: mingw-w64-x86_64-boost mingw-w64-x86_64-openssl mingw-w64-x86_64-gcc
REM i686: mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-gcc

REM setting up variables for MSYS
REM Note: if you installed MSYS64 to different path, edit WD variable (only C:\msys64 needed to edit)!
set "WD=C:\msys64\usr\bin\"
set MSYS2_PATH_TYPE=inherit
set CHERE_INVOKING=enabled_from_arguments
REM set MSYSTEM=MSYS
set MSYSTEM=MINGW32

set "xSH=%WD%bash -lc"

set "FILELIST=i2pd.exe README.txt contrib/i2pd.conf contrib/tunnels.conf contrib/certificates contrib/tunnels.d"

REM detecting number of processors
set /a threads=%NUMBER_OF_PROCESSORS%

REM we must work in root of repo
cd ..

REM deleting old log files
del /S build_*.log >> nul 2>&1

echo Receiving latest commit and cleaning up...
%xSH% "git checkout contrib/* && git pull && make clean" > build\build.log 2>&1
echo.

REM set to variable current commit hash
FOR /F "usebackq" %%a IN (`%xSH% 'git describe --tags'`) DO (
 set tag=%%a
)

%xSH% "echo To use configs and certificates, move all files and certificates folder from contrib directory here. > README.txt" >> nul

REM converting configuration files to DOS format (usable in default notepad)
%xSH% "unix2dos contrib/i2pd.conf contrib/tunnels.conf contrib/tunnels.d/*" >> build\build.log 2>&1

REM starting building
set MSYSTEM=MINGW32
set bitness=32
call :BUILDING

set MSYSTEM=MINGW64
set bitness=64
call :BUILDING

REM building for WinXP
set "WD=C:\msys64-xp\usr\bin\"
set MSYSTEM=MINGW32
set bitness=32
set "xSH=%WD%bash -lc"
call :BUILDING_XP
echo.

REM compile installer
C:\PROGRA~2\INNOSE~1\ISCC.exe /dI2Pd_TextVer="%tag%" /dI2Pd_Ver="%tag%.0" build\win_installer.iss >> build\build.log 2>&1

del README.txt i2pd_x32.exe i2pd_x64.exe i2pd_xp.exe >> nul

echo Build complete...
pause
exit /b 0

:BUILDING
%xSH% "make clean" >> nul
echo Building i2pd %tag% for win%bitness%
%xSH% "make DEBUG=no USE_UPNP=yes -j%threads% && cp i2pd.exe i2pd_x%bitness%.exe && zip -r9 build/i2pd_%tag%_win%bitness%_mingw.zip %FILELIST% && make clean" > build\build_win%bitness%_%tag%.log 2>&1
goto EOF

:BUILDING_XP
%xSH% "make clean" >> nul
echo Building i2pd %tag% for winxp
%xSH% "make DEBUG=no USE_UPNP=yes USE_WINXP_FLAGS=yes -j%threads% && cp i2pd.exe i2pd_xp.exe && zip -r9 build/i2pd_%tag%_winxp_mingw.zip %FILELIST% && make clean" > build\build_winxp_%tag%.log 2>&1

:EOF