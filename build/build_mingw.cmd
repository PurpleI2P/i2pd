@echo off
setlocal enableextensions enabledelayedexpansion
title Building i2pd

REM Copyright (c) 2013-2017, The PurpleI2P Project
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

REM detecting number of processors and subtract 1.
set /a threads=%NUMBER_OF_PROCESSORS%-1

REM we must work in root of repo
cd ..

REM deleting old log files
del /S build_*.log >> nul

echo Receiving latest commit and cleaning up...
%xSH% "git pull && make clean" > build/build_git.log 2>&1
echo.

REM set to variable current commit hash
FOR /F "usebackq" %%a IN (`%xSH% 'git describe --tags'`) DO (
 set tag=%%a
)

%xSH% "echo To use configs and certificates, move all files and certificates folder from contrib directory here. > README.txt" >> nul

REM starting building
set MSYSTEM=MINGW32
set bitness=32
call :BUILDING
echo.

set MSYSTEM=MINGW64
set bitness=64
call :BUILDING
echo.

del README.txt >> nul

echo Build complete...
pause
exit /b 0

:BUILDING
%xSH% "make clean" >> nul
echo Building i2pd %tag% for win%bitness%:
echo Build AVX+AESNI...
%xSH% "make DEBUG=no USE_UPNP=yes USE_AVX=1 USE_AESNI=1 -j%threads% && zip -r9 build/i2pd_%tag%_win%bitness%_mingw_avx_aesni.zip %FILELIST% && make clean" > build/build_win%bitness%_avx_aesni_%tag%.log 2>&1
echo Build AVX...
%xSH% "make DEBUG=no USE_UPNP=yes USE_AVX=1 -j%threads% && zip -r9 build/i2pd_%tag%_win%bitness%_mingw_avx.zip %FILELIST% && make clean" > build/build_win%bitness%_avx_%tag%.log 2>&1
echo Build AESNI...
%xSH% "make DEBUG=no USE_UPNP=yes USE_AESNI=1 -j%threads% && zip -r9 build/i2pd_%tag%_win%bitness%_mingw_aesni.zip %FILELIST% && make clean" > build/build_win%bitness%_aesni_%tag%.log 2>&1
echo Build without extensions...
%xSH% "make DEBUG=no USE_UPNP=yes -j%threads% && zip -r9 build/i2pd_%tag%_win%bitness%_mingw.zip %FILELIST% && make clean" > build/build_win%bitness%_%tag%.log 2>&1

:EOF