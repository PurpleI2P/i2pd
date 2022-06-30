@echo off
setlocal enableextensions enabledelayedexpansion
title Building i2pd

REM Copyright (c) 2013-2022, The PurpleI2P Project
REM This file is part of Purple i2pd project and licensed under BSD3
REM See full license text in LICENSE file at top of project tree

REM To use that script, you must have installed in your MSYS installation these packages:
REM Base: git make zip
REM UCRT64: mingw-w64-ucrt-x86_64-boost mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-gcc
REM MINGW32: mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-gcc

REM setting up variables for MSYS
REM Note: if you installed MSYS64 to different path, edit WD variable (only C:\msys64 needed to edit)
set MSYS2_PATH_TYPE=inherit
set CHERE_INVOKING=enabled_from_arguments
set MSYSTEM=MINGW32

set "WD=C:\msys64\usr\bin\"
set "xSH=%WD%bash -lc"

set "FILELIST=i2pd.exe README.txt contrib/i2pd.conf contrib/tunnels.conf contrib/certificates contrib/tunnels.d contrib/webconsole"

REM detecting number of processors
set /a threads=%NUMBER_OF_PROCESSORS%

REM we must work in root of repo
cd ..

REM deleting old log files
del /S build_*.log >> nul 2>&1

echo Receiving latest commit and cleaning up...
%xSH% "git checkout contrib/* && git pull && make clean" > build\build.log 2>&1

REM set to variable current commit hash
for /F "usebackq" %%a in (`%xSH% "git describe --tags"`) DO (
 set tag=%%a
)

REM set to variable latest released tag
for /F "usebackq" %%b in (`%xSH% "git describe --abbrev=0"`) DO (
 set reltag=%%b
)

echo Preparing configuration files and README for packaging...

%xSH% "echo To use configs and certificates, move all files and certificates folder from contrib directory here. > README.txt" >> nul

REM converting configuration files to DOS format (make usable in Windows Notepad)
%xSH% "unix2dos contrib/i2pd.conf contrib/tunnels.conf contrib/tunnels.d/* contrib/webconsole/style.css" >> build\build.log 2>&1

REM Prepare binary signing command if signing key and password provided
if defined SIGN (
  echo Signing enabled

  for %%X in (signtool.exe) do (set xSIGNTOOL=%%~$PATH:X)
  if not defined xSIGNTOOL (
    if not defined SIGNTOOL (
      echo Error: Can't find signtool. Please provide path to binary using SIGNTOOL variable.
      exit /b 1
    ) else (
      set "xSIGNTOOL=%SIGNTOOL%"
    )
  )

  if defined SIGNKEY (
    set "xSIGNKEYOPTS=/f ^"%SIGNKEY%^""
  )

  if defined SIGNPASS (
    set "xSIGNPASSOPTS=/p ^"%SIGNPASS%^""
  )

  set "xSIGNOPTS=sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 %xSIGNKEYOPTS% %xSIGNPASSOPTS%"
)

REM starting building
set MSYSTEM=MINGW32
set bitness=32
call :BUILDING

set MSYSTEM=UCRT64
set bitness=64
call :BUILDING

REM build for Windows XP
if exist C:\msys64-xp\ ( call :BUILDING_XP )

echo.

REM compile installer
echo Building installer...
C:\PROGRA~2\INNOSE~1\ISCC.exe /dI2Pd_TextVer="%tag%" /dI2Pd_Ver="%reltag%.0" build\win_installer.iss >> build\build.log 2>&1

REM Sign binary
if defined xSIGNOPTS (
  "%xSIGNTOOL%" %xSIGNOPTS% build\setup_i2pd_v%tag%.exe
)

%xSH% "git checkout contrib/*" >> build\build.log 2>&1
del README.txt i2pd_x32.exe i2pd_x64.exe i2pd_xp.exe >> nul

echo Build complete...
pause
exit /b 0

:BUILDING
%xSH% "make clean" >> nul
echo Building i2pd %tag% for win%bitness%...
REM Build i2pd
%xSH% "make DEBUG=no USE_UPNP=yes -j%threads%" > build\build_win%bitness%_%tag%.log 2>&1

REM Sign binary
if defined xSIGNOPTS (
  "%xSIGNTOOL%" %xSIGNOPTS% i2pd.exe
)

REM Copy binary for installer and create distribution archive
%xSH% "cp i2pd.exe i2pd_x%bitness%.exe && zip -r9 build/i2pd_%tag%_win%bitness%_mingw.zip %FILELIST%" >> build\build_win%bitness%_%tag%.log 2>&1

REM Clean work directory
%xSH% "make clean" >> build\build_win%bitness%_%tag%.log 2>&1
goto EOF

:BUILDING_XP
set MSYSTEM=MINGW32
set bitness=32
set "WD=C:\msys64-xp\usr\bin\"
set "xSH=%WD%bash -lc"

%xSH% "make clean" >> nul
echo Building i2pd %tag% for winxp...
%xSH% "make DEBUG=no USE_UPNP=yes USE_WINXP_FLAGS=yes -j%threads%" > build\build_winxp_%tag%.log 2>&1

REM Sign binary
if defined xSIGNOPTS (
  "%xSIGNTOOL%" %xSIGNOPTS% i2pd.exe
)

REM Copy binary for installer and create distribution archive
%xSH% "cp i2pd.exe i2pd_xp.exe && zip -r9 build/i2pd_%tag%_winxp_mingw.zip %FILELIST%" >> build\build_winxp_%tag%.log 2>&1

REM Clean work directory
%xSH% "make clean" >> build\build_winxp_%tag%.log 2>&1
goto EOF

:EOF
