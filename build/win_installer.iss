#define I2Pd_AppName "i2pd"
#define I2Pd_Publisher "PurpleI2P"
; Get application version from compiled binary
; Disabled to use definition from command line
;#define I2Pd_ver GetFileVersionString(AddBackslash(SourcePath) + "..\i2pd_x64.exe")

[Setup]
AppName={#I2Pd_AppName}
AppVersion={#I2Pd_TextVer}
AppPublisher={#I2Pd_Publisher}

DefaultDirName={pf}\I2Pd
DefaultGroupName=I2Pd
UninstallDisplayIcon={app}\I2Pd.exe
OutputDir=.
OutputBaseFilename=setup_{#I2Pd_AppName}_v{#I2Pd_TextVer}

LicenseFile=..\LICENSE
SetupIconFile=..\Win32\mask.ico

InternalCompressLevel=ultra64
Compression=lzma/ultra64
SolidCompression=true

ArchitecturesInstallIn64BitMode=x64
ExtraDiskSpaceRequired=15

AppID={{621A23E0-3CF4-4BD6-97BC-4835EA5206A2}
AppVerName={#I2Pd_AppName}
AppCopyright=Copyright (c) 2013-2020, The PurpleI2P Project
AppPublisherURL=http://i2pd.website/
AppSupportURL=https://github.com/PurpleI2P/i2pd/issues
AppUpdatesURL=https://github.com/PurpleI2P/i2pd/releases

VersionInfoProductVersion={#I2Pd_Ver}
VersionInfoVersion={#I2Pd_Ver}

CloseApplications=yes

[Files]
Source: ..\i2pd_x32.exe; DestDir: {app}; DestName: i2pd.exe; Flags: ignoreversion; Check: not IsWin64; MinVersion: 6.0
Source: ..\i2pd_x64.exe; DestDir: {app}; DestName: i2pd.exe; Flags: ignoreversion; Check: IsWin64; MinVersion: 6.0
Source: ..\i2pd_xp.exe; DestDir: {app}; DestName: i2pd.exe; Flags: ignoreversion; Check: IsWin64; OnlyBelowVersion: 6.0
Source: ..\README.md; DestDir: {app}; DestName: Readme.txt; Flags: onlyifdoesntexist
Source: ..\contrib\i2pd.conf; DestDir: {userappdata}\i2pd; Flags: onlyifdoesntexist
Source: ..\contrib\subscriptions.txt; DestDir: {userappdata}\i2pd; Flags: onlyifdoesntexist
Source: ..\contrib\tunnels.conf; DestDir: {userappdata}\i2pd; Flags: onlyifdoesntexist
Source: ..\contrib\certificates\*; DestDir: {userappdata}\i2pd\certificates; Flags: onlyifdoesntexist recursesubdirs createallsubdirs
Source: ..\contrib\tunnels.d\*; DestDir: {userappdata}\i2pd\tunnels.d; Flags: onlyifdoesntexist recursesubdirs createallsubdirs

[Icons]
Name: {group}\I2Pd; Filename: {app}\i2pd.exe
Name: {group}\Readme; Filename: {app}\Readme.txt

[UninstallDelete]
Type: filesandordirs; Name: {app}
