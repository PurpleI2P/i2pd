#define DOTNET_AppName "dotnet"
#define DOTNET_ver "2.25.0"
#define DOTNET_Publisher "PurpleI2P"

[Setup]
AppName={#DOTNET_AppName}
AppVersion={#DOTNET_ver}
AppPublisher={#DOTNET_Publisher}
DefaultDirName={pf}\DOTNET
DefaultGroupName=DOTNET
UninstallDisplayIcon={app}\DOTNET.exe
OutputDir=.
LicenseFile=../LICENSE
OutputBaseFilename=setup_{#DOTNET_AppName}_v{#DOTNET_ver}
SetupIconFile=mask.ico
InternalCompressLevel=ultra64
Compression=lzma/ultra64
SolidCompression=true
ArchitecturesInstallIn64BitMode=x64
AppVerName={#DOTNET_AppName}
ExtraDiskSpaceRequired=15
AppID={{621A23E0-3CF4-4BD6-97BC-4835EA5206A2}
AppPublisherURL=http://dotnet.website/
AppSupportURL=https://github.com/PurpleI2P/dotnet/issues
AppUpdatesURL=https://github.com/PurpleI2P/dotnet/releases

[Files]
Source: ..\dotnet_x86.exe; DestDir: {app}; DestName: dotnet.exe; Flags: ignoreversion; Check: not IsWin64
Source: ..\dotnet_x64.exe; DestDir: {app}; DestName: dotnet.exe; Flags: ignoreversion; Check: IsWin64
Source: ..\README.md; DestDir: {app}; DestName: Readme.txt; Flags: onlyifdoesntexist
Source: ..\contrib\dotnet.conf; DestDir: {userappdata}\dotnet; Flags: onlyifdoesntexist
Source: ..\contrib\subscriptions.txt; DestDir: {userappdata}\dotnet; Flags: onlyifdoesntexist
Source: ..\contrib\tunnels.conf; DestDir: {userappdata}\dotnet; Flags: onlyifdoesntexist
Source: ..\contrib\certificates\*; DestDir: {userappdata}\dotnet\certificates; Flags: onlyifdoesntexist recursesubdirs createallsubdirs
Source: ..\contrib\tunnels.d\*; DestDir: {userappdata}\dotnet\tunnels.d; Flags: onlyifdoesntexist recursesubdirs createallsubdirs

[Icons]
Name: {group}\DOTNET; Filename: {app}\dotnet.exe
Name: {group}\Readme; Filename: {app}\Readme.txt

[UninstallDelete]
Type: filesandordirs; Name: {app}
