#define I2Pd_AppName "i2pd"
#define I2Pd_ver "2.31.0"
#define I2Pd_Publisher "PurpleI2P"

[Setup]
AppName={#I2Pd_AppName}
AppVersion={#I2Pd_ver}
AppPublisher={#I2Pd_Publisher}
DefaultDirName={pf}\I2Pd
DefaultGroupName=I2Pd
UninstallDisplayIcon={app}\I2Pd.exe
OutputDir=.
LicenseFile=../LICENSE
OutputBaseFilename=setup_{#I2Pd_AppName}_v{#I2Pd_ver}
SetupIconFile=mask.ico
InternalCompressLevel=ultra64
Compression=lzma/ultra64
SolidCompression=true
ArchitecturesInstallIn64BitMode=x64
AppVerName={#I2Pd_AppName}
ExtraDiskSpaceRequired=15
AppID={{621A23E0-3CF4-4BD6-97BC-4835EA5206A2}
AppPublisherURL=http://i2pd.website/
AppSupportURL=https://github.com/PurpleI2P/i2pd/issues
AppUpdatesURL=https://github.com/PurpleI2P/i2pd/releases

[Files]
Source: ..\i2pd_x86.exe; DestDir: {app}; DestName: i2pd.exe; Flags: ignoreversion; Check: not IsWin64
Source: ..\i2pd_x64.exe; DestDir: {app}; DestName: i2pd.exe; Flags: ignoreversion; Check: IsWin64
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
