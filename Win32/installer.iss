#define I2Pd_AppName "i2pd"
#define I2Pd_ver "2.10.0"

[Setup]
AppName={#I2Pd_AppName}
AppVersion={#I2Pd_ver}
DefaultDirName={pf}\I2Pd
DefaultGroupName=I2Pd
UninstallDisplayIcon={app}\I2Pd.exe
OutputDir=.
LicenseFile=../LICENSE
OutputBaseFilename=setup_{#I2Pd_AppName}_v{#I2Pd_ver}
InternalCompressLevel=ultra64
Compression=lzma/ultra64
SolidCompression=true
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "..\i2pd_x86.exe"; DestDir: "{app}"; DestName: "i2pd.exe"; Flags: ignoreversion; Check: not IsWin64
Source: "..\i2pd_x64.exe"; DestDir: "{app}"; DestName: "i2pd.exe"; Flags: ignoreversion; Check: IsWin64
Source: "..\README.md"; DestDir: "{app}"; DestName: "Readme.txt"; Flags: onlyifdoesntexist
Source: "..\docs\i2pd.conf"; DestDir: "{userappdata}\i2pd"; Flags: onlyifdoesntexist
Source: "..\docs\subscriptions.txt"; DestDir: "{userappdata}\i2pd"; Flags: onlyifdoesntexist
Source: "..\docs\tunnels.conf"; DestDir: "{userappdata}\i2pd"; Flags: onlyifdoesntexist
Source: "..\contrib\*"; DestDir: "{userappdata}\i2pd"; Flags: onlyifdoesntexist recursesubdirs createallsubdirs

[Icons]
Name: "{group}\I2Pd"; Filename: "{app}\i2pd.exe"
Name: "{group}\Readme"; Filename: "{app}\Readme.txt"

[UninstallDelete]
Type: filesandordirs; Name: {app}\*
