
#define I2Pd_AppName "i2pd" 
#define I2Pd_ver "0.1" 

[Setup]
AppName={#I2Pd_AppName} 
AppVersion={#I2Pd_ver} 
DefaultDirName={pf}\I2Pd
DefaultGroupName=I2Pd
UninstallDisplayIcon={app}\I2Pd.exe
Compression=lzma2
SolidCompression=yes
OutputDir=.
OutputBaseFilename=setup_{#I2Pd_AppName}_v{#I2Pd_ver}

[Files]
Source: "i2pd.exe"; DestDir: "{app}"

[Icons]
Name: "{group}\I2Pd"; Filename: "{app}\i2pd.exe"
