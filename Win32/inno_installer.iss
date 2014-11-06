
#define I2Pd_AppName "i2pd"
#define I2Pd_ver "0.2"

[Setup]
AppName={#I2Pd_AppName}
AppVersion={#I2Pd_ver}
DefaultDirName={pf}\I2Pd
DefaultGroupName=I2Pd
UninstallDisplayIcon={app}\I2Pd.exe
Compression=lzma2
SolidCompression=yes
OutputDir=.
LicenseFile=.\..\LICENSE
OutputBaseFilename=setup_{#I2Pd_AppName}_v{#I2Pd_ver}
ArchitecturesInstallIn64BitMode=x64


[Files]
Source: "x64\Release\i2pd.exe"; DestDir: "{app}"; DestName: "i2pd.exe"; Check: Is64BitInstallMode
Source: "Release\i2pd.exe"; DestDir: "{app}"; Check: not Is64BitInstallMode
Source: "..\README.md"; DestDir: "{app}"; DestName: "Readme.txt"; AfterInstall: ConvertLineEndings

[Icons]
Name: "{group}\I2Pd"; Filename: "{app}\i2pd.exe"
Name: "{group}\Readme"; Filename: "{app}\Readme.txt"


[Registry]
Root: HKCU; Subkey: "Environment"; ValueName: "Path"; ValueType: "string"; ValueData: "{app};{olddata}"; Check: NotOnPathAlready(); Flags: preservestringtype;

[Code]

var
  DefaultTop,
  DefaultLeft,
  DefaultHeight,
  DefaultBackTop,
  DefaultNextTop,
  DefaultCancelTop,
  DefaultBevelTop,
  DefaultOuterHeight: Integer;

const
  LicenseHeight = 400;
   LF = #10;
   CR = #13;
   CRLF = CR + LF;

procedure ConvertLineEndings();
  var
     FilePath : String;
     FileContents : String;
begin
   FilePath := ExpandConstant(CurrentFileName)
   LoadStringFromFile(FilePath, FileContents);
   StringChangeEx(FileContents, LF, CRLF, False);
   SaveStringToFile(FilePath, FileContents, False);
end;

procedure InitializeWizard();
begin
  DefaultTop := WizardForm.Top;
  DefaultLeft := WizardForm.Left;
  DefaultHeight := WizardForm.Height;
  DefaultBackTop := WizardForm.BackButton.Top;
  DefaultNextTop := WizardForm.NextButton.Top;
  DefaultCancelTop := WizardForm.CancelButton.Top;
  DefaultBevelTop := WizardForm.Bevel.Top;
  DefaultOuterHeight := WizardForm.OuterNotebook.Height;

  WizardForm.InnerPage.Height := WizardForm.InnerPage.Height + (LicenseHeight - DefaultHeight);
  WizardForm.InnerNotebook.Height :=  WizardForm.InnerNotebook.Height + (LicenseHeight - DefaultHeight);
  WizardForm.LicensePage.Height := WizardForm.LicensePage.Height + (LicenseHeight - DefaultHeight);
  WizardForm.LicenseMemo.Height := WizardForm.LicenseMemo.Height + (LicenseHeight - DefaultHeight);
  WizardForm.LicenseNotAcceptedRadio.Top := WizardForm.LicenseNotAcceptedRadio.Top + (LicenseHeight - DefaultHeight);
  WizardForm.LicenseAcceptedRadio.Top := WizardForm.LicenseAcceptedRadio.Top + (LicenseHeight - DefaultHeight);

end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpLicense then
  begin
    WizardForm.Top := DefaultTop - (LicenseHeight - DefaultHeight) div 2;
    WizardForm.Height := LicenseHeight;
    WizardForm.OuterNotebook.Height := WizardForm.OuterNotebook.Height + (LicenseHeight - DefaultHeight);
    WizardForm.CancelButton.Top := DefaultCancelTop + (LicenseHeight - DefaultHeight);
    WizardForm.NextButton.Top := DefaultNextTop + (LicenseHeight - DefaultHeight);
    WizardForm.BackButton.Top := DefaultBackTop + (LicenseHeight - DefaultHeight);
    WizardForm.Bevel.Top := DefaultBevelTop + (LicenseHeight - DefaultHeight);
  end
  else
  begin
    WizardForm.Top := DefaultTop;
    WizardForm.Left := DefaultLeft;
    WizardForm.Height := DefaultHeight;
    WizardForm.OuterNotebook.Height := DefaultOuterHeight;
    WizardForm.CancelButton.Top := DefaultCancelTop;
    WizardForm.NextButton.Top := DefaultNextTop;
    WizardForm.BackButton.Top := DefaultBackTop;
    WizardForm.Bevel.Top := DefaultBevelTop;
  end;
end;

function NotOnPathAlready(): Boolean;
var
  BinDir, Path: String;
begin
  Log('Checking if i2pd dir is already in the %PATH%');
  if RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Path) then
  begin // Successfully read the value
    Log('HKCUEnvironmentPATH = ' + Path);
    BinDir := ExpandConstant('{app}');
    Log('Looking for i2pd dir in %PATH%: ' + BinDir + ' in ' + Path);
    if Pos(LowerCase(BinDir), Lowercase(Path)) = 0 then
    begin
      Log('Did not find i2pd dir in %PATH% so I will add it');
      Result := True;
    end
    else
    begin
      Log('Found i2pd dir in %PATH% so will not add it again');
      Result := False;
    end
  end
  else // The key probably doesn't exist
  begin
    Log('Could not access HKCUEnvironmentPATH so I assume that it is OK to add it');
    Result := True;
  end;
end;


procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  BinDir, Path: String;
begin
  if (CurUninstallStep = usPostUninstall)
     and (RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'PATH', Path)) then
  begin
    BinDir := ExpandConstant('{app}');
    if Pos(LowerCase(BinDir) + ';', Lowercase(Path)) <> 0 then
    begin
      StringChange(Path, BinDir + ';', '');
      RegWriteStringValue(HKEY_CURRENT_USER, 'Environment', 'PATH', Path);
    end;
  end;
end;
