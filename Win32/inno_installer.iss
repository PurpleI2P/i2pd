
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
LicenseFile=.\..\LICENSE
OutputBaseFilename=setup_{#I2Pd_AppName}_v{#I2Pd_ver}

[Files]
Source: "i2pd.exe"; DestDir: "{app}"

[Icons]
Name: "{group}\I2Pd"; Filename: "{app}\i2pd.exe"

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