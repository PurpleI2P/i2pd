# NSIS Installer script. (Tested with NSIS 2.64 on Windows 7)
# Author: Mikal Villa (Meeh)
# Version: 1.1
Name PurpleI2P

RequestExecutionLevel highest
SetCompressor /SOLID lzma
ShowInstDetails show

# General Symbol Definitions
!define REGKEY "SOFTWARE\$(^Name)"
!define VERSION 0.3.0.0
!define COMPANY "The Privacy Solutions Project"
!define URL "https://i2p.io"

# MUI Symbol Definitions
!define MUI_ICON "mask.ico"
#!define MUI_WELCOMEFINISHPAGE_BITMAP "../share/pixmaps/nsis-wizard.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
#!define MUI_HEADERIMAGE_BITMAP "../share/pixmaps/nsis-header.bmp"
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_STARTMENUPAGE_REGISTRY_ROOT HKLM
!define MUI_STARTMENUPAGE_REGISTRY_KEY ${REGKEY}
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME StartMenuGroup
!define MUI_STARTMENUPAGE_DEFAULTFOLDER PurpleI2P
!define MUI_FINISHPAGE_RUN $INSTDIR\i2pd.exe
!define MUI_FINISHPAGE_SHOWREADME $INSTDIR\Readme.txt


!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "../share/pixmaps/nsis-wizard.bmp"
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

# Included files
!include Sections.nsh
!include MUI2.nsh
!include nsDialogs.nsh
!include winmessages.nsh
!include logiclib.nsh
# Local included files
!include nsi\helper_readme.nsh
;!include nsi\servicelib.nsh

# Variables
Var StartMenuGroup

# Installer pages
# Execution flow of installer windows
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_README "../Readme.md"
!insertmacro MUI_PAGE_DIRECTORY
# Disabled for now. Use the bat
;Page custom mode_selection # Meeh's hack for installing and starting service.
!insertmacro MUI_PAGE_STARTMENU Application $StartMenuGroup
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

# Uninstall pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

# Installer languages
!insertmacro MUI_LANGUAGE English

# Installer attributes
OutFile PurpleI2P-0.3.0.0-win32-setup.exe
InstallDir $PROGRAMFILES\PurpleI2P
CRCCheck on
XPStyle on
BrandingText " "
ShowInstDetails show
VIProductVersion 0.3.0.0
VIAddVersionKey ProductName PurpleI2P
VIAddVersionKey ProductVersion "${VERSION}"
VIAddVersionKey CompanyName "${COMPANY}"
VIAddVersionKey CompanyWebsite "${URL}"
VIAddVersionKey FileVersion "${VERSION}"
VIAddVersionKey FileDescription ""
VIAddVersionKey LegalCopyright ""
InstallDirRegKey HKCU "${REGKEY}" Path
ShowUninstDetails show

# Readme definitions

;--------------------------------
;Languages
  ;Set up install lang strings for 1st lang
  ${ReadmeLanguage} "${LANG_ENGLISH}" \
          "Read Me" \
          "Please review the following important information." \
          "About $(^name):" \
          "$\n  Click on scrollbar arrows or press Page Down to review the entire text."
 
  ;Add 2nd language
  !insertmacro MUI_LANGUAGE "Norwegian"
 
  ;set up install lang strings for second lang
  ${ReadmeLanguage} "${LANG_NORWEGIAN}" \
          "Les meg!" \
          "Vennligst les informasjonen om hvordan du skal bruke PurpleI2P." \
          "Om $(^name):" \
          "$\n  Klikk på scrollbaren til høyre for å se hele innholdet."
 
;--------------------------------

# Installer sections
Section -Main SEC0000
    SetOutPath $INSTDIR
    SetOverwrite on
    File /oname=i2pd.exe Release\i2pd.exe
    File /oname=install_service.bat install_service.bat
    File /oname=uninstall_service.bat uninstall_service.bat
    File /oname=LICENSE.txt ..\LICENSE
    File /oname=Readme.txt ..\README.md
    SetOutPath $INSTDIR\src
    File /r /x *.nsi /x *.rc /x *.exe /x *.obj /x *.nsh /x *.sln /x *.vcxproj /x *.tlog /x *.log /x *.res /x *.pdb /x *.suo /x *.opensdf /x *.filters /x *.sdf /x *.iss /x *.aps /x .gitignore /x *.o ../\*.*
    SetOutPath $INSTDIR
    RMDir /r /REBOOTOK $INSTDIR\src\.git # Remove git directory
    RMDir /r /REBOOTOK $INSTDIR\src\Win32\Release # Removing release directory
    RMDir /r /REBOOTOK $INSTDIR\src\Win32\nsi
    WriteRegStr HKCU "${REGKEY}\Components" Main 1
SectionEnd

Section -post SEC0001
    WriteRegStr HKCU "${REGKEY}" Path $INSTDIR
    SetOutPath $INSTDIR
    WriteUninstaller $INSTDIR\uninstall.exe
    !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
    CreateDirectory $SMPROGRAMS\$StartMenuGroup
    CreateShortcut "$SMPROGRAMS\$StartMenuGroup\PurpleI2P.lnk" $INSTDIR\i2pd.exe
    CreateShortcut "$SMPROGRAMS\$StartMenuGroup\Install PurpleI2P Service.lnk" $INSTDIR\install_service.bat
    CreateShortcut "$SMPROGRAMS\$StartMenuGroup\Uninstall PurpleI2P Service.lnk" $INSTDIR\uninstall_service.bat
    CreateShortcut "$SMPROGRAMS\$StartMenuGroup\Uninstall PurpleI2P.lnk" $INSTDIR\uninstall.exe
    !insertmacro MUI_STARTMENU_WRITE_END
    WriteRegStr HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$(^Name)" DisplayName "$(^Name)"
    WriteRegStr HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$(^Name)" DisplayVersion "${VERSION}"
    WriteRegStr HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$(^Name)" Publisher "${COMPANY}"
    WriteRegStr HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$(^Name)" URLInfoAbout "${URL}"
    WriteRegStr HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$(^Name)" DisplayIcon $INSTDIR\uninstall.exe
    WriteRegStr HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$(^Name)" UninstallString $INSTDIR\uninstall.exe
    WriteRegDWORD HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$(^Name)" NoModify 1
    WriteRegDWORD HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$(^Name)" NoRepair 1
    WriteRegStr HKCR "i2pd" "URL Protocol" ""
    WriteRegStr HKCR "i2pd" "" "URL:i2pd" # TODO: if a instance of own is found, relaunch with a proxyfied browser to open webage. (e.g i2pd://meeh.i2p)
    WriteRegStr HKCR "i2pd\DefaultIcon" "" $INSTDIR\i2pd.exe
    WriteRegStr HKCR "i2pd\shell\open\command" "" '"$INSTDIR\i2pd.exe" "%1"'
SectionEnd

# Macro for selecting uninstaller sections
!macro SELECT_UNSECTION SECTION_NAME UNSECTION_ID
    Push $R0
    ReadRegStr $R0 HKCU "${REGKEY}\Components" "${SECTION_NAME}"
    StrCmp $R0 1 0 next${UNSECTION_ID}
    !insertmacro SelectSection "${UNSECTION_ID}"
    GoTo done${UNSECTION_ID}
next${UNSECTION_ID}:
    !insertmacro UnselectSection "${UNSECTION_ID}"
done${UNSECTION_ID}:
    Pop $R0
!macroend


# Uninstaller sections
Section /o -un.Main UNSEC0000
    Delete /REBOOTOK $INSTDIR\i2pd.exe
    Delete /REBOOTOK $INSTDIR\LICENSE.txt
    Delete /REBOOTOK $INSTDIR\Readme.txt
    Delete /REBOOTOK $INSTDIR\install_service.bat
    Delete /REBOOTOK $INSTDIR\uninstall_service.bat
    RMDir /r /REBOOTOK $INSTDIR\src
    DeleteRegValue HKCU "${REGKEY}\Components" Main
SectionEnd

Section -un.post UNSEC0001
    DeleteRegKey HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$(^Name)"
    Delete /REBOOTOK "$SMPROGRAMS\$StartMenuGroup\Uninstall PurpleI2P.lnk"
    Delete /REBOOTOK "$SMPROGRAMS\$StartMenuGroup\PurpleI2P.lnk"
    Delete /REBOOTOK "$SMPROGRAMS\$StartMenuGroup\Install PurpleI2P Service.lnk"
    Delete /REBOOTOK "$SMPROGRAMS\$StartMenuGroup\UnInstall PurpleI2P Service.lnk"
    Delete /REBOOTOK "$SMSTARTUP\PurpleI2P.lnk"
    Delete /REBOOTOK $INSTDIR\uninstall.exe
    Delete /REBOOTOK $INSTDIR\debug.log
    DeleteRegValue HKCU "${REGKEY}" StartMenuGroup
    DeleteRegValue HKCU "${REGKEY}" Path
    DeleteRegKey /IfEmpty HKCU "${REGKEY}\Components"
    DeleteRegKey /IfEmpty HKCU "${REGKEY}"
    DeleteRegKey HKCR "i2pd"
    RmDir /REBOOTOK $SMPROGRAMS\$StartMenuGroup
    RmDir /REBOOTOK $INSTDIR
    Push $R0
    StrCpy $R0 $StartMenuGroup 1
    StrCmp $R0 ">" no_smgroup
no_smgroup:
    Pop $R0
SectionEnd

; var hwndExecModeRadio
; var hwndRunServiceNowRadio

; Function mode_selection
;     nsDialogs::Create 1018 
;     Pop $0
;     ${NSD_CreateLabel} 0 10 75% 20u "How would you like PurpleI2P (i2pd) to run?"
;     Pop $0 

;     ${NSD_CreateRadioButton} 20 60 80% 25u "Service Mode"
;     Pop $hwndExecModeRadio
;     ${NSD_AddStyle} $hwndExecModeRadio ${WS_GROUP}

;     ${NSD_CreateRadioButton} 20 90 80% 25u "Command line Mode"
;     Pop $0

;     ${NSD_CreateButton} 20 150 -40 14u "Do it!"
;     Pop $0
;     ${NSD_OnClick} $0 perform_mode

;     nsDialogs::Show
; FunctionEnd

; Function start_now_selection
;     nsDialogs::Create 1018 
;     Pop $0
;     ${NSD_CreateLabel} 0 10 75% 20u "Enable the service now?"
;     Pop $0 

;     ${NSD_CreateRadioButton} 20 60 80% 25u "Yes"
;     Pop $hwndRunServiceNowRadio
;     ${NSD_AddStyle} $hwndRunServiceNowRadio ${WS_GROUP}

;     ${NSD_CreateRadioButton} 20 90 80% 25u "No"
;     Pop $0

;     ${NSD_CreateButton} 20 150 -40 14u "Do it!"
;     Pop $0
;     ${NSD_OnClick} $0 perform_mode

;     nsDialogs::Show
; FunctionEnd

; Function perform_mode
;     ${NSD_GetState} $hwndExecModeRadio $0
;     ${If} $0 = ${BST_CHECKED}
;         Call service_mode
;     ${EndIF}
; FunctionEnd

; Function start_now
;     ${NSD_GetState} $hwndRunServiceNowRadio $0
;     ${If} $0 = ${BST_CHECKED}
;         Call start_now_selection
;     ${EndIF}
; FunctionEnd

; Function service_mode
;     Push "create"
;     Push "PurpleI2P Service"
;     Push "$INSTDIR\i2pd.exe;autostart=1;display=PurpleI2P"
;     Call Service
;     Pop $0 ; Actually more to write than !insertmacro, but much more fun :D
;     Push "start"
;     Push "PurpleI2P Service"
;     Call Service
;     Pop $0
;     Call start_now
;     !define MUI_FINISHPAGE_RUN_NOTCHECKED
;     !define MUI_FINISHPAGE_RUN_TEXT "No need to run now since we already installed and launched it as a Windows service!"
; FunctionEnd

# Installer functions
Function .onInit
    InitPluginsDir
    !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

# Uninstaller functions
Function un.onInit
    ReadRegStr $INSTDIR HKCU "${REGKEY}" Path
    !insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuGroup
    !insertmacro SELECT_UNSECTION Main ${UNSEC0000}
    !insertmacro MUI_UNGETLANGUAGE
FunctionEnd