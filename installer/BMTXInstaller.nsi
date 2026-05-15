Unicode true
SetCompressor /SOLID lzma
RequestExecutionLevel admin
ManifestSupportedOS all

!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"

!ifndef APP_BUILD_DIR
  !define APP_BUILD_DIR "..\build\Release"
!endif
!ifndef PROJECT_DIR
  !define PROJECT_DIR ".."
!endif
!ifndef OUT_DIR
  !define OUT_DIR "."
!endif

!define APP_NAME "BMTX"
!define COMPANY_NAME "BMTX"
!define SERVICE_NAME "BMTXService"
!define SERVICE_EXE "BMTXService.exe"
!define CLIENT_EXE "BMTX.exe"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\BMTX"

Name "${APP_NAME}"
OutFile "${OUT_DIR}\BMTXSetup.exe"
InstallDir "$PROGRAMFILES64\BMTX"
InstallDirRegKey HKLM "${UNINSTALL_KEY}" "InstallLocation"
BrandingText "${APP_NAME} Installer"

!define MUI_ABORTWARNING
!define MUI_ICON "${PROJECT_DIR}\assets\bmtx.ico"
!define MUI_UNICON "${PROJECT_DIR}\assets\bmtx.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "64-bit Windows is required to install this application."
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Section "BMTX Application" SEC_APP
  SetShellVarContext all
  SetOutPath "$INSTDIR"

  DetailPrint "Stopping previous service installation if it exists..."
  ExecWait 'sc stop ${SERVICE_NAME}'
  Sleep 1500
  ExecWait 'sc delete ${SERVICE_NAME}'
  Sleep 1000

  DetailPrint "Installing executable files..."
  File "${APP_BUILD_DIR}\${CLIENT_EXE}"
  File "${APP_BUILD_DIR}\${SERVICE_EXE}"
  File /nonfatal "${APP_BUILD_DIR}\*.dll"
  File /nonfatal "${APP_BUILD_DIR}\*.config"
  File /nonfatal "${APP_BUILD_DIR}\*.json"

  SetOutPath "$INSTDIR\assets"
  File "${PROJECT_DIR}\assets\bmtx.ico"
  File "${PROJECT_DIR}\assets\bmtx_icon_preview.png"

  SetOutPath "$INSTDIR\avdb"
  File "${PROJECT_DIR}\avdb\bmtx_avdb.bin"
  File "${PROJECT_DIR}\avdb\bmtx_avdb.bak"

  SetOutPath "$INSTDIR"

  DetailPrint "Registering Windows service for automatic startup..."
  ExecWait '"$INSTDIR\${SERVICE_EXE}" --install' $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Failed to register service ${SERVICE_NAME}. Error code: $0"
    Abort
  ${EndIf}

  DetailPrint "Starting Windows service..."
  ExecWait 'sc start ${SERVICE_NAME}'

  CreateDirectory "$SMPROGRAMS\BMTX"
  CreateShortcut "$SMPROGRAMS\BMTX\BMTX.lnk" "$INSTDIR\${CLIENT_EXE}" "" "$INSTDIR\assets\bmtx.ico"
  CreateShortcut "$DESKTOP\BMTX.lnk" "$INSTDIR\${CLIENT_EXE}" "" "$INSTDIR\assets\bmtx.ico"

  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "1.0.0"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "${COMPANY_NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\assets\bmtx.ico"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Third-party runtime dependencies" SEC_DEPS
  DetailPrint "No separate third-party dependencies are installed: the application is built with the static MSVC runtime (/MT)."
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  SetRegView 64

  DetailPrint "Stopping and removing Windows service..."
  ExecWait 'sc stop ${SERVICE_NAME}'
  Sleep 2000
  ExecWait '"$INSTDIR\${SERVICE_EXE}" --uninstall' $0
  ExecWait 'sc delete ${SERVICE_NAME}'
  Sleep 1000

  DetailPrint "Removing application files..."
  Delete "$DESKTOP\BMTX.lnk"
  Delete "$SMPROGRAMS\BMTX\BMTX.lnk"
  RMDir "$SMPROGRAMS\BMTX"

  Delete "$INSTDIR\${CLIENT_EXE}"
  Delete "$INSTDIR\${SERVICE_EXE}"
  Delete "$INSTDIR\*.dll"
  Delete "$INSTDIR\*.config"
  Delete "$INSTDIR\*.json"
  Delete "$INSTDIR\Uninstall.exe"

  RMDir /r "$INSTDIR\assets"
  RMDir /r "$INSTDIR\avdb"

  RMDir /r "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"

  DetailPrint "No separate third-party dependencies are removed: the installer does not install them because the MSVC runtime is linked statically."
SectionEnd