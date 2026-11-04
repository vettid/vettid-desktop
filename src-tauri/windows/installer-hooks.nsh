; VettID Desktop: hooks for the Windows (NSIS) installer and uninstaller,
; included by tauri-bundler's installer.nsi (bundle > windows > nsis >
; installerHooks in tauri.conf.json).
;
; On uninstall, the saved pairing is deleted, always, silent (/S) included:
; the app's own confirmed log-out wipe, `vettid-desktop.exe --uninstall-wipe`
; (src/uninstall.rs). It doesn't contact the vault: the phone still lists
; the desktop, and only the phone can remove it.
;
; Exit codes of --uninstall-wipe:
;   0  nothing was paired here
;   10 a pairing was saved here, and every part is confirmed gone
;   20 something couldn't be removed or confirmed
; Anything else, or the program not running at all, is treated as 20.
;
; Not on an update (/UPDATE, as the updater and an update-mode reinstall
; run the old uninstaller): an update must never delete the pairing.
;
; Nor when an installer runs this uninstaller (owner decision "a",
; 2026-11-04): an upgrade or downgrade by hand, whose default is "Uninstall
; before installing", or a same-version reinstall that chose "Uninstall",
; must keep the pairing too. The installer runs the old uninstaller in
; place, `uninstall.exe _?=$INSTDIR` (installer.nsi, PageLeaveReinstall),
; with no /UPDATE. An uninstall from Windows' Apps list, or `uninstall.exe
; /S`, first copies the uninstaller to a temporary folder and runs the copy
; there; `_?=` stops that copy (NSIS manual, 3.2 "Uninstaller"). So the
; uninstaller running from $INSTDIR itself ($EXEDIR = $INSTDIR) means an
; installer, or a script, ran it in place. A script that runs `uninstall.exe
; /S _?=<folder>` in place therefore also keeps the pairing; it must run
; `uninstall.exe /S` without `_?=` to delete it.

; $0 = 1 if this uninstaller runs from $INSTDIR, else 0. The two paths are
; compared in short (8.3) form, without a trailing backslash; NSIS string
; comparison ignores case. Uses $1 and $2.
!macro VETTID_UNINSTALLER_IN_PLACE
  StrCpy $1 $EXEDIR
  StrCpy $2 $INSTDIR
  ClearErrors
  GetFullPathName /SHORT $0 $1
  ${IfNot} ${Errors}
  ${AndIf} $0 != ""
    StrCpy $1 $0
  ${EndIf}
  ClearErrors
  GetFullPathName /SHORT $0 $2
  ${IfNot} ${Errors}
  ${AndIf} $0 != ""
    StrCpy $2 $0
  ${EndIf}
  ${If} $1 != ""
  ${AndIf} $1 != "\"
    StrCpy $0 $1 1 -1
    ${IfThen} $0 == "\" ${|} StrCpy $1 $1 -1 ${|}
  ${EndIf}
  ${If} $2 != ""
  ${AndIf} $2 != "\"
    StrCpy $0 $2 1 -1
    ${IfThen} $0 == "\" ${|} StrCpy $2 $2 -1 ${|}
  ${EndIf}
  ${If} $1 == $2
    StrCpy $0 1
  ${Else}
    StrCpy $0 0
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro VETTID_UNINSTALLER_IN_PLACE
  ${If} $UpdateMode <> 1
  ${AndIf} $0 <> 1
    ; The template checks for the running app only after this hook. A
    ; running app could save the pairing again after the wipe, so it is
    ; closed first (in a silent uninstall without asking; if it can't be
    ; closed, or the person cancels, the uninstall stops here, before
    ; anything is removed).
    !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

    ClearErrors
    ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --uninstall-wipe' $0
    ${If} ${Errors}
      StrCpy $0 -1
    ${EndIf}

    ${If} $0 = 10
      ${IfNot} ${Silent}
        ; NEW TEXT (owner approval needed).
        MessageBox MB_OK|MB_ICONINFORMATION "This desktop was paired. Remove it on your phone too." /SD IDOK
      ${EndIf}
    ${ElseIf} $0 <> 0
      ; A scripted uninstall can tell: the uninstall goes on, but its exit
      ; code is 2, not 0.
      SetErrorLevel 2
      ${IfNot} ${Silent}
        ReadEnvStr $1 LOCALAPPDATA
        ${If} $1 == ""
          StrCpy $1 "%LOCALAPPDATA%"
        ${EndIf}
        ; NEW TEXT (owner approval needed).
        MessageBox MB_OK|MB_ICONEXCLAMATION "This desktop's saved pairing couldn't be removed from this computer, or its removal couldn't be confirmed. If the folder $1\vettid-desktop is still there, delete it, and delete any vettid-desktop entry in Windows Credential Manager. Remove this desktop on your phone too." /SD IDOK
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend
