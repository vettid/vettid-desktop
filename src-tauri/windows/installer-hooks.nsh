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
;   10 a pairing was saved here, and every part is confirmed gone
;   11 nothing was paired here
;   20 something couldn't be removed or confirmed
; Anything else, 0 included (a program that ignores the switch, such as an
; older build, exits 0), or the program not starting, is a failure.
;
; The wipe runs in NSIS_HOOK_PREUNINSTALL; what the person is told, and the
; exit code, are decided in NSIS_HOOK_POSTUNINSTALL, from the wipe's code
; and a check of the files then.
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

; The wipe's result, from NSIS_HOOK_PREUNINSTALL to NSIS_HOOK_POSTUNINSTALL:
; "" if the wipe was skipped (update, in place, no $INSTDIR), else its exit
; code, or -1 if the program couldn't be started.
Var VettidWipe

; Why these are macros, not functions: this file is included near the top
; of installer.nsi, before the template declares $UpdateMode and
; $PassiveMode and defines MAINBINARYNAME and PRODUCTNAME. A function here
; would read "$UpdateMode" as a literal string (makensis 3.11: warning
; 6000, "unknown variable/constant ... ignoring"), and the /UPDATE skip
; would silently stop working. Macros are expanded where they are inserted,
; inside Section Uninstall, after all of those.
;
; CheckIfAppIsRunning is inserted twice in Section Uninstall (here and by
; the template). Its labels use ${__LINE__}, which makensis expands with the
; insertion's line and nesting ("786.1.1" here, "789.1" for the template's,
; checked with makensis 3.11), so they don't collide.

!macro NSIS_HOOK_PREUNINSTALL
  StrCpy $VettidWipe ""
  ; No $INSTDIR (say, a missing install-location entry): skip, rather than
  ; report a failure that didn't happen.
  ${If} $INSTDIR != ""
    !insertmacro VETTID_UNINSTALLER_IN_PLACE
    ${If} $UpdateMode <> 1
    ${AndIf} $0 <> 1
      ; Close a running app first, so it can't save the pairing again after
      ; the wipe. This check can silently do nothing (when the Restart
      ; Manager session or registration fails), and the app could be
      ; started again before the wipe: the result is therefore decided in
      ; NSIS_HOOK_POSTUNINSTALL, after the template's own app check and the
      ; removal of the program, from what is on disk then. If the person
      ; cancels, or the app can't be closed, the uninstall stops here.
      !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

      ClearErrors
      ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --uninstall-wipe' $0
      ${If} ${Errors}
        StrCpy $0 -1
      ${EndIf}
      StrCpy $VettidWipe $0
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $VettidWipe != ""
    ; $2 = 1 if a pairing file is there now, or that can't be checked.
    StrCpy $2 0
    ReadEnvStr $1 LOCALAPPDATA
    ${If} $1 == ""
      StrCpy $2 1
      StrCpy $1 "%LOCALAPPDATA%"
    ${ElseIf} ${FileExists} "$1\vettid-desktop\device.enc"
    ${OrIf} ${FileExists} "$1\vettid-desktop\connection.enc"
    ${OrIf} ${FileExists} "$1\vettid-desktop\*.tmp-*"
      StrCpy $2 1
    ${EndIf}
    ; The program still there: it may still be running, and save again.
    ${If} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
      StrCpy $2 1
    ${EndIf}

    ; $3 = 1 if a person is watching: not silent, not passive (/P, where a
    ; box would wait for a click nobody gives).
    StrCpy $3 0
    ${IfNot} ${Silent}
    ${AndIf} $PassiveMode <> 1
      StrCpy $3 1
    ${EndIf}

    ${If} $VettidWipe = 10
    ${AndIf} $2 = 0
      ${If} $3 = 1
        ; NEW TEXT (owner approval needed).
        MessageBox MB_OK|MB_ICONINFORMATION "This desktop was paired. Remove it on your phone too." /SD IDOK
      ${EndIf}
    ${ElseIf} $VettidWipe = 11
    ${AndIf} $2 = 0
      ; Nothing was paired, and nothing is there.
    ${Else}
      ; A scripted uninstall can tell: the uninstall finished, but its exit
      ; code is 2, not 0.
      SetErrorLevel 2
      ${If} $3 = 1
        ; NEW TEXT (owner approval needed).
        MessageBox MB_OK|MB_ICONEXCLAMATION "This desktop's saved pairing couldn't be removed from this computer, or its removal couldn't be confirmed. If the folder $1\vettid-desktop is still there, delete it, and delete any vettid-desktop entry in Windows Credential Manager. Remove this desktop on your phone too." /SD IDOK
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend
