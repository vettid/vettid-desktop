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

; The path in ${reg} in short (8.3) form, without a trailing backslash or
; surrounding quotes, as VETTID_UNINSTALLER_IN_PLACE compares them. Uses $0.
!macro VETTID_NORMALISE reg
  StrCpy $0 ${reg} 1
  ${If} $0 == '"'
    StrCpy $0 ${reg} 1 -1
    ${If} $0 == '"'
      StrCpy ${reg} ${reg} -1 1
    ${EndIf}
  ${EndIf}
  ClearErrors
  GetFullPathName /SHORT $0 ${reg}
  ${IfNot} ${Errors}
  ${AndIf} $0 != ""
    StrCpy ${reg} $0
  ${EndIf}
  ${If} ${reg} != ""
  ${AndIf} ${reg} != "\"
    StrCpy $0 ${reg} 1 -1
    ${IfThen} $0 == "\" ${|} StrCpy ${reg} ${reg} -1 ${|}
  ${EndIf}
!macroend

; $0 = 1 if the account this uninstaller runs as is the one that installed
; at $INSTDIR: its own HKCU records $INSTDIR, as the product key's default
; value or the uninstall entry's InstallLocation (written by the installer,
; deleted by Section Uninstall only after NSIS_HOOK_PREUNINSTALL). Else 0.
;
; The wipe (the app's own, run by ExecWait as this account) deletes this
; account's pairing, from its known folder and its Credential Manager. A
; per-user install uninstalled as another account ("Run as administrator"
; with an administrator's password) would otherwise wipe the
; administrator's own pairing, report "nothing was paired", and keep the
; installing user's. Uses $0 to $3.
!macro VETTID_INSTALLED_FOR_THIS_USER
  StrCpy $2 $INSTDIR
  !insertmacro VETTID_NORMALISE $2
  StrCpy $3 0
  ReadRegStr $1 HKCU "${MANUPRODUCTKEY}" ""
  !insertmacro VETTID_NORMALISE $1
  ${If} $1 != ""
  ${AndIf} $1 == $2
    StrCpy $3 1
  ${EndIf}
  ${If} $3 = 0
    ReadRegStr $1 HKCU "${UNINSTKEY}" "InstallLocation"
    !insertmacro VETTID_NORMALISE $1
    ${If} $1 != ""
    ${AndIf} $1 == $2
      StrCpy $3 1
    ${EndIf}
  ${EndIf}
  StrCpy $0 $3
!macroend

; The wipe's result, from NSIS_HOOK_PREUNINSTALL to NSIS_HOOK_POSTUNINSTALL:
; "" if the wipe was skipped (update, in place, no $INSTDIR), else its exit
; code, or -1 if the program couldn't be started. (-2, this account didn't
; install at $INSTDIR, or the install isn't per-user, never reaches
; NSIS_HOOK_POSTUNINSTALL: the uninstall is refused before anything is
; removed.)
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
    ; /WIPEPAIRING: a script asks for the wipe in place, so that it can wait
    ; for the uninstall and see its exit code (0, or 2 if the pairing
    ; couldn't be removed or confirmed): `uninstall.exe /S /WIPEPAIRING
    ; _?=<install folder>`. A plain `uninstall.exe /S` returns before its
    ; temporary copy has run, always with 0. No installer passes this
    ; switch, so an upgrade, downgrade or reinstall still keeps the pairing;
    ; /UPDATE still skips the wipe, with or without it.
    ${If} $0 = 1
      ClearErrors
      ${GetOptions} $CMDLINE "/WIPEPAIRING" $1
      ${IfNot} ${Errors}
        StrCpy $0 0
      ${EndIf}
    ${EndIf}
    ${If} $UpdateMode <> 1
    ${AndIf} $0 <> 1
      ; Only a per-user install, uninstalled by the account that installed
      ; it. A per-machine install would be uninstalled elevated, by any
      ; account: whose pairing to delete can't be told.
      ; Any other install mode fails the build, rather than making the app
      ; impossible to uninstall (every uninstall would be refused below).
      !if "${INSTALLMODE}" == "currentUser"
        !insertmacro VETTID_INSTALLED_FOR_THIS_USER
      !else
        !error "installer-hooks.nsh: the uninstall wipe supports only a per-user install (installMode currentUser), not ${INSTALLMODE}"
      !endif
      ${If} $0 <> 1
        ; Refused, before anything is removed: going on would delete the
        ; program, the uninstaller and this account's registry entries,
        ; and leave the installing account's pairing with no app to log
        ; out from and no uninstaller to run. Exit code 2, an event, and the
        ; box if someone is watching. Quit, not Abort: an aborted section
        ; leaves the progress page open, waiting for a click, and under /P
        ; nobody gives it (seen in the mock).
        StrCpy $VettidWipe -2
        SetErrorLevel 2
        ; NEW TEXT (owner approval needed).
        StrCpy $7 "VettID Desktop wasn't uninstalled: the uninstaller ran as a Windows account that didn't install it, and uninstalling it would leave the installing account's saved pairing on this computer. Sign in as the account that installed VettID Desktop, and uninstall it there."
        !insertmacro VETTID_REPORT_EVENT 1002
        ${IfNot} ${Silent}
        ${AndIf} $PassiveMode <> 1
          ; NEW TEXT (owner approval needed).
          MessageBox MB_OK|MB_ICONEXCLAMATION "VettID Desktop wasn't uninstalled. This Windows account isn't the one that installed it, and uninstalling it from here would leave that account's saved pairing on this computer. Sign in as the account that installed VettID Desktop, and uninstall it there." /SD IDOK
        ${EndIf}
        Quit
      ${Else}
        ; Close a running app first, so it can't save the pairing again
        ; after the wipe. This check can silently do nothing (when the
        ; Restart Manager session or registration fails), and the app could
        ; be started again before the wipe: the result is therefore decided
        ; in NSIS_HOOK_POSTUNINSTALL, after the template's own app check
        ; and the removal of the program, from what is on disk then. If the
        ; person cancels, or the app can't be closed, the uninstall stops
        ; here.
        ;
        ; The path form of CheckIfAppIsRunning's first argument is
        ; tauri-cli 2.12's (tested with 2.12.2). Earlier templates take a
        ; process name there, and this check would silently do nothing: the
        ; post-check below would then be the only safeguard. Build with
        ; tauri-cli 2.12.2 or later.
        !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

        ClearErrors
        ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --uninstall-wipe' $0
        ${If} ${Errors}
          StrCpy $0 -1
        ${EndIf}
        StrCpy $VettidWipe $0
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend

; A Warning with the text in $7, source "VettID Desktop", in the Application
; log: event ID 1001 for an uninstall whose pairing couldn't be removed or
; confirmed, 1002 for an uninstall refused because another account ran it,
; 1003 for an uninstall that couldn't delete the program itself, 1004 for an
; uninstall that stopped before it finished (un.onUninstFailed, below).
; The source isn't registered (that needs an administrator), so Event Viewer
; says the event's description isn't found and shows the text as the
; event's data. `Get-WinEvent -LogName Application -FilterXPath
; "*[System[Provider[@Name='VettID Desktop']]]"` finds it (a ProviderName
; filter doesn't, for an unregistered source). An account may write to the
; Application log without elevation. If the write fails, nothing else
; changes: the exit code is 2 regardless. The texts name no person, folder
; or account. Uses $4 to $7.
!macro VETTID_REPORT_EVENT id
  System::Call 'advapi32::RegisterEventSourceW(p 0, w "VettID Desktop") p .r4'
  ${If} $4 != 0
    System::Call '*(w r7) p .r5'
    ${If} $5 != 0
      System::Call 'advapi32::ReportEventW(p r4, i 2, i 0, i ${id}, p 0, i 1, i 0, p r5, p 0) i .r6'
      System::Free $5
    ${EndIf}
    System::Call 'advapi32::DeregisterEventSource(p r4)'
  ${EndIf}
!macroend

; #74: an uninstall that stops part way exits with 2 and wrote no event: an
; `Abort` in Section Uninstall, most likely the template's own
; CheckIfAppIsRunning (in NSIS_HOOK_PREUNINSTALL above, and again in the
; template after it) when the app is running and can't be closed, or the
; person cancels. NSIS calls un.onUninstFailed then, silent (/S) included;
; not after `Quit` (the 1002 refusal above, which writes its own event), and
; not after a finished uninstall (checked in a test uninstaller, makensis
; 3.11). The template doesn't define it. Nothing is claimed removed: the
; program, the uninstaller and the saved pairing may all still be there.
Function un.onUninstFailed
  ; NEW TEXT (owner approval needed).
  StrCpy $7 "VettID Desktop's uninstall stopped before it finished, so nothing was confirmed removed: the program and this desktop's saved pairing may still be on this computer. This usually means VettID Desktop was running and couldn't be closed. Close it, then uninstall again."
  !insertmacro VETTID_REPORT_EVENT 1004
FunctionEnd

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $VettidWipe != ""
    ; $2 = 1 if a pairing file is seen there now. An extra check, not the
    ; confirmation (that is the wipe's own 10 or 11): FileExists reads a
    ; folder it can't list as empty.
    ;
    ; The current user's local app data, from the known folder as the app
    ; finds it (not the LOCALAPPDATA environment variable, which may be stale
    ; or overridden). This is the end of Section Uninstall, so changing the
    ; context here affects nothing after it.
    StrCpy $2 0
    SetShellVarContext current
    StrCpy $1 $LOCALAPPDATA
    ${If} $1 == ""
      StrCpy $2 1
      StrCpy $1 "%LOCALAPPDATA%"
    ${ElseIf} ${FileExists} "$1\vettid-desktop\device.enc"
    ${OrIf} ${FileExists} "$1\vettid-desktop\connection.enc"
    ${OrIf} ${FileExists} "$1\vettid-desktop\*.tmp-*"
      StrCpy $2 1
    ${EndIf}
    ; $8 = 1 if the program is still there: it may still be running, and
    ; save again. That is a failure too, with its own text.
    StrCpy $8 0
    ${If} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
      StrCpy $2 1
      StrCpy $8 1
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
      ; A scripted uninstall that waits (/WIPEPAIRING, above) can tell: the
      ; uninstall finished, but its exit code is 2, not 0.
      SetErrorLevel 2
      ; Silent or not, the failure is also written to the Windows Application
      ; event log, where it outlives the uninstall and where IT tools look: a
      ; plain `uninstall.exe /S` returns 0 before this runs, and shows no box.
      ${If} $8 = 1
        ; The program couldn't be deleted: "uninstalled" would be false.
        ; NEW TEXT (owner approval needed).
        StrCpy $7 "VettID Desktop couldn't be fully removed from this computer: its program was still in its folder after the uninstall, and may still be running (result $VettidWipe). Close VettID Desktop, then delete its program folder; for the account that installed it, also delete %LOCALAPPDATA%\vettid-desktop if it's there, and any vettid-desktop entry in that account's Windows Credential Manager. Remove this desktop on the phone too."
        !insertmacro VETTID_REPORT_EVENT 1003
        ${If} $3 = 1
          ; NEW TEXT (owner approval needed).
          MessageBox MB_OK|MB_ICONEXCLAMATION "VettID Desktop couldn't be fully removed from this computer: its program is still in $INSTDIR, and may still be running. Close VettID Desktop, then delete that folder. Also delete $1\vettid-desktop if it's there, and any vettid-desktop entry in Windows Credential Manager. Remove this desktop on your phone too." /SD IDOK
        ${EndIf}
      ${Else}
        ; NEW TEXT (owner approval needed).
        StrCpy $7 "VettID Desktop was uninstalled, but this desktop's saved pairing couldn't be removed from this computer, or its removal couldn't be confirmed (result $VettidWipe). If %LOCALAPPDATA%\vettid-desktop is still there for the account that installed it, delete it, and delete any vettid-desktop entry in that account's Windows Credential Manager. Remove this desktop on the phone too."
        !insertmacro VETTID_REPORT_EVENT 1001
        ${If} $3 = 1
          ; NEW TEXT (owner approval needed).
          MessageBox MB_OK|MB_ICONEXCLAMATION "VettID Desktop was uninstalled, but this desktop's saved pairing couldn't be removed from this computer, or its removal couldn't be confirmed. If the folder $1\vettid-desktop is still there, delete it, and delete any vettid-desktop entry in Windows Credential Manager. Remove this desktop on your phone too." /SD IDOK
        ${EndIf}
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend
