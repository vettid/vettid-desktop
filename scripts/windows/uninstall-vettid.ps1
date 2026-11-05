# Uninstall VettID Desktop for the signed-in user, and report whether the saved pairing is confirmed gone.
# Run it as that user (user context), not as SYSTEM: see docs/WINDOWS-TESTING.md, "IT-managed installs".
# Exit 0: uninstalled, and the pairing confirmed gone (or nothing was installed or paired).
# Exit 2: not confirmed, or anything unexpected (events 1001-1003 in the Application log say more).
$ErrorActionPreference = 'Stop'
try {
    function Exists($path) {
        # $false only when the item is not found; any other error (access denied, I/O) throws: not confirmed.
        try { $null = Get-Item -LiteralPath $path -Force; $true } catch [System.Management.Automation.ItemNotFoundException] { $false }
    }
    function LegacyEntryLeft($target) {
        # The earlier format's Credential Manager entry. Absent only in cmdkey's "absent" shape: no line but the
        # header names the target, and a "* ... *" marker line is there. Anything else counts as present.
        $out = @(cmdkey "/list:$target")
        if ($LASTEXITCODE -ne 0) { throw 'cmdkey failed' }
        $naming = @($out | Where-Object { $_ -like "*$target*" }).Count
        $marker = @($out | Where-Object { $_ -match '^\s*\*\s*\S.*\*\s*$' }).Count
        -not ($naming -le 1 -and $marker -ge 1)
    }
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    $pairingDir = Join-Path $local 'vettid-desktop'
    $key = 'HKCU:\Software\vettid\VettID Desktop'
    $dir = $null
    if (Exists $key) { $dir = (Get-ItemProperty -LiteralPath $key).'(default)' }
    if (-not $dir) { $dir = Join-Path $local 'VettID Desktop' }
    $dir = $dir.Trim('"').TrimEnd('\')
    # A full path below a drive or a share, not a drive root or a relative path.
    if ($dir -notmatch '^([A-Za-z]:\\|\\\\[^\\]+\\[^\\]+\\).') { exit 2 }
    $exe = Join-Path $dir 'vettid-desktop.exe'
    $u = Join-Path $dir 'uninstall.exe'

    if (Exists $exe) {
        # The program is there: only its uninstaller, in the one form that waits and wipes, can confirm.
        if (-not (Exists $u)) { exit 2 }
        $p = Start-Process -FilePath $u -ArgumentList "/S /WIPEPAIRING _?=$dir" -Wait -PassThru
        if ($null -eq $p -or $p.ExitCode -ne 0) { exit 2 }
        exit 0
    }

    # The program is gone, so nothing here can run the wipe: confirmed only if nothing of the pairing is left.
    if ((Exists $pairingDir) -and @(Get-ChildItem -LiteralPath $pairingDir -Force -Recurse).Count -gt 0) { exit 2 }
    if (LegacyEntryLeft 'vettid-desktop/master-key-v1/local') { exit 2 }
    # The uninstall.exe an earlier in-place run leaves, and its folder if that is then empty. Nothing else.
    if (Exists $u) { Remove-Item -LiteralPath $u }
    if ((Exists $dir) -and @(Get-ChildItem -LiteralPath $dir -Force).Count -eq 0) { Remove-Item -LiteralPath $dir }
    exit 0
} catch {
    exit 2
}
