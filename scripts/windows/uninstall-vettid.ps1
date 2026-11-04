# Uninstall VettID Desktop for the signed-in user, and report whether the saved pairing is confirmed gone.
# Run it as that user (user context), not as SYSTEM: see docs/WINDOWS-TESTING.md, "IT-managed installs".
# Exit 0: uninstalled, and the pairing confirmed gone (or nothing was installed or paired).
# Exit 2: not confirmed, or anything unexpected (events 1001-1003 in the Application log say more).
$ErrorActionPreference = 'Stop'
try {
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    $pairingDir = Join-Path $local 'vettid-desktop'
    $legacy = 'vettid-desktop/master-key-v1/local'
    function PairingLeft {
        # Any entry, hidden ones and subfolders included. A folder that can't be read throws: not confirmed.
        (Test-Path -LiteralPath $pairingDir) -and @(Get-ChildItem -LiteralPath $pairingDir -Force -Recurse).Count -gt 0
    }
    function LegacyEntryLeft {
        # The earlier format's Credential Manager entry. cmdkey's header names the target whether or not it
        # is there; a second line naming it is the entry.
        $out = @(cmdkey "/list:$legacy")
        if ($LASTEXITCODE -ne 0) { throw 'cmdkey failed' }
        @($out | Where-Object { $_ -like "*$legacy*" }).Count -gt 1
    }

    $key = 'HKCU:\Software\vettid\VettID Desktop'
    $dir = $null
    if (Test-Path -LiteralPath $key) { $dir = (Get-ItemProperty -LiteralPath $key).'(default)' }
    if (-not $dir) { $dir = Join-Path $local 'VettID Desktop' }
    $dir = $dir.Trim('"').TrimEnd('\')
    if (-not [IO.Path]::IsPathRooted($dir) -or $dir.Length -le 3) { exit 2 }
    $exe = Join-Path $dir 'vettid-desktop.exe'
    $u = Join-Path $dir 'uninstall.exe'

    if (Test-Path -LiteralPath $exe) {
        # The program is there: only its uninstaller, in the one form that waits and wipes, can confirm.
        if (-not (Test-Path -LiteralPath $u)) { exit 2 }
        $p = Start-Process -FilePath $u -ArgumentList "/S /WIPEPAIRING _?=$dir" -Wait -PassThru
        if ($null -eq $p -or $p.ExitCode -ne 0) { exit 2 }
        exit 0
    }

    # The program is gone, so nothing here can run the wipe: confirmed only if nothing of the pairing is left.
    if ((PairingLeft) -or (LegacyEntryLeft)) { exit 2 }
    # The uninstall.exe an earlier in-place run leaves, and its folder if that is then empty. Nothing else.
    if (Test-Path -LiteralPath $u) { Remove-Item -LiteralPath $u }
    if ((Test-Path -LiteralPath $dir) -and @(Get-ChildItem -LiteralPath $dir -Force).Count -eq 0) { Remove-Item -LiteralPath $dir }
    exit 0
} catch {
    exit 2
}
