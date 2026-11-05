# Uninstall VettID Desktop for the signed-in user, and report whether the saved pairing is confirmed gone.
# Run it as that user (user context), not as SYSTEM: see docs/WINDOWS-TESTING.md, "IT-managed installs".
# Exit 0: uninstalled, and the pairing confirmed gone (or nothing was installed or paired).
# Exit 2: not confirmed, or anything unexpected (events 1001-1003 in the Application log may say more).
$ErrorActionPreference = 'Stop'
try {
    # A service account (SYSTEM, LocalService, NetworkService) sees its own profile, not the person's: refuse.
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -in 'S-1-5-18', 'S-1-5-19', 'S-1-5-20') { exit 2 }

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
    function FullFolder($value) {
        # A full path below a drive or a share, normalised; anything else throws (exit 2).
        $guard = '^([A-Za-z]:\\|\\\\[^\\]+\\[^\\]+\\).'
        $v = "$value".Trim().Trim('"').TrimEnd('\')
        if ($v -notmatch $guard) { throw "not a full path: $v" }
        $v = [IO.Path]::GetFullPath($v).TrimEnd('\')
        if ($v -notmatch $guard) { throw "not a full path: $v" }
        $v
    }
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    $pairingDir = Join-Path $local 'vettid-desktop'
    $legacy = 'vettid-desktop/master-key-v1/local'
    function PairingLeft {
        ((Exists $pairingDir) -and @(Get-ChildItem -LiteralPath $pairingDir -Force -Recurse).Count -gt 0) -or (LegacyEntryLeft $legacy)
    }

    # Where it is installed: the product key (which the installer reuses) and the Apps-list entry's
    # InstallLocation, as the uninstaller's own account check reads them. If both are there they must agree.
    $productKey = 'HKCU:\Software\vettid\VettID Desktop'
    $appsKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\VettID Desktop'
    $found = @()
    if (Exists $productKey) { $v = (Get-ItemProperty -LiteralPath $productKey).'(default)'; if ($v) { $found += FullFolder $v } }
    if (Exists $appsKey) { $v = (Get-ItemProperty -LiteralPath $appsKey).InstallLocation; if ($v) { $found += FullFolder $v } }
    $distinct = @($found | Sort-Object -Unique)   # case-insensitive, as Windows paths are
    if ($distinct.Count -gt 1) { exit 2 }
    $dir = if ($distinct.Count -eq 1) { $distinct[0] } else { FullFolder (Join-Path $local 'VettID Desktop') }
    $exe = Join-Path $dir 'vettid-desktop.exe'
    $u = Join-Path $dir 'uninstall.exe'

    if (Exists $exe) {
        # The program is there: only its uninstaller, in the one form that waits and wipes, can remove the pairing.
        if (-not (Exists $u)) { exit 2 }
        $p = Start-Process -FilePath $u -ArgumentList "/S /WIPEPAIRING _?=$dir" -Wait -PassThru
        if ($null -eq $p -or $p.ExitCode -ne 0) { exit 2 }
        # Its 0 isn't taken on trust (an older build, or a regression, could exit 0 without wiping): check.
        if ((Exists $exe) -or (PairingLeft)) { exit 2 }
        exit 0
    }

    # The program is gone, so nothing here can run the wipe: confirmed only if nothing of the pairing is left.
    if (PairingLeft) { exit 2 }
    # The uninstall.exe an earlier in-place run leaves (only if it is VettID Desktop's), and its folder if that
    # is then empty. Nothing else: the folder can be shared with other files (/D=).
    if (Exists $u) {
        if ((Get-Item -LiteralPath $u -Force).VersionInfo.ProductName -ne 'VettID Desktop') { exit 2 }
        Remove-Item -LiteralPath $u -Force -Confirm:$false
    }
    if ((Exists $dir) -and @(Get-ChildItem -LiteralPath $dir -Force).Count -eq 0) { Remove-Item -LiteralPath $dir -Confirm:$false }
    exit 0
} catch {
    exit 2
}
