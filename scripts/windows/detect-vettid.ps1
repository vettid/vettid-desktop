# Detection for VettID Desktop, run as the signed-in user. Detected (a line on standard output, exit 0) while the
# program is installed for this user or anything of a saved pairing is left; not detected (no output, exit 0)
# otherwise. When something can't be checked, or it runs as a service account, it counts as detected, so a
# failed wipe stays visible.
$ErrorActionPreference = 'Stop'
try {
    # A service account (SYSTEM, LocalService, NetworkService) sees its own profile, not the person's.
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -in 'S-1-5-18', 'S-1-5-19', 'S-1-5-20') {
        'VettID Desktop: running as a service account, not as the user; counted as installed'
        exit 0
    }
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
    # Every place it may be installed: the product key, the Apps-list entry's InstallLocation, the default.
    $dirs = @(Join-Path $local 'VettID Desktop')
    $productKey = 'HKCU:\Software\vettid\VettID Desktop'
    $appsKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\VettID Desktop'
    if (Exists $productKey) { $v = (Get-ItemProperty -LiteralPath $productKey).'(default)'; if ($v) { $dirs += $v } }
    if (Exists $appsKey) { $v = (Get-ItemProperty -LiteralPath $appsKey).InstallLocation; if ($v) { $dirs += $v } }
    $program = $false
    foreach ($d in $dirs) {
        $d = "$d".Trim().Trim('"').TrimEnd('\')
        if ($d -and (Exists (Join-Path $d 'vettid-desktop.exe'))) { $program = $true }
    }
    $pairing = (Exists $pairingDir) -and @(Get-ChildItem -LiteralPath $pairingDir -Force -Recurse).Count -gt 0
    $entry = LegacyEntryLeft 'vettid-desktop/master-key-v1/local'
    if ($program -or $pairing -or $entry) { "VettID Desktop: program $program, pairing files $pairing, legacy entry $entry" }
} catch {
    "VettID Desktop: couldn't check ($($_.Exception.Message)); counted as installed"
}
exit 0
