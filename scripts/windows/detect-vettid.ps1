# Detection for VettID Desktop, run as the signed-in user. Detected (a line on standard output, exit 0) while the
# program is installed for this user or anything of a saved pairing is left; not detected (no output, exit 0)
# otherwise. When something can't be checked, it counts as detected, so a failed wipe stays visible.
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
    $program = Exists (Join-Path $dir 'vettid-desktop.exe')
    $pairing = (Exists $pairingDir) -and @(Get-ChildItem -LiteralPath $pairingDir -Force -Recurse).Count -gt 0
    $entry = LegacyEntryLeft 'vettid-desktop/master-key-v1/local'
    if ($program -or $pairing -or $entry) { "VettID Desktop: program $program, pairing files $pairing, legacy entry $entry" }
} catch {
    "VettID Desktop: couldn't check ($($_.Exception.Message)); counted as installed"
}
exit 0
