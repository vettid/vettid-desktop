# Detection for VettID Desktop, run as the signed-in user. Detected (a line on standard output, exit 0) while the
# program is installed for this user or anything of a saved pairing is left; not detected (no output, exit 0)
# otherwise. When something can't be checked, it counts as detected, so a failed wipe stays visible.
$ErrorActionPreference = 'Stop'
try {
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    $pairingDir = Join-Path $local 'vettid-desktop'
    $legacy = 'vettid-desktop/master-key-v1/local'
    $key = 'HKCU:\Software\vettid\VettID Desktop'
    $dir = $null
    if (Test-Path -LiteralPath $key) { $dir = (Get-ItemProperty -LiteralPath $key).'(default)' }
    if (-not $dir) { $dir = Join-Path $local 'VettID Desktop' }
    $dir = $dir.Trim('"').TrimEnd('\')
    $program = Test-Path -LiteralPath (Join-Path $dir 'vettid-desktop.exe')
    $pairing = (Test-Path -LiteralPath $pairingDir) -and @(Get-ChildItem -LiteralPath $pairingDir -Force -Recurse).Count -gt 0
    $out = @(cmdkey "/list:$legacy")
    if ($LASTEXITCODE -ne 0) { throw 'cmdkey failed' }
    $entry = @($out | Where-Object { $_ -like "*$legacy*" }).Count -gt 1
    if ($program -or $pairing -or $entry) { "VettID Desktop: program $program, pairing files $pairing, legacy entry $entry" }
} catch {
    "VettID Desktop: couldn't check ($($_.Exception.Message)); counted as installed"
}
exit 0
