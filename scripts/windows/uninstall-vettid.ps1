# Uninstall VettID Desktop for the signed-in user and report whether the saved pairing is confirmed gone.
# Exit 0: uninstalled, pairing confirmed gone (or nothing was there). Exit 2: not confirmed; see event 1001-1003.
$key = 'HKCU:\Software\vettid\VettID Desktop'
$dir = (Get-ItemProperty $key -ErrorAction SilentlyContinue).'(default)'
if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'VettID Desktop' }
$dir = $dir.Trim('"').TrimEnd('\')
$u = Join-Path $dir 'uninstall.exe'
if (-not (Test-Path (Join-Path $dir 'vettid-desktop.exe')) -or -not (Test-Path $u)) {
    # The program is gone, so nothing here can run the wipe: confirmed only if no pairing file is left.
    if (@(Get-ChildItem (Join-Path $env:LOCALAPPDATA 'vettid-desktop') -File -ErrorAction SilentlyContinue).Count) { exit 2 }
    Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue   # an uninstall.exe left by an earlier run
    exit 0
}
$p = Start-Process -FilePath $u -ArgumentList @('/S', '/WIPEPAIRING', "_?=$dir") -Wait -PassThru
exit $p.ExitCode
