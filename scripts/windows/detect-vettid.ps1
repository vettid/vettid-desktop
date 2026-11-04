# Detected (prints a line) while the program is installed for the signed-in user, or a saved pairing is still there.
$key = 'HKCU:\Software\vettid\VettID Desktop'
$dir = (Get-ItemProperty $key -ErrorAction SilentlyContinue).'(default)'
if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'VettID Desktop' }
$dir = $dir.Trim('"').TrimEnd('\')
$program = Test-Path (Join-Path $dir 'vettid-desktop.exe')
$pairing = @(Get-ChildItem (Join-Path $env:LOCALAPPDATA 'vettid-desktop') -File -ErrorAction SilentlyContinue).Count -gt 0
if ($program -or $pairing) { "VettID Desktop: program $program, pairing left $pairing" }
exit 0
