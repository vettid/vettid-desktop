# Check that a built vettid-desktop.exe needs no Visual C++ runtime DLL (#112). A fresh Windows doesn't have
# them: a program that imports one doesn't start there, and the uninstaller's wipe can't run.
# Usage: check-no-vcruntime.ps1 <path to vettid-desktop.exe>. Exit 0: none imported. Exit 1: one or more is,
# or the file can't be read. Used by CI (windows.yml) and after a release build (docs/WINDOWS-TESTING.md).
param([Parameter(Mandatory = $true)][string]$Exe)
$ErrorActionPreference = 'Stop'
try {
    $path = (Resolve-Path -LiteralPath $Exe).Path
    # DLL names in the import and delay-load tables are ASCII. The Visual C++ runtime's DLLs: vcruntime, the C++
    # library (msvcp), the old C runtime (msvcr; the system's msvcrt.dll has no number and isn't matched),
    # concurrency (concrt), OpenMP (vcomp) and C++/CX (vccorlib).
    $text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($path))
    $found = @([regex]::Matches($text, '(?i)\b(vcruntime|msvcp|msvcr|concrt|vcomp|vccorlib)\d+[_\w]*\.dll') |
        ForEach-Object Value | Sort-Object -Unique)
} catch {
    Write-Output "::error::couldn't check ${Exe}: $($_.Exception.Message)"
    exit 1
}
if ($found.Count -gt 0) {
    Write-Output "::error::$path imports $($found -join ', '): it would not start on a PC without the Visual C++ runtime (#112)"
    exit 1
}
Write-Output "$path imports no Visual C++ runtime DLL"
exit 0
