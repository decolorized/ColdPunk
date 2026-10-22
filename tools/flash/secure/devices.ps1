# keys\devices.txt for the Windows scripts of a build-secure folder
# (flash.bat, secure-first-flash.bat). Tab-separated lines:
#   date  name  secure-boot-key-digest  bootloader-sha256  version
#
#   devices.ps1 lookup FILE DIGEST                 -> the last bootloader sha for DIGEST ("" if none)
#   devices.ps1 set    FILE DIGEST BLSHA           -> record BLSHA for every device with DIGEST
#   devices.ps1 add    FILE NAME DIGEST BLSHA VER  -> append a device
param([string]$Cmd, [string]$File, [string]$A, [string]$B, [string]$C, [string]$D)
$ErrorActionPreference = 'Stop'
switch ($Cmd) {
  'lookup' {
    if (-not (Test-Path -LiteralPath $File)) { ''; break }
    $bl = ''
    foreach ($l in Get-Content -LiteralPath $File) {
      if ($l.StartsWith('#')) { continue }
      $f = $l -split "`t"
      if ($f.Count -ge 4 -and $f[2] -eq $A) { $bl = $f[3] }
    }
    $bl
  }
  'set' {
    if (-not (Test-Path -LiteralPath $File)) { break }
    $out = foreach ($l in Get-Content -LiteralPath $File) {
      $f = $l -split "`t"
      if (-not $l.StartsWith('#') -and $f.Count -ge 4 -and $f[2] -eq $A) { $f[3] = $B; $f -join "`t" } else { $l }
    }
    Set-Content -LiteralPath $File -Value $out -Encoding ascii
  }
  'add' {
    if (-not (Test-Path -LiteralPath $File)) {
      Set-Content -LiteralPath $File -Value ("# date`tname`tsecure boot key digest`tbootloader sha256`tversion") -Encoding ascii
    }
    $name = ($A -replace "`t", ' ')
    if ($name -eq '') { $name = 'device' }
    Add-Content -LiteralPath $File -Value ((Get-Date -Format 'yyyy-MM-dd') + "`t" + $name + "`t" + $B + "`t" + $C + "`t" + $D) -Encoding ascii
  }
}
