<#
.SYNOPSIS
    Reconstruct ACE-ADVT.sys from its disassembly and prove byte identity.

.DESCRIPTION
    Stages
      1 assets      DOS stub / authenticode blob  -> out\assets\*.bin
      2 headers     field-level PE header rebuild  -> out\assets\headers.bin
      3 analyze     unwind tables + recursive descent -> out\model.json
      4 assemble    ml64 (default) or nasm (-Nasm)  -> build\ace_advt.obj
      5 pack+settle slice sections, rebuild image, compare, demote, repeat
      6 verify      sha256 / md5 / checksum / authenticode

.PARAMETER Fresh
    Rebuild the analysis model and start with an empty encoding-override table.

.PARAMETER Nasm
    Use the NASM fallback toolchain (tools\build.py) instead of ml64.

.PARAMETER Target
    Path of the rebuilt driver to verify (default out\rebuild\ACE-ADVT.rebuilt.sys)

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Fresh
    .\build.ps1 -Nasm
#>
[CmdletBinding()]
param(
    [switch]$Fresh,
    [switch]$Nasm,
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$python = 'python'
$ml64Exe = if ($env:ML64) { $env:ML64 } else { 'E:\VisualStudio2026\VC\Tools\MSVC\14.52.36815\bin\Hostx64\x64\ml64.exe' }
$nasmExe = if ($env:NASM) { $env:NASM } else { 'E:\nasm\nasm.exe' }
$target  = if ($env:ADVT_TARGET) { $env:ADVT_TARGET } else { '<TARGET_SYS>' }
$env:ADVT_TARGET = $target
$env:ML64 = $ml64Exe

function Step($n, $text) { Write-Host ("[{0}/{1}] {2}" -f $n, 6, $text) -ForegroundColor Cyan }
function Fail($msg) { Write-Host "FAILED: $msg" -ForegroundColor Red; exit 1 }

Write-Host "ACE-ADVT.sys reconstruction" -ForegroundColor Yellow
Write-Host ("  root     {0}" -f $root)
$toolchain = if ($Nasm) { 'nasm ' + ((& $nasmExe -v) 2>&1 | Select-Object -First 1) } else { 'ml64  ' + (Get-Item $ml64Exe).VersionInfo.FileVersion }
Write-Host ("  toolchain {0}" -f $toolchain)

New-Item -ItemType Directory -Force -Path out, build, out\assets, out\rebuild, logs | Out-Null

if ($Fresh) {
    Remove-Item out\model.json, out\emit_overrides.json -ErrorAction SilentlyContinue
    Write-Host "  fresh: model and override table cleared" -ForegroundColor DarkGray
}

Step 1 'assets (dos stub + authenticode, transcribed as db)'
& $python tools\gen_assets.py
if ($LASTEXITCODE -ne 0) { Fail 'gen_assets.py' }

Step 2 'PE headers (field-level rebuild, verified against the reference)'
& $python tools\mkheaders.py
if ($LASTEXITCODE -ne 0) { Fail 'mkheaders.py' }

if (-not (Test-Path out\model.json)) {
    Step 3 'analysis (unwind tables, recursive descent, section partition)'
    & $python tools\analyze.py
    if ($LASTEXITCODE -ne 0) { Fail 'analyze.py' }
} else {
    Write-Host "[3/6] analysis reused out\model.json (-Fresh to redo)" -ForegroundColor DarkGray
}

if ($Nasm) {
    Step 4 'assemble + pack + settle (nasm flat image)'
    & $python tools\build.py
} else {
    Step 4 'assemble + pack + settle (ml64 -> COFF -> flat image)'
    & $python tools\build_masm.py
}
if ($LASTEXITCODE -ne 0) { Fail 'build' }

if (-not $SkipVerify) {
    Step 5 'verification'
    & $python tools\verify.py
    if ($LASTEXITCODE -ne 0) { Fail 'verify.py' }
} else {
    Write-Host '[5/6] verification skipped' -ForegroundColor DarkGray
}

Step 6 'done'
$rebuilt = 'out\rebuild\ACE-ADVT.rebuilt.sys'
$h1 = (Get-FileHash $rebuilt -Algorithm SHA256).Hash
$h2 = (Get-FileHash $target -Algorithm SHA256).Hash
Write-Host ''
Write-Host ("  rebuilt  {0}  {1}" -f $h1, $rebuilt)
Write-Host ("  original {0}  {1}" -f $h2, $target)
Write-Host ("  identical: {0}" -f ($h1 -eq $h2)) -ForegroundColor $(if ($h1 -eq $h2) { 'Green' } else { 'Red' })
& $python -c "import json;d=json.load(open('out/verification.json'));print('  signature:',d['authenticode']['status']);print('  coverage : %.2f%% mnemonic lines' % d['coverage']['mnemonic_ratio'])"


