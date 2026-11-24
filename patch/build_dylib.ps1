# build_dylib.ps1 - cross-compile gate.dylib with Zig on Windows and inject into IPA
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File patch\build_dylib.ps1 -Server http://192.168.1.112 -AtsAllowHttp
#
# Notes:
#   * ASCII-only on purpose: Windows PowerShell 5.1 misreads UTF-8 without BOM.
#   * Zig target is aarch64-macos, then we patch LC_BUILD_VERSION to iOS.

param(
    [Parameter(Mandatory = $true)][string]$Server,
    [string]$Ipa = "in\input.ipa",
    [string]$Out = "..\out\AXProMax-gate-local.ipa",
    [string]$Python = "",
    [switch]$AtsAllowHttp
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$repo = Split-Path -Parent $root

Push-Location $root
try {
    $zig = Join-Path $repo "toolchain\zig-windows-x86_64-0.13.0\zig.exe"
    if (-not (Test-Path $zig)) { throw "zig not found: $zig" }

    if (-not $Python) {
        $Python = Get-Command python -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
        if (-not $Python) { throw "python not found; pass -Python <path>" }
    }

    Write-Host "[1/5] configure axp_config.h (server=$Server)"
    & $Python -X utf8 "patch\configure.py" --server $Server --pubkey-from "server\keys\public_b64.txt"
    if ($LASTEXITCODE -ne 0) { throw "configure.py failed" }

    Write-Host "[2/5] cross compile (zig, aarch64-macos)"
    $work = Join-Path $repo "work"
    New-Item -ItemType Directory -Force $work | Out-Null
    $mac = Join-Path $work "gate_mac.dylib"
    $raw = Join-Path $work "gate_raw.dylib"
    $zigArgs = @(
        "cc", "-target", "aarch64-macos", "-dynamiclib",
        "-fblocks", "-fobjc-exceptions", "-O1",
        "-o", $mac, "tweak\gate_standalone.m", "-Itweak",
        "-Wl,-undefined,dynamic_lookup"
    )
    & $zig @zigArgs
    if ($LASTEXITCODE -ne 0) { throw "zig compile failed" }

    Write-Host "[3/5] patch platform macOS -> iOS"
    & $Python -X utf8 (Join-Path $repo "tools\to_ios.py") $mac $raw | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "to_ios.py failed" }

    Write-Host "[4/5] finalize (install name / clear signature / self check)"
    $dylib = Join-Path $work "gate.dylib"
    & $Python -X utf8 (Join-Path $repo "tools\finalize_dylib.py") $raw $dylib
    if ($LASTEXITCODE -ne 0) { throw "finalize_dylib.py failed" }

    Write-Host "[5/5] inject into IPA"
    $inj = @("patch\inject.py", "--ipa", $Ipa, "--dylib", $dylib, "--out", $Out)
    if ($AtsAllowHttp) { $inj += "--ats-allow-http" }
    & $Python -X utf8 @inj
    if ($LASTEXITCODE -ne 0) { throw "inject.py failed" }

    Write-Host ""
    Write-Host "DONE: $Out"
}
finally {
    Pop-Location
}
