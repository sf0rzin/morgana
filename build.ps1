[CmdletBinding()]
param(
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'src'

& g++ -O2 "-I$src" -o (Join-Path $PSScriptRoot 'server.exe') `
    (Join-Path $src 'server.cpp') `
    (Join-Path $src 'crypto.cpp') `
    (Join-Path $src 'kx.cpp') `
    -lws2_32 -lbcrypt -lcrypt32 -lsecur32
if ($LASTEXITCODE -ne 0) { throw "server build failed with exit code $LASTEXITCODE" }

& g++ -O2 '-Wl,--disable-dynamicbase' "-I$src" `
    -o (Join-Path $PSScriptRoot 'client.exe') `
    (Join-Path $src 'client.cpp') `
    (Join-Path $src 'syscalls.cpp') `
    (Join-Path $src 'spoof.cpp') `
    (Join-Path $src 'crypto.cpp') `
    (Join-Path $src 'evasion.cpp') `
    (Join-Path $src 'kx.cpp') `
    -lws2_32 -lbcrypt -lcrypt32 -lsecur32
if ($LASTEXITCODE -ne 0) { throw "client build failed with exit code $LASTEXITCODE" }

& (Join-Path $PSScriptRoot 'tools\Set-CetCompat.ps1') (Join-Path $PSScriptRoot 'client.exe')

if ($Test) {
    $testExe = Join-Path $PSScriptRoot 'tests\spoof-test.exe'
    & g++ -O2 "-I$src" -o $testExe `
        (Join-Path $PSScriptRoot 'tests\spoof_test.cpp') `
        (Join-Path $src 'spoof.cpp') -pthread
    if ($LASTEXITCODE -ne 0) { throw "test build failed with exit code $LASTEXITCODE" }

    & (Join-Path $PSScriptRoot 'tools\Set-CetCompat.ps1') $testExe
    & $testExe
    if ($LASTEXITCODE -ne 0) { throw "tests failed with exit code $LASTEXITCODE" }
}
