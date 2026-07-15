$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$compiler = Get-Command "g++.exe" -ErrorAction SilentlyContinue
if (-not $compiler) {
    throw "Khong tim thay g++.exe trong PATH."
}

$srcDir = Join-Path $root "src"
$cryptoDir = Join-Path $root "deps\\cryptopp"
$jsonDir = Join-Path $root "deps\\json"

if (-not (Test-Path $srcDir)) {
    throw "Khong tim thay thu muc source: $srcDir"
}

if (-not (Test-Path $cryptoDir)) {
    throw "Khong tim thay thu muc dependency: $cryptoDir"
}

if (-not (Test-Path $jsonDir)) {
    throw "Khong tim thay thu muc dependency: $jsonDir"
}

$cryptoFiles = Get-ChildItem $cryptoDir -Filter *.cpp |
    Where-Object {
        $_.Name -notmatch '^(bench1|bench2|bench3|datatest|dlltest|regtest1|regtest2|regtest3|regtest4|test|validat\d+)\.cpp$'
    } |
    Sort-Object Name |
    Select-Object -ExpandProperty FullName

if (-not $cryptoFiles) {
    throw "Khong tim thay source file can build trong $cryptoDir"
}

$appFiles = Get-ChildItem $srcDir -Filter *.cpp |
    Sort-Object Name |
    Select-Object -ExpandProperty FullName

if (-not $appFiles) {
    throw "Khong tim thay source file can build trong $srcDir"
}

& $compiler.Source `
    "-std=c++17" `
    "-DCRYPTOPP_DISABLE_ASM" `
    "-I" $root `
    "-I" $srcDir `
    "-I" $cryptoDir `
    $appFiles `
    $cryptoFiles `
    "-o" (Join-Path $root "project2.exe") `
    "-lws2_32" `
    "-lgdi32" `
    "-lcrypt32"

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Build thanh cong: $(Join-Path $root 'project2.exe')"
