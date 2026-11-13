param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$OutDir = (Join-Path $PSScriptRoot 'out')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$srcRoot = Join-Path $PSScriptRoot 'src'
$payloadProject = Join-Path $srcRoot 'payload\payload.vcxproj'
$kernelProject = Join-Path $srcRoot 'kernel\kernel.vcxproj'
$clientProject = Join-Path $PSScriptRoot 'tools\erebus_client\erebus_client.vcxproj'

$outDirFull = [IO.Path]::GetFullPath($OutDir)
if (-not $outDirFull.EndsWith('\')) {
    $outDirFull += '\'
}

$clientProps = @(
    "/p:Configuration=$Configuration",
    '/p:Platform=x64',
    "/p:OutDir=$outDirFull",
    '/p:TargetName=ErebusClient',
    '/m',
    '/v:m'
)
$generator = Join-Path $PSScriptRoot 'generate_payload_header.ps1'
$clientSource = Join-Path $PSScriptRoot 'tools\erebus_client\ErebusClient.cpp'
$payloadHeader = Join-Path $srcRoot 'kernel\payloadbytes.h'

# Prefer the Visual Studio 2022 install roots first: that is the toolset the
# driver projects are validated against. Fall back to vswhere so custom install
# locations still work.
$msbuild = $null
$msbuildCandidates = @(
    'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe',
    'C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe',
    'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe',
    'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe'
)
$msbuild = $msbuildCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $msbuild) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $msbuild = & $vswhere -version '[17.0,18.0)' -latest -products * `
            -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' |
            Select-Object -First 1
    }
}
if (-not $msbuild) {
    throw 'MSBuild.exe was not found (install Visual Studio 2022 with the WDK/C++ workloads)'
}

foreach ($path in @($payloadProject, $kernelProject, $clientProject, $generator, $clientSource)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "missing build input: $path"
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$commonProps = @(
    "/p:Configuration=$Configuration",
    '/p:Platform=x64',
    '/p:SignMode=Off',
    '/m',
    '/v:m'
)

& $msbuild $payloadProject @commonProps
if ($LASTEXITCODE -ne 0) {
    throw "payload msbuild failed: $LASTEXITCODE"
}

$payload = Get-ChildItem -LiteralPath (Join-Path $srcRoot 'payload') -Recurse -Filter 'payload.sys' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $payload) {
    throw 'no payload.sys artifact produced'
}

& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
    -File $generator `
    -PayloadPath $payload.FullName `
    -HeaderPath $payloadHeader
if ($LASTEXITCODE -ne 0) {
    throw "payload header generation failed: $LASTEXITCODE"
}

$kernelProps = @($commonProps)
& $msbuild $kernelProject @kernelProps
if ($LASTEXITCODE -ne 0) {
    throw "kernel msbuild failed: $LASTEXITCODE"
}

$sys = Get-ChildItem -LiteralPath (Join-Path $srcRoot 'kernel') -Recurse -Filter '*.sys' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $sys) {
    throw 'no kernel .sys artifact produced'
}

$driverOut = Join-Path $OutDir 'Erebus.sys'
$pdbOut = Join-Path $OutDir 'Erebus.pdb'

Copy-Item -Force -LiteralPath $sys.FullName -Destination $driverOut

$pdb = Get-ChildItem -LiteralPath (Join-Path $srcRoot 'kernel') -Recurse -Filter 'kernel.pdb' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if ($pdb) {
    Copy-Item -Force -LiteralPath $pdb.FullName -Destination $pdbOut
}

$clientOut = Join-Path $outDirFull 'ErebusClient.exe'

& $msbuild $clientProject @clientProps
if ($LASTEXITCODE -ne 0) {
    throw "client msbuild failed: $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $clientOut)) {
    throw "client artifact missing: $clientOut"
}

[pscustomobject]@{
    ok = $true
    action = 'erebus-build'
    configuration = $Configuration
    platform = 'x64'
    driver = (Get-FileHash -Algorithm SHA256 -LiteralPath $driverOut | Select-Object Path, Hash)
    payload = (Get-FileHash -Algorithm SHA256 -LiteralPath $payload.FullName | Select-Object Path, Hash)
    client = (Get-FileHash -Algorithm SHA256 -LiteralPath $clientOut | Select-Object Path, Hash)
} | ConvertTo-Json -Compress -Depth 6
