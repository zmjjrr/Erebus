param(
    [Parameter(Mandatory=$true)][string]$PayloadPath,
    [Parameter(Mandatory=$true)][string]$HeaderPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Read-U16 {
    param([byte[]]$Bytes, [int]$Offset)
    return [BitConverter]::ToUInt16($Bytes, $Offset)
}

function Read-U32 {
    param([byte[]]$Bytes, [int]$Offset)
    return [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Read-AsciiZ {
    param([byte[]]$Bytes, [int]$Offset)
    $end = $Offset
    while ($end -lt $Bytes.Length -and $Bytes[$end] -ne 0) {
        $end++
    }
    return [Text.Encoding]::ASCII.GetString($Bytes, $Offset, $end - $Offset)
}

function Convert-RvaToOffset {
    param(
        [uint32]$Rva,
        [object[]]$Sections
    )
    foreach ($section in $Sections) {
        $span = [Math]::Max([uint32]$section.VirtualSize, [uint32]$section.RawSize)
        if ($Rva -ge $section.VirtualAddress -and $Rva -lt ($section.VirtualAddress + $span)) {
            return [int]($section.RawPointer + ($Rva - $section.VirtualAddress))
        }
    }
    if ($Rva -lt 0x1000) {
        return [int]$Rva
    }
    throw "RVA 0x$($Rva.ToString('X')) is outside all sections"
}

$bytes = [IO.File]::ReadAllBytes($PayloadPath)
if ($bytes.Length -lt 0x1000) {
    throw "payload too small: $($bytes.Length)"
}

$eLfanew = Read-U32 $bytes 0x3c
if ((Read-U16 $bytes 0) -ne 0x5a4d -or (Read-U32 $bytes $eLfanew) -ne 0x4550) {
    throw 'payload is not a PE image'
}

$coff = $eLfanew + 4
$sectionCount = Read-U16 $bytes ($coff + 2)
$optionalHeaderSize = Read-U16 $bytes ($coff + 16)
$optional = $coff + 20
$exportRva = Read-U32 $bytes ($optional + 112)
$exportSize = Read-U32 $bytes ($optional + 116)
$sectionsOffset = $optional + $optionalHeaderSize

$sections = @()
for ($i = 0; $i -lt $sectionCount; $i++) {
    $off = $sectionsOffset + ($i * 40)
    $nameBytes = $bytes[$off..($off + 7)]
    $nameLen = 0
    while ($nameLen -lt 8 -and $nameBytes[$nameLen] -ne 0) {
        $nameLen++
    }
    $name = [Text.Encoding]::ASCII.GetString($nameBytes, 0, $nameLen)
    $sections += [pscustomobject]@{
        Name = $name
        VirtualSize = Read-U32 $bytes ($off + 8)
        VirtualAddress = Read-U32 $bytes ($off + 12)
        RawSize = Read-U32 $bytes ($off + 16)
        RawPointer = Read-U32 $bytes ($off + 20)
    }
}

$exports = [ordered]@{}
if ($exportRva -ne 0 -and $exportSize -ne 0) {
    $exportOff = Convert-RvaToOffset $exportRva $sections
    $numberOfFunctions = Read-U32 $bytes ($exportOff + 20)
    $numberOfNames = Read-U32 $bytes ($exportOff + 24)
    $addressOfFunctions = Read-U32 $bytes ($exportOff + 28)
    $addressOfNames = Read-U32 $bytes ($exportOff + 32)
    $addressOfNameOrdinals = Read-U32 $bytes ($exportOff + 36)
    $functionsOff = Convert-RvaToOffset $addressOfFunctions $sections
    $namesOff = Convert-RvaToOffset $addressOfNames $sections
    $ordinalsOff = Convert-RvaToOffset $addressOfNameOrdinals $sections

    for ($i = 0; $i -lt $numberOfNames; $i++) {
        $nameRva = Read-U32 $bytes ($namesOff + ($i * 4))
        $nameOff = Convert-RvaToOffset $nameRva $sections
        $name = Read-AsciiZ $bytes $nameOff
        $ordinalIndex = Read-U16 $bytes ($ordinalsOff + ($i * 2))
        if ($ordinalIndex -ge $numberOfFunctions) {
            throw "invalid export ordinal index for $name"
        }
        $functionRva = Read-U32 $bytes ($functionsOff + ($ordinalIndex * 4))
        $exports[$name] = ('0x{0:X}' -f $functionRva)
    }
}

foreach ($required in @(
    'ErebusVmExitHandler',
    'ErebusOriginalHandler',
    'ErebusPostVmExitHandler',
    'ErebusVmExitCallDispatcher',
    'ErebusAfterCallDelta'
)) {
    if (-not $exports.Contains($required)) {
        throw "required payload export missing: $required"
    }
}

$builder = [Text.StringBuilder]::new()
[void]$builder.AppendLine('#pragma once')
[void]$builder.AppendLine(('// Generated from {0}' -f (Split-Path -Leaf $PayloadPath)))
[void]$builder.AppendLine(('#define PAYLOAD_SIZE 0x{0:X}' -f $bytes.Length))
[void]$builder.AppendLine('unsigned char payloadData[PAYLOAD_SIZE] = {')
for ($i = 0; $i -lt $bytes.Length; $i++) {
    if (($i % 16) -eq 0) {
        [void]$builder.Append('    ')
    }
    [void]$builder.Append(('0x{0:X2}' -f $bytes[$i]))
    if ($i -ne ($bytes.Length - 1)) {
        [void]$builder.Append(', ')
    }
    if (($i % 16) -eq 15 -or $i -eq ($bytes.Length - 1)) {
        [void]$builder.AppendLine()
    }
}
[void]$builder.AppendLine('};')
[IO.File]::WriteAllText($HeaderPath, $builder.ToString(), [Text.Encoding]::ASCII)
