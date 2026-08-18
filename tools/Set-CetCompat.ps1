[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path
)

$ErrorActionPreference = 'Stop'
$fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
$script:bytes = [IO.File]::ReadAllBytes($fullPath)

function Read-U16([int]$Offset) {
    return [BitConverter]::ToUInt16($script:bytes, $Offset)
}

function Read-U32([int]$Offset) {
    return [BitConverter]::ToUInt32($script:bytes, $Offset)
}

function Write-U16([int]$Offset, [uint16]$Value) {
    [Array]::Copy([BitConverter]::GetBytes($Value), 0, $script:bytes, $Offset, 2)
}

function Write-U32([int]$Offset, [uint32]$Value) {
    [Array]::Copy([BitConverter]::GetBytes($Value), 0, $script:bytes, $Offset, 4)
}

function Align-Up([uint64]$Value, [uint64]$Alignment) {
    return [uint64](($Value + $Alignment - 1) -band -bnot ($Alignment - 1))
}

if ($script:bytes.Length -lt 0x100 -or (Read-U16 0) -ne 0x5a4d) {
    throw 'Input is not a PE image.'
}

$peOffset = [int](Read-U32 0x3c)
if ($peOffset -lt 0 -or $peOffset + 24 -gt $script:bytes.Length -or
    (Read-U32 $peOffset) -ne 0x00004550) {
    throw 'Invalid PE header.'
}

$fileHeader = $peOffset + 4
$sectionCount = [int](Read-U16 ($fileHeader + 2))
$optionalSize = [int](Read-U16 ($fileHeader + 16))
$optional = $fileHeader + 20
if ((Read-U16 $fileHeader) -ne 0x8664 -or
    $optionalSize -lt 168 -or $optional + $optionalSize -gt $script:bytes.Length -or
    (Read-U16 $optional) -ne 0x20b) {
    throw 'CETCOMPAT is supported here only for x64 PE32+ images.'
}
if ((Read-U32 ($optional + 108)) -lt 7) {
    throw 'PE image does not declare the debug data directory.'
}

$sectionAlignment = [uint32](Read-U32 ($optional + 32))
$fileAlignment = [uint32](Read-U32 ($optional + 36))
$sizeOfHeaders = [uint32](Read-U32 ($optional + 60))
if ($sectionAlignment -eq 0 -or $fileAlignment -eq 0 -or
    ($sectionAlignment -band ($sectionAlignment - 1)) -ne 0 -or
    ($fileAlignment -band ($fileAlignment - 1)) -ne 0) {
    throw 'Invalid PE alignment.'
}
$directoryBase = $optional + 112
$securityDirectory = $directoryBase + 4 * 8
$debugDirectory = $directoryBase + 6 * 8
if ((Read-U32 $securityDirectory) -ne 0 -or (Read-U32 ($securityDirectory + 4)) -ne 0) {
    throw 'Refusing to modify a signed image.'
}

$sectionTable = $optional + $optionalSize
if ($sectionTable + $sectionCount * 40 -gt $sizeOfHeaders) {
    throw 'Section table extends beyond PE headers.'
}
$sections = @()
for ($i = 0; $i -lt $sectionCount; $i++) {
    $header = $sectionTable + $i * 40
    if ($header + 40 -gt $script:bytes.Length) { throw 'Invalid section table.' }
    $sections += [pscustomobject]@{
        VirtualSize = [uint32](Read-U32 ($header + 8))
        VirtualAddress = [uint32](Read-U32 ($header + 12))
        RawSize = [uint32](Read-U32 ($header + 16))
        RawAddress = [uint32](Read-U32 ($header + 20))
    }
}

function Convert-RvaToOffset([uint32]$Rva) {
    foreach ($section in $sections) {
        $span = [Math]::Max([uint64]$section.VirtualSize, [uint64]$section.RawSize)
        if ($Rva -ge $section.VirtualAddress -and
            [uint64]$Rva -lt [uint64]$section.VirtualAddress + $span) {
            return [int]([uint64]$section.RawAddress + $Rva - $section.VirtualAddress)
        }
    }
    throw ('RVA 0x{0:X} is not backed by a section.' -f $Rva)
}

$debugRva = [uint32](Read-U32 $debugDirectory)
$debugSize = [uint32](Read-U32 ($debugDirectory + 4))
$debugOffset = 0
if ($debugRva -ne 0 -or $debugSize -ne 0) {
    if ($debugRva -eq 0 -or $debugSize -eq 0 -or ($debugSize % 28) -ne 0) {
        throw 'Invalid PE debug directory.'
    }
    $debugOffset = Convert-RvaToOffset $debugRva
    if ([uint64]$debugOffset + $debugSize -gt $script:bytes.Length) {
        throw 'Debug directory extends beyond the image.'
    }

    for ($entry = 0; $entry -lt $debugSize; $entry += 28) {
        $entryOffset = $debugOffset + $entry
        if ((Read-U32 ($entryOffset + 12)) -ne 20) { continue }
        $dataSize = Read-U32 ($entryOffset + 16)
        $dataOffset = Read-U32 ($entryOffset + 24)
        if ($dataSize -lt 4 -or [uint64]$dataOffset + 4 -gt $script:bytes.Length) {
            throw 'Invalid extended DLL characteristics entry.'
        }
        Write-U32 $dataOffset ((Read-U32 $dataOffset) -bor 1)
        Write-U32 ($optional + 64) 0
        [IO.File]::WriteAllBytes($fullPath, $script:bytes)
        Write-Output "CETCOMPAT already present; marker updated: $fullPath"
        return
    }
}

$newHeader = $sectionTable + $sectionCount * 40
if ($newHeader + 40 -gt $sizeOfHeaders) {
    throw 'PE headers have no room for an additional section.'
}
for ($i = 0; $i -lt 40; $i++) {
    if ($script:bytes[$newHeader + $i] -ne 0) {
        throw 'The next PE section header is not empty.'
    }
}

$maxVirtualEnd = [uint64](Read-U32 ($optional + 56))
foreach ($section in $sections) {
    $end = [uint64]$section.VirtualAddress +
           [Math]::Max([uint64]$section.VirtualSize, [uint64]$section.RawSize)
    if ($end -gt $maxVirtualEnd) { $maxVirtualEnd = $end }
}

$newRva = [uint32](Align-Up $maxVirtualEnd $sectionAlignment)
$newRaw = [uint32](Align-Up ([uint64]$script:bytes.Length) $fileAlignment)
$payloadSize = [uint32]($debugSize + 28 + 4)
$newRawSize = [uint32](Align-Up $payloadSize $fileAlignment)
$expanded = New-Object byte[] ([int]([uint64]$newRaw + $newRawSize))
[Array]::Copy($script:bytes, 0, $expanded, 0, $script:bytes.Length)
$script:bytes = $expanded

if ($debugSize -ne 0) {
    [Array]::Copy($script:bytes, $debugOffset, $script:bytes, $newRaw, $debugSize)
}

$entryOffset = [int]($newRaw + $debugSize)
$entryRva = [uint32]($newRva + $debugSize)
$markerOffset = [uint32]($entryOffset + 28)
$markerRva = [uint32]($entryRva + 28)
Write-U32 ($entryOffset + 4) (Read-U32 ($fileHeader + 4))
Write-U32 ($entryOffset + 12) 20
Write-U32 ($entryOffset + 16) 4
Write-U32 ($entryOffset + 20) $markerRva
Write-U32 ($entryOffset + 24) $markerOffset
Write-U32 $markerOffset 1

$name = [Text.Encoding]::ASCII.GetBytes('.cet')
[Array]::Copy($name, 0, $script:bytes, $newHeader, $name.Length)
Write-U32 ($newHeader + 8) $payloadSize
Write-U32 ($newHeader + 12) $newRva
Write-U32 ($newHeader + 16) $newRawSize
Write-U32 ($newHeader + 20) $newRaw
Write-U32 ($newHeader + 36) 0x42000040

Write-U16 ($fileHeader + 2) ([uint16]($sectionCount + 1))
Write-U32 ($optional + 8) ([uint32]((Read-U32 ($optional + 8)) + $newRawSize))
Write-U32 ($optional + 56) ([uint32](Align-Up ([uint64]$newRva + $payloadSize) $sectionAlignment))
Write-U32 ($optional + 64) 0
Write-U32 $debugDirectory $newRva
Write-U32 ($debugDirectory + 4) ([uint32]($debugSize + 28))

[IO.File]::WriteAllBytes($fullPath, $script:bytes)
Write-Output "CETCOMPAT marker added: $fullPath"
