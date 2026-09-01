param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,

    [Parameter(Mandatory = $true)]
    [string]$IcoPath
)

$ErrorActionPreference = 'Stop'

$ExePath = [System.IO.Path]::GetFullPath($ExePath)
$IcoPath = [System.IO.Path]::GetFullPath($IcoPath)

if (-not (Test-Path -LiteralPath $ExePath -PathType Leaf)) {
    throw "Executable not found: $ExePath"
}
if (-not (Test-Path -LiteralPath $IcoPath -PathType Leaf)) {
    throw "Icon not found: $IcoPath"
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class Win32IconResource
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr BeginUpdateResource(string pFileName, bool bDeleteExistingResources);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool UpdateResource(
        IntPtr hUpdate,
        IntPtr lpType,
        IntPtr lpName,
        ushort wLanguage,
        IntPtr lpData,
        uint cbData);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool EndUpdateResource(IntPtr hUpdate, bool fDiscard);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr FindResource(IntPtr hModule, IntPtr lpName, IntPtr lpType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);
}
'@

$RT_ICON = [IntPtr]3
$RT_GROUP_ICON = [IntPtr]14
$APP_GROUP_ID = [IntPtr]1
$LANG_NEUTRAL = [UInt16]0
$LOAD_LIBRARY_AS_DATAFILE = [UInt32]0x00000002
$LOAD_LIBRARY_AS_IMAGE_RESOURCE = [UInt32]0x00000020

function Throw-Win32Error([string]$Operation) {
    $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $message = (New-Object ComponentModel.Win32Exception($code)).Message
    throw "$Operation failed (Win32 $code): $message"
}

function Update-BinaryResource(
    [IntPtr]$Handle,
    [IntPtr]$Type,
    [IntPtr]$Name,
    [byte[]]$Data
) {
    $memory = [IntPtr]::Zero
    try {
        if ($Data.Length -gt 0) {
            $memory = [Runtime.InteropServices.Marshal]::AllocHGlobal($Data.Length)
            [Runtime.InteropServices.Marshal]::Copy($Data, 0, $memory, $Data.Length)
        }
        if (-not [Win32IconResource]::UpdateResource(
            $Handle,
            $Type,
            $Name,
            $LANG_NEUTRAL,
            $memory,
            [UInt32]$Data.Length)) {
            Throw-Win32Error 'UpdateResource'
        }
    }
    finally {
        if ($memory -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($memory)
        }
    }
}

# ICO: ICONDIR (6 bytes) followed by ICONDIRENTRY records (16 bytes each).
# A Windows RT_GROUP_ICON resource contains the same header but uses 14-byte
# entries whose last field is the numeric RT_ICON resource id.
$icoBytes = [System.IO.File]::ReadAllBytes($IcoPath)
if ($icoBytes.Length -lt 6) {
    throw 'Invalid ICO: file is shorter than ICONDIR.'
}

$stream = New-Object System.IO.MemoryStream(,$icoBytes)
$reader = New-Object System.IO.BinaryReader($stream)
try {
    $reserved = $reader.ReadUInt16()
    $kind = $reader.ReadUInt16()
    $count = $reader.ReadUInt16()
    if ($reserved -ne 0 -or $kind -ne 1 -or $count -lt 1) {
        throw 'Invalid ICO: expected ICONDIR reserved=0, type=1 and at least one image.'
    }
    if ($icoBytes.Length -lt (6 + (16 * $count))) {
        throw 'Invalid ICO: truncated image directory.'
    }

    $entries = @()
    for ($i = 0; $i -lt $count; ++$i) {
        $entry = [PSCustomObject]@{
            Width       = $reader.ReadByte()
            Height      = $reader.ReadByte()
            ColorCount  = $reader.ReadByte()
            Reserved    = $reader.ReadByte()
            Planes      = $reader.ReadUInt16()
            BitCount    = $reader.ReadUInt16()
            BytesInRes  = $reader.ReadUInt32()
            ImageOffset = $reader.ReadUInt32()
            ResourceId  = [UInt16]($i + 1)
        }
        $end = [UInt64]$entry.ImageOffset + [UInt64]$entry.BytesInRes
        if ($entry.BytesInRes -eq 0 -or $end -gt [UInt64]$icoBytes.Length) {
            throw "Invalid ICO: image $i points outside the file."
        }
        $entries += $entry
    }
}
finally {
    $reader.Dispose()
    $stream.Dispose()
}

$groupStream = New-Object System.IO.MemoryStream
$groupWriter = New-Object System.IO.BinaryWriter($groupStream)
try {
    $groupWriter.Write([UInt16]0)
    $groupWriter.Write([UInt16]1)
    $groupWriter.Write([UInt16]$entries.Count)
    foreach ($entry in $entries) {
        $groupWriter.Write([Byte]$entry.Width)
        $groupWriter.Write([Byte]$entry.Height)
        $groupWriter.Write([Byte]$entry.ColorCount)
        $groupWriter.Write([Byte]$entry.Reserved)
        $groupWriter.Write([UInt16]$entry.Planes)
        $groupWriter.Write([UInt16]$entry.BitCount)
        $groupWriter.Write([UInt32]$entry.BytesInRes)
        $groupWriter.Write([UInt16]$entry.ResourceId)
    }
    $groupWriter.Flush()
    $groupBytes = $groupStream.ToArray()
}
finally {
    $groupWriter.Dispose()
    $groupStream.Dispose()
}

$update = [Win32IconResource]::BeginUpdateResource($ExePath, $false)
if ($update -eq [IntPtr]::Zero) {
    Throw-Win32Error 'BeginUpdateResource'
}

$commit = $false
try {
    foreach ($entry in $entries) {
        $image = New-Object byte[] ([int]$entry.BytesInRes)
        [Array]::Copy(
            $icoBytes,
            [int]$entry.ImageOffset,
            $image,
            0,
            [int]$entry.BytesInRes)
        Update-BinaryResource $update $RT_ICON ([IntPtr][int]$entry.ResourceId) $image
    }
    Update-BinaryResource $update $RT_GROUP_ICON $APP_GROUP_ID $groupBytes
    $commit = $true
}
finally {
    if (-not [Win32IconResource]::EndUpdateResource($update, -not $commit)) {
        Throw-Win32Error 'EndUpdateResource'
    }
}

# Verify the resource in the resulting PE rather than trusting only the API
# return value. ID 1 is deliberately used so Windows shell icon extraction
# sees our group before the generic IExpress icon group.
$module = [Win32IconResource]::LoadLibraryEx(
    $ExePath,
    [IntPtr]::Zero,
    ($LOAD_LIBRARY_AS_DATAFILE -bor $LOAD_LIBRARY_AS_IMAGE_RESOURCE))
if ($module -eq [IntPtr]::Zero) {
    Throw-Win32Error 'LoadLibraryEx verification'
}
try {
    $group = [Win32IconResource]::FindResource($module, $APP_GROUP_ID, $RT_GROUP_ICON)
    if ($group -eq [IntPtr]::Zero) {
        Throw-Win32Error 'FindResource(RT_GROUP_ICON, 1) verification'
    }
    $groupSize = [Win32IconResource]::SizeofResource($module, $group)
    if ($groupSize -ne [UInt32]$groupBytes.Length) {
        throw "Icon verification failed: expected group size $($groupBytes.Length), got $groupSize."
    }
}
finally {
    [void][Win32IconResource]::FreeLibrary($module)
}

Write-Host ("    final wrapper icon: {0} image(s), group id 1" -f $entries.Count)
