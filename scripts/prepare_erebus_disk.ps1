param(
    [ValidateSet('Prepare', 'Cleanup')]
    [string]$Action = 'Prepare',
    [string]$Path = (Join-Path $env:TEMP 'ErebusDiskBounce.vhd'),
    [ValidateRange(1, 1024)]
    [int]$SizeMB = 3
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not ('Erebus.VirtualDisk' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Erebus {
    public static class VirtualDisk {
        [StructLayout(LayoutKind.Sequential)]
        private struct VIRTUAL_STORAGE_TYPE {
            public uint DeviceId;
            public Guid VendorId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CREATE_VIRTUAL_DISK_PARAMETERS_V1 {
            public Guid UniqueId;
            public ulong MaximumSize;
            public uint BlockSizeInBytes;
            public uint SectorSizeInBytes;
            public IntPtr ParentPath;
            public IntPtr SourcePath;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct CREATE_VIRTUAL_DISK_PARAMETERS {
            [FieldOffset(0)]
            public uint Version;
            [FieldOffset(8)]
            public CREATE_VIRTUAL_DISK_PARAMETERS_V1 Version1;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ATTACH_VIRTUAL_DISK_PARAMETERS {
            public uint Version;
            public uint Reserved;
        }

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
        private static extern int CreateVirtualDisk(
            ref VIRTUAL_STORAGE_TYPE virtualStorageType,
            string path,
            uint virtualDiskAccessMask,
            IntPtr securityDescriptor,
            uint flags,
            uint providerSpecificFlags,
            ref CREATE_VIRTUAL_DISK_PARAMETERS parameters,
            IntPtr overlapped,
            out IntPtr handle);

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
        private static extern int AttachVirtualDisk(
            IntPtr handle,
            IntPtr securityDescriptor,
            uint flags,
            uint providerSpecificFlags,
            ref ATTACH_VIRTUAL_DISK_PARAMETERS parameters,
            IntPtr overlapped);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        public static int CreateAndAttach(string path, ulong maximumSize) {
            var storageType = new VIRTUAL_STORAGE_TYPE {
                DeviceId = 2,
                VendorId = Guid.Empty
            };
            var parameters = new CREATE_VIRTUAL_DISK_PARAMETERS {
                Version = 1
            };
            parameters.Version1.UniqueId = Guid.Empty;
            parameters.Version1.MaximumSize = maximumSize;
            parameters.Version1.BlockSizeInBytes = 0;
            parameters.Version1.SectorSizeInBytes = 0;
            parameters.Version1.ParentPath = IntPtr.Zero;
            parameters.Version1.SourcePath = IntPtr.Zero;

            IntPtr handle;
            int result = CreateVirtualDisk(
                ref storageType,
                path,
                0x003F0000,
                IntPtr.Zero,
                0,
                0,
                ref parameters,
                IntPtr.Zero,
                out handle);
            if (result != 0) {
                return result;
            }

            var attachParameters = new ATTACH_VIRTUAL_DISK_PARAMETERS {
                Version = 1,
                Reserved = 0
            };
            result = AttachVirtualDisk(
                handle,
                IntPtr.Zero,
                4,
                0,
                ref attachParameters,
                IntPtr.Zero);
            CloseHandle(handle);
            return result;
        }
    }
}
'@
}

if (-not (Test-Administrator)) {
    throw 'This script must run from an elevated PowerShell session'
}

$fullPath = [IO.Path]::GetFullPath($Path)
$parent = Split-Path -Parent $fullPath
if (-not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

switch ($Action) {
    'Prepare' {
        if (Test-Path -LiteralPath $fullPath) {
            throw "VHD already exists; use -Action Cleanup first or choose another -Path: $fullPath"
        }

        Write-Host "[+] Creating and permanently attaching $fullPath (${SizeMB} MiB)"
        $result = [Erebus.VirtualDisk]::CreateAndAttach(
            $fullPath,
            [uint64]$SizeMB * 1024 * 1024)
        if ($result -ne 0) {
            throw ("CreateVirtualDisk/AttachVirtualDisk failed: 0x{0:X8}" -f $result)
        }
        if (-not (Test-Path -LiteralPath $fullPath)) {
            throw "VHD was not created: $fullPath"
        }
        Write-Host "[+] Cleanup: powershell.exe -File `"$($MyInvocation.MyCommand.Path)`" -Action Cleanup -Path `"$fullPath`""
    }
    'Cleanup' {
        if (-not (Test-Path -LiteralPath $fullPath)) {
            Write-Host "[+] VHD does not exist: $fullPath"
            return
        }

        $image = Get-DiskImage -ImagePath $fullPath
        if ($image.Attached) {
            Write-Host "[+] Detaching $fullPath"
            Dismount-DiskImage -ImagePath $fullPath | Out-Null
        }
        else {
            Write-Host "[+] VHD is not attached; removing the file"
        }
        Remove-Item -LiteralPath $fullPath -Force
        Write-Host "[+] Removed $fullPath"
    }
}
