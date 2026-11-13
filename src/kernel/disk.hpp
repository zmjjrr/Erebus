#pragma once

// Credits BTBD and Cutecatsandvirtualmachines (BTBD for original POC and ccvm for SCSI support). Removed ATA support because I felt like it.
// https://github.com/cutecatsandvirtualmachines/DDMA
// https://github.com/btbd/ddma

#include "defines.h"
#include <ntimage.h>
#include <scsi.h>
#include <cstddef>
#include "erebus_defines.h"


typedef PDEVICE_OBJECT (*PFN_IO_GET_LOWER_DEVICE_OBJECT)(PDEVICE_OBJECT DeviceObject);

static PFN_IO_GET_LOWER_DEVICE_OBJECT ResolveIoGetLowerDeviceObject()
{
    static PFN_IO_GET_LOWER_DEVICE_OBJECT getLower = NULL;
    static BOOLEAN resolved = FALSE;
    UNICODE_STRING routineName;

    if (!resolved) {
        RtlInitUnicodeString(&routineName, L"IoGetLowerDeviceObject");
        getLower = (PFN_IO_GET_LOWER_DEVICE_OBJECT)MmGetSystemRoutineAddress(&routineName);
        resolved = TRUE;
    }

    return getLower;
}

static BOOLEAN IsVhdmpDevice(PDEVICE_OBJECT device)
{
    UNICODE_STRING vhdmpName;

    RtlInitUnicodeString(&vhdmpName, L"\\Driver\\vhdmp");
    return device &&
        device->DriverObject &&
        RtlEqualUnicodeString(&device->DriverObject->DriverName, &vhdmpName, TRUE);
}

static BOOLEAN IsVhdmpBackedDisk(PDEVICE_OBJECT device)
{
    PFN_IO_GET_LOWER_DEVICE_OBJECT getLower = ResolveIoGetLowerDeviceObject();

    for (PDEVICE_OBJECT current = device; current; current = current->AttachedDevice) {
        if (IsVhdmpDevice(current)) {
            return TRUE;
        }
    }

    if (!getLower) {
        return FALSE;
    }

    PDEVICE_OBJECT current = getLower(device);
    while (current) {
        PDEVICE_OBJECT next = NULL;
        BOOLEAN matched = IsVhdmpDevice(current);

        if (!matched) {
            next = getLower(current);
        }
        ObDereferenceObject(current);

        if (matched) {
            return TRUE;
        }

        current = next;
    }

    return FALSE;
}

NTSTATUS GetDeviceObjectList(IN PDRIVER_OBJECT driverObject, OUT PDEVICE_OBJECT** outDevices,
    OUT PULONG outDeviceCount) {

    ULONG count = 0;
    NTSTATUS status = IoEnumerateDeviceObjectList(driverObject, NULL, 0, &count);

    if (status != STATUS_BUFFER_TOO_SMALL) {
        return status;
    }

    ULONG size = count * sizeof(PDEVICE_OBJECT);
    PDEVICE_OBJECT* devices = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPoolNx, size);
    if (devices) {
        *outDeviceCount = count;

        status = IoEnumerateDeviceObjectList(driverObject, devices, size, &count);
        if (NT_SUCCESS(status)) {
            *outDevices = devices;
        }
        else {
            ExFreePool(devices);
        }
    }
    else {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    return status;
}

BOOLEAN SCSIBuild10CDB(PSCSI_PASS_THROUGH_DIRECT srb, ULONGLONG offset, ULONG length, BOOLEAN Write) {
    if (!srb || offset >= 0x20000000000 || length < 1)
        return FALSE;

    LPCH cdb = (LPCH)srb->Cdb;

    if (Write == FALSE) {
        cdb[0] = SCSIOP_READ;
        cdb[1] = 0;
    }
    else {
        cdb[0] = SCSIOP_WRITE;
        cdb[1] = 0;
    }
    DWORD32 LBA = (DWORD32)(offset / SCSI_SECTOR_SIZE);

    cdb[2] = ((LPCH)&LBA)[3];
    cdb[3] = ((LPCH)&LBA)[2];
    cdb[4] = ((LPCH)&LBA)[1];
    cdb[5] = ((LPCH)&LBA)[0];
    cdb[6] = 0x00;

    SHORT CDBTLen = (SHORT)(length / SCSI_SECTOR_SIZE);
    cdb[7] = ((LPCH)&CDBTLen)[1];
    cdb[8] = ((LPCH)&CDBTLen)[0];
    cdb[9] = 0x00;
    return TRUE;
}

static NTSTATUS ScsiIssueCommand(IN PDEVICE_OBJECT device, IN UCHAR operationCode, IN PVOID buffer) {
    KEVENT event;
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);

    SCSI_PASS_THROUGH_DIRECT Srb = { 0 };

    Srb.Length = sizeof(Srb);
    Srb.CdbLength = 10;
    Srb.SenseInfoLength = 0;
    Srb.SenseInfoOffset = sizeof(Srb);
    Srb.DataIn = operationCode == SCSIOP_WRITE ? SCSI_IOCTL_DATA_OUT : SCSI_IOCTL_DATA_IN;
    Srb.DataTransferLength = PAGE_SIZE;
    Srb.TimeOutValue = 5;
    Srb.DataBuffer = buffer;

    if (!SCSIBuild10CDB(&Srb, EREBUS_SCRATCH_LBA * SCSI_SECTOR_SIZE, Srb.DataTransferLength, operationCode == SCSIOP_WRITE)) {
        return STATUS_INVALID_PARAMETER;
    }

    IO_STATUS_BLOCK ioStatusBlock;

    PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_SCSI_PASS_THROUGH_DIRECT, device, &Srb,
        sizeof(Srb), 0, 0, FALSE,
        &event, &ioStatusBlock);

    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // DataBuffer above is always a kernel VA. Keep the IRP kernel-mode so
    // StorPort locks it instead of probing it as user memory.
    irp->RequestorMode = KernelMode;

    NTSTATUS status = IoCallDriver(device, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }

    return status;
}

NTSTATUS ScsiReadPage(IN PDEVICE_OBJECT device, OUT PVOID dest) {
    return ScsiIssueCommand(device, SCSIOP_READ, dest);
}

NTSTATUS ScsiWritePage(IN PDEVICE_OBJECT device, IN PVOID src) {
    return ScsiIssueCommand(device, SCSIOP_WRITE, src);
}

NTSTATUS DiskCopy(IN PDISK disk, IN PVOID dest, IN PVOID src) {
    if (!disk || !disk->Device) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = ScsiWritePage(disk->Device, src);
    if (NT_SUCCESS(status)) {
        // Write to dest by reading from disk
        status = ScsiReadPage(disk->Device, dest);

        // Restore original sectors
        ScsiWritePage(disk->Device, disk->Buffer);
    }

    return status;
}

NTSTATUS DiskCopyPagesEx(
    IN PDISK disk,
    IN PVOID dest,
    IN PVOID src,
    IN UINT64 pageCount,
    OUT UINT64* failedPageIndexOut) {
    if (!disk || !disk->Device) {
        return STATUS_INVALID_PARAMETER;
    }

    if (failedPageIndexOut) {
        *failedPageIndexOut = 0;
    }

    NTSTATUS status = STATUS_SUCCESS;
    for (UINT64 i = 0; i < pageCount; ++i) {
        PVOID srcPage = (PVOID)((PUCHAR)src + i * PAGE_SIZE);
        PVOID destPage = (PVOID)((PUCHAR)dest + i * PAGE_SIZE);

        status = ScsiWritePage(disk->Device, srcPage);
        if (!NT_SUCCESS(status)) {
            if (failedPageIndexOut) {
                *failedPageIndexOut = i;
            }
            break;
        }

        status = ScsiReadPage(disk->Device, destPage);
        if (!NT_SUCCESS(status)) {
            if (failedPageIndexOut) {
                *failedPageIndexOut = i;
            }
            break;
        }

        ScsiWritePage(disk->Device, disk->Buffer);
    }
    return status;
}

NTSTATUS DiskCopyPages(IN PDISK disk, IN PVOID dest, IN PVOID src, IN UINT64 pageCount) {
    return DiskCopyPagesEx(disk, dest, src, pageCount, NULL);
}
BOOLEAN IsMicrosoftVirtualDisk(PDEVICE_OBJECT device, PVOID buffer) {
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER sptdwb = { 0 };
    PSCSI_PASS_THROUGH_DIRECT sptd = &sptdwb.spt;

    sptd->Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    sptd->CdbLength = 6;
    sptd->SenseInfoLength = 32;
    sptd->DataIn = SCSI_IOCTL_DATA_IN;
    sptd->DataTransferLength = 96;
    sptd->TimeOutValue = 10;
    sptd->DataBuffer = buffer;
    sptd->SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, ucSenseBuf);
    sptd->Cdb[0] = SCSIOP_INQUIRY;
    sptd->Cdb[4] = 96;

    KEVENT event;
    IO_STATUS_BLOCK iosb;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    PIRP irp = IoBuildDeviceIoControlRequest(
        IOCTL_SCSI_PASS_THROUGH_DIRECT,
        device,
        &sptdwb,
        sizeof(sptdwb),
        &sptdwb,
        sizeof(sptdwb),
        FALSE,
        &event,
        &iosb
    );

    if (!irp) {
        return FALSE;
    }

    NTSTATUS status = IoCallDriver(device, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    PINQUIRYDATA inquiryData = (PINQUIRYDATA)buffer;
    if (RtlCompareMemory(&inquiryData->VendorId[0], "Msft    ", 8) == 8) {
        if (RtlCompareMemory(&inquiryData->ProductId[0], "Virtual Disk    ", 16) == 16) {
            return TRUE;
        }
    }

    return FALSE;
}

VOID DiskRelease(IN PDISK disk)
{
    if (!disk) {
        return;
    }

    if (disk->Device) {
        ObDereferenceObject(disk->Device);
        disk->Device = NULL;
    }

    ExFreePool(disk);
}

NTSTATUS DiskFind(OUT PDISK* outDisk) {
    PDISK disk = (PDISK)ExAllocatePool(NonPagedPoolNx, sizeof(DISK));
    if (!disk) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(disk, sizeof(*disk));

    UNICODE_STRING diskStr = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
    PDRIVER_OBJECT diskObject;

    NTSTATUS status = ObReferenceObjectByName(&diskStr, OBJ_CASE_INSENSITIVE, NULL, 0,
        *IoDriverObjectType, KernelMode, NULL, (PVOID*)&diskObject);

    if (NT_SUCCESS(status)) {
        PDEVICE_OBJECT* devices;
        ULONG deviceCount;

        status = GetDeviceObjectList(diskObject, &devices, &deviceCount);

        if (NT_SUCCESS(status)) {
            status = STATUS_NOT_FOUND;

            for (ULONG i = 0; i < deviceCount; ++i) {
                PDEVICE_OBJECT device = devices[i];


                if (status == STATUS_NOT_FOUND &&
                    IsVhdmpBackedDisk(device) &&
                    IsMicrosoftVirtualDisk(device, disk->Buffer) &&
                    NT_SUCCESS(ScsiReadPage(device, disk->Buffer))) {
                    disk->Device = device;
                    status = STATUS_SUCCESS;
                    continue;
                }

                ObDereferenceObject(device);
            }

            ExFreePool(devices);
        }

        ObDereferenceObject(diskObject);
    }

    if (NT_SUCCESS(status)) {
        *outDisk = disk;
    }
    else {
        DiskRelease(disk);
    }

    return status;
}
