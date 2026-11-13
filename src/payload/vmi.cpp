#include "erebus_abi.h"

bool VmRead(UINT64 field, UINT64* value)
{
    size_t raw = 0;
    if (__vmx_vmread(static_cast<size_t>(field), &raw) != 0) {
        return false;
    }

    *value = static_cast<UINT64>(raw);
    return true;
}

bool IsCanonicalPointer(UINT64 value)
{
    UINT64 high = value >> 47;
    return high == 0 || high == 0x1FFFFULL;
}

static void* MapHostPhysical(UINT64 physicalAddress)
{
    UINT64 page = physicalAddress & EREBUS_PHYS_MASK_4KB;
    UINT64 offset = physicalAddress & EREBUS_PAGE_OFFSET_4KB;

    ErebusImagePt[EREBUS_HOST_PHYS_MAP_SLOT] = page | EREBUS_HOST_PHYS_MAP_FLAGS;
    _ReadWriteBarrier();
    __invlpg(reinterpret_cast<void*>(EREBUS_HOST_PHYS_MAP_VA));

    return reinterpret_cast<void*>(EREBUS_HOST_PHYS_MAP_VA + offset);
}

static UINT64 ReadHostPhysicalU64(UINT64 physicalAddress)
{
    volatile UINT64* value = reinterpret_cast<volatile UINT64*>(MapHostPhysical(physicalAddress));
    return *value;
}

static UINT32 EptPml4Index(UINT64 gpa)
{
    return static_cast<UINT32>((gpa >> 39) & 0x1FF);
}

static UINT32 EptPdptIndex(UINT64 gpa)
{
    return static_cast<UINT32>((gpa >> 30) & 0x1FF);
}

static UINT32 EptPdIndex(UINT64 gpa)
{
    return static_cast<UINT32>((gpa >> 21) & 0x1FF);
}

static UINT32 EptPtIndex(UINT64 gpa)
{
    return static_cast<UINT32>((gpa >> 12) & 0x1FF);
}

static bool IsEptEntryPresent(UINT64 entry)
{
    return (entry & EREBUS_EPT_PRESENT_MASK) != 0;
}

static UINT64 WalkGpaInternal(UINT64 eptp, UINT64 gpa, UINT64* hpaOut)
{
    *hpaOut = 0;

    UINT64 pml4Base = eptp & EREBUS_PHYS_MASK_4KB;
    if (!pml4Base) {
        return EREBUS_STATUS_BAD_EPTP;
    }

    UINT64 pml4e = ReadHostPhysicalU64(pml4Base + EptPml4Index(gpa) * sizeof(UINT64));
    if (!IsEptEntryPresent(pml4e)) {
        return EREBUS_STATUS_EPT_NOT_PRESENT;
    }

    UINT64 pdptBase = pml4e & EREBUS_PHYS_MASK_4KB;
    UINT64 pdpte = ReadHostPhysicalU64(pdptBase + EptPdptIndex(gpa) * sizeof(UINT64));
    if (!IsEptEntryPresent(pdpte)) {
        return EREBUS_STATUS_EPT_NOT_PRESENT;
    }
    if (pdpte & EREBUS_EPT_LARGE_PAGE) {
        *hpaOut = (pdpte & EREBUS_PHYS_MASK_1GB) | (gpa & EREBUS_PAGE_OFFSET_1GB);
        return EREBUS_STATUS_OK;
    }

    UINT64 pdBase = pdpte & EREBUS_PHYS_MASK_4KB;
    UINT64 pde = ReadHostPhysicalU64(pdBase + EptPdIndex(gpa) * sizeof(UINT64));
    if (!IsEptEntryPresent(pde)) {
        return EREBUS_STATUS_EPT_NOT_PRESENT;
    }
    if (pde & EREBUS_EPT_LARGE_PAGE) {
        *hpaOut = (pde & EREBUS_PHYS_MASK_2MB) | (gpa & EREBUS_PAGE_OFFSET_2MB);
        return EREBUS_STATUS_OK;
    }

    UINT64 ptBase = pde & EREBUS_PHYS_MASK_4KB;
    UINT64 pte = ReadHostPhysicalU64(ptBase + EptPtIndex(gpa) * sizeof(UINT64));
    if (!IsEptEntryPresent(pte)) {
        return EREBUS_STATUS_EPT_NOT_PRESENT;
    }

    *hpaOut = (pte & EREBUS_PHYS_MASK_4KB) | (gpa & EREBUS_PAGE_OFFSET_4KB);
    return EREBUS_STATUS_OK;
}

static UINT64 MinU64(UINT64 left, UINT64 right)
{
    return left < right ? left : right;
}

UINT64 ReadGuestPhysicalBytes(UINT64 eptp, UINT64 gpa, void* buffer, UINT64 size)
{
    UINT8* out = reinterpret_cast<UINT8*>(buffer);
    UINT64 copied = 0;

    while (copied < size) {
        UINT64 hpa = 0;
        UINT64 currentGpa = gpa + copied;
        UINT64 status = WalkGpaInternal(eptp, currentGpa, &hpa);
        if (status != EREBUS_STATUS_OK) {
            return status;
        }

        UINT64 chunk = MinU64(size - copied, 0x1000ULL - (currentGpa & EREBUS_PAGE_OFFSET_4KB));
        volatile UINT8* mapped = reinterpret_cast<volatile UINT8*>(MapHostPhysical(hpa));
        for (UINT64 index = 0; index < chunk; ++index) {
            out[copied + index] = mapped[index];
        }
        copied += chunk;
    }

    return EREBUS_STATUS_OK;
}

UINT64 WriteGuestPhysicalBytes(UINT64 eptp, UINT64 gpa, const void* buffer, UINT64 size)
{
    const UINT8* in = reinterpret_cast<const UINT8*>(buffer);
    UINT64 copied = 0;

    while (copied < size) {
        UINT64 hpa = 0;
        UINT64 currentGpa = gpa + copied;
        UINT64 status = WalkGpaInternal(eptp, currentGpa, &hpa);
        if (status != EREBUS_STATUS_OK) {
            return status;
        }

        UINT64 chunk = MinU64(size - copied, 0x1000ULL - (currentGpa & EREBUS_PAGE_OFFSET_4KB));
        volatile UINT8* mapped = reinterpret_cast<volatile UINT8*>(MapHostPhysical(hpa));
        for (UINT64 index = 0; index < chunk; ++index) {
            mapped[index] = in[copied + index];
        }
        _ReadWriteBarrier();
        copied += chunk;
    }

    return EREBUS_STATUS_OK;
}

static UINT64 ReadGuestPhysicalU64(UINT64 eptp, UINT64 gpa, UINT64* valueOut)
{
    UINT64 value = 0;
    UINT64 status = ReadGuestPhysicalBytes(eptp, gpa, &value, sizeof(value));
    *valueOut = value;
    return status;
}

static UINT64 TranslateGuestVirtual(UINT64 eptp, UINT64 directoryBase, UINT64 guestVirtual, UINT64* gpaOut)
{
    UINT64 pml4Base = directoryBase & EREBUS_PHYS_MASK_4KB;
    if (!pml4Base) {
        *gpaOut = 0;
        return EREBUS_STATUS_BAD_REQUEST;
    }

    UINT64 pml4e = 0;
    UINT64 status = ReadGuestPhysicalU64(
        eptp,
        pml4Base + EptPml4Index(guestVirtual) * sizeof(UINT64),
        &pml4e);
    if (status != EREBUS_STATUS_OK || (pml4e & EREBUS_GUEST_PAGING_PRESENT) == 0) {
        *gpaOut = 0;
        return status == EREBUS_STATUS_OK ? EREBUS_STATUS_TRANSLATION_FAILED : status;
    }

    UINT64 pdpte = 0;
    status = ReadGuestPhysicalU64(
        eptp,
        (pml4e & EREBUS_PHYS_MASK_4KB) + EptPdptIndex(guestVirtual) * sizeof(UINT64),
        &pdpte);
    if (status != EREBUS_STATUS_OK || (pdpte & EREBUS_GUEST_PAGING_PRESENT) == 0) {
        *gpaOut = 0;
        return status == EREBUS_STATUS_OK ? EREBUS_STATUS_TRANSLATION_FAILED : status;
    }
    if ((pdpte & EREBUS_GUEST_PAGING_LARGE_PAGE) != 0) {
        *gpaOut = (pdpte & EREBUS_PHYS_MASK_1GB) | (guestVirtual & EREBUS_PAGE_OFFSET_1GB);
        return EREBUS_STATUS_OK;
    }

    UINT64 pde = 0;
    status = ReadGuestPhysicalU64(
        eptp,
        (pdpte & EREBUS_PHYS_MASK_4KB) + EptPdIndex(guestVirtual) * sizeof(UINT64),
        &pde);
    if (status != EREBUS_STATUS_OK || (pde & EREBUS_GUEST_PAGING_PRESENT) == 0) {
        *gpaOut = 0;
        return status == EREBUS_STATUS_OK ? EREBUS_STATUS_TRANSLATION_FAILED : status;
    }
    if ((pde & EREBUS_GUEST_PAGING_LARGE_PAGE) != 0) {
        *gpaOut = (pde & EREBUS_PHYS_MASK_2MB) | (guestVirtual & EREBUS_PAGE_OFFSET_2MB);
        return EREBUS_STATUS_OK;
    }

    UINT64 pte = 0;
    status = ReadGuestPhysicalU64(
        eptp,
        (pde & EREBUS_PHYS_MASK_4KB) + EptPtIndex(guestVirtual) * sizeof(UINT64),
        &pte);
    if (status != EREBUS_STATUS_OK || (pte & EREBUS_GUEST_PAGING_PRESENT) == 0) {
        *gpaOut = 0;
        return status == EREBUS_STATUS_OK ? EREBUS_STATUS_TRANSLATION_FAILED : status;
    }

    *gpaOut = (pte & EREBUS_PHYS_MASK_4KB) | (guestVirtual & EREBUS_PAGE_OFFSET_4KB);
    return EREBUS_STATUS_OK;
}

UINT64 ReadGuestVirtualBytes(UINT64 eptp, UINT64 directoryBase, UINT64 guestVirtual, void* buffer, UINT64 size)
{
    UINT8* out = reinterpret_cast<UINT8*>(buffer);
    UINT64 copied = 0;

    while (copied < size) {
        UINT64 currentVa = guestVirtual + copied;
        UINT64 gpa = 0;
        UINT64 status = TranslateGuestVirtual(eptp, directoryBase, currentVa, &gpa);
        if (status != EREBUS_STATUS_OK) {
            return status;
        }

        UINT64 chunk = MinU64(size - copied, 0x1000ULL - (currentVa & EREBUS_PAGE_OFFSET_4KB));
        status = ReadGuestPhysicalBytes(eptp, gpa, out + copied, chunk);
        if (status != EREBUS_STATUS_OK) {
            return status;
        }
        copied += chunk;
    }

    return EREBUS_STATUS_OK;
}

UINT64 ReadGuestVirtualU64(UINT64 eptp, UINT64 directoryBase, UINT64 guestVirtual, UINT64* valueOut)
{
    UINT64 value = 0;
    UINT64 status = ReadGuestVirtualBytes(eptp, directoryBase, guestVirtual, &value, sizeof(value));
    *valueOut = value;
    return status;
}

UINT64 WriteGuestVirtualBytes(UINT64 eptp, UINT64 directoryBase, UINT64 guestVirtual, const void* buffer, UINT64 size)
{
    const UINT8* in = reinterpret_cast<const UINT8*>(buffer);
    UINT64 copied = 0;

    while (copied < size) {
        UINT64 currentVa = guestVirtual + copied;
        UINT64 gpa = 0;
        UINT64 status = TranslateGuestVirtual(eptp, directoryBase, currentVa, &gpa);
        if (status != EREBUS_STATUS_OK) {
            return status;
        }

        UINT64 chunk = MinU64(size - copied, 0x1000ULL - (currentVa & EREBUS_PAGE_OFFSET_4KB));
        status = WriteGuestPhysicalBytes(eptp, gpa, in + copied, chunk);
        if (status != EREBUS_STATUS_OK) {
            return status;
        }
        copied += chunk;
    }

    return EREBUS_STATUS_OK;
}
