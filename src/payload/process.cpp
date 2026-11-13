#include "erebus_abi.h"

bool GuestDirectoryBaseValid(UINT64 directoryBase)
{
    return (directoryBase & EREBUS_PHYS_MASK_4KB) != 0;
}

static bool KernelLayoutReady()
{
    return ErebusKernelLayout.Magic == EREBUS_KERNEL_LAYOUT_MAGIC &&
        ErebusKernelLayout.Size >= sizeof(ErebusKernelLayoutBlob) &&
        ErebusKernelLayout.PsInitialSystemProcess != 0 &&
        GuestDirectoryBaseValid(ErebusKernelLayout.SystemDirectoryTableBase) &&
        ErebusKernelLayout.EprocessDirectoryTableBase != 0 &&
        ErebusKernelLayout.EprocessPeb != 0 &&
        ErebusKernelLayout.EprocessUniqueProcessId != 0 &&
        ErebusKernelLayout.EprocessActiveProcessLinks != 0;
}

UINT64 ResolveProcessByPid(
    UINT64 eptp,
    UINT64 pid,
    UINT64 kernelDirectoryBase,
    UINT64* processOut,
    UINT64* directoryBaseOut,
    UINT64* pebOut)
{
    *processOut = 0;
    *directoryBaseOut = 0;
    *pebOut = 0;

    if (pid == 0 || !KernelLayoutReady()) {
        return EREBUS_STATUS_BAD_REQUEST;
    }

    UINT64 systemProcess = ErebusKernelLayout.PsInitialSystemProcess;
    UINT64 systemCr3 = kernelDirectoryBase ?
        (kernelDirectoryBase & EREBUS_PHYS_MASK_4KB) :
        (ErebusKernelLayout.SystemDirectoryTableBase & EREBUS_PHYS_MASK_4KB);
    UINT32 directoryBaseOffset = ErebusKernelLayout.EprocessDirectoryTableBase;
    UINT32 userDirectoryBaseOffset = ErebusKernelLayout.EprocessUserDirectoryTableBase;
    UINT32 pebOffset = ErebusKernelLayout.EprocessPeb;
    UINT32 uniqueProcessIdOffset = ErebusKernelLayout.EprocessUniqueProcessId;
    UINT32 activeProcessLinksOffset = ErebusKernelLayout.EprocessActiveProcessLinks;

    if (!IsCanonicalPointer(systemProcess) || !GuestDirectoryBaseValid(systemCr3)) {
        return EREBUS_STATUS_BAD_REQUEST;
    }

    UINT64 listHead = systemProcess + activeProcessLinksOffset;
    UINT64 current = listHead;
    for (UINT32 iteration = 0; iteration < 4096; ++iteration) {
        if (current < activeProcessLinksOffset || !IsCanonicalPointer(current)) {
            return EREBUS_STATUS_TRANSLATION_FAILED;
        }

        UINT64 process = current - activeProcessLinksOffset;
        UINT64 currentPid = 0;
        UINT64 status = ReadGuestVirtualU64(
            eptp,
            systemCr3,
            process + uniqueProcessIdOffset,
            &currentPid);
        if (status != EREBUS_STATUS_OK) {
            return status;
        }

        if (currentPid == pid) {
            UINT64 directoryBase = 0;
            UINT64 userDirectoryBase = 0;
            status = ReadGuestVirtualU64(
                eptp,
                systemCr3,
                process + directoryBaseOffset,
                &directoryBase);
            if (status != EREBUS_STATUS_OK) {
                return status;
            }

            if (userDirectoryBaseOffset != 0) {
                status = ReadGuestVirtualU64(
                    eptp,
                    systemCr3,
                    process + userDirectoryBaseOffset,
                    &userDirectoryBase);
                if (status != EREBUS_STATUS_OK) {
                    return status;
                }
            }

            UINT64 peb = 0;
            status = ReadGuestVirtualU64(eptp, systemCr3, process + pebOffset, &peb);
            if (status != EREBUS_STATUS_OK) {
                return status;
            }

            UINT64 selectedDirectoryBase = GuestDirectoryBaseValid(userDirectoryBase) ?
                userDirectoryBase :
                directoryBase;
            if (!GuestDirectoryBaseValid(selectedDirectoryBase)) {
                return EREBUS_STATUS_TRANSLATION_FAILED;
            }

            *processOut = process;
            *directoryBaseOut = selectedDirectoryBase;
            *pebOut = peb;
            return EREBUS_STATUS_OK;
        }

        UINT64 next = 0;
        status = ReadGuestVirtualU64(eptp, systemCr3, current, &next);
        if (status != EREBUS_STATUS_OK) {
            return status;
        }
        if (next == 0 || next == listHead) {
            break;
        }
        current = next;
    }

    return EREBUS_STATUS_PROCESS_NOT_FOUND;
}

static UINT16 ToLowerAsciiWide(UINT16 value)
{
    if (value >= 'A' && value <= 'Z') {
        return static_cast<UINT16>(value + ('a' - 'A'));
    }
    return value;
}

static bool WideStringEqualsInsensitive(const UINT16* left, const UINT16* right, UINT64 maxChars)
{
    for (UINT64 index = 0; index < maxChars; ++index) {
        UINT16 l = ToLowerAsciiWide(left[index]);
        UINT16 r = ToLowerAsciiWide(right[index]);
        if (l != r) {
            return false;
        }
        if (l == 0) {
            return true;
        }
    }

    return true;
}

bool CommandHeaderValid(const ErebusCommand* command)
{
    return command->Magic == EREBUS_API_MAGIC &&
        command->Size >= sizeof(ErebusCommand);
}

UINT64 FindModuleInPeb(
    UINT64 eptp,
    UINT64 directoryBase,
    UINT64 pebAddress,
    const UINT16* moduleName,
    UINT64* moduleBaseOut,
    UINT64* moduleSizeOut)
{
    *moduleBaseOut = 0;
    *moduleSizeOut = 0;

    if (pebAddress == 0 || moduleName[0] == 0) {
        return EREBUS_STATUS_BAD_REQUEST;
    }

    ErebusPeb64 peb = {};
    UINT64 status = ReadGuestVirtualBytes(eptp, directoryBase, pebAddress, &peb, sizeof(peb));
    if (status != EREBUS_STATUS_OK || peb.Ldr == 0) {
        return status == EREBUS_STATUS_OK ? EREBUS_STATUS_TRANSLATION_FAILED : status;
    }

    ErebusPebLdrData64 ldr = {};
    status = ReadGuestVirtualBytes(eptp, directoryBase, peb.Ldr, &ldr, sizeof(ldr));
    if (status != EREBUS_STATUS_OK) {
        return status;
    }

    UINT64 listHead = peb.Ldr + 0x10ULL;
    UINT64 current = ldr.InLoadOrderModuleList.Flink;
    for (UINT32 iteration = 0; iteration < 512 && current != 0 && current != listHead; ++iteration) {
        ErebusLdrDataTableEntry64 entry = {};
        status = ReadGuestVirtualBytes(eptp, directoryBase, current, &entry, sizeof(entry));
        if (status != EREBUS_STATUS_OK) {
            return status;
        }

        if (entry.BaseDllName.Buffer != 0 && entry.BaseDllName.Length != 0) {
            UINT16 nameBuffer[EREBUS_MAX_MODULE_NAME_CHARS] = {};
            UINT64 bytesToRead = entry.BaseDllName.Length;
            if (bytesToRead > (EREBUS_MAX_MODULE_NAME_CHARS - 1ULL) * sizeof(UINT16)) {
                bytesToRead = (EREBUS_MAX_MODULE_NAME_CHARS - 1ULL) * sizeof(UINT16);
            }

            status = ReadGuestVirtualBytes(eptp, directoryBase, entry.BaseDllName.Buffer, nameBuffer, bytesToRead);
            if (status != EREBUS_STATUS_OK) {
                return status;
            }

            if (WideStringEqualsInsensitive(nameBuffer, moduleName, EREBUS_MAX_MODULE_NAME_CHARS)) {
                *moduleBaseOut = entry.DllBase;
                *moduleSizeOut = entry.SizeOfImage;
                return EREBUS_STATUS_OK;
            }
        }

        current = entry.InLoadOrderLinks.Flink;
    }

    return EREBUS_STATUS_MODULE_NOT_FOUND;
}
