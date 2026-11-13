#pragma once

#include "erebus_defines.h"

#if defined(_KERNEL_MODE) || defined(_NTDDK_) || defined(_NTIFS_)
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

// Wire layout shared by the user-mode client, the kernel driver and the
// resident payload. Keep the duplicate definition in src/payload/erebus_abi.h
// in sync; the static assertions below guard the sizes.
#pragma pack(push, 8)
typedef struct ErebusCommand
{
    uint64_t magic;
    uint32_t size;
    uint32_t operation;
    uint64_t sourceCr3;
    uint64_t destinationCr3;
    uint64_t sourceAddress;
    uint64_t destinationAddress;
    uint64_t bytesRequested;
    uint64_t bytesTransferred;
    uint64_t payloadStatus;
    uint64_t result0;
    uint64_t result1;
    uint64_t result2;
    uint16_t moduleName[EREBUS_MAX_MODULE_NAME_CHARS];
    uint8_t data[EREBUS_MAX_TRANSFER];
} ErebusCommand;

typedef struct ErebusKernelLayout
{
    uint64_t magic;
    uint32_t size;
    uint64_t ntBuildNumber;
    uint64_t psInitialSystemProcess;
    uint64_t systemDirectoryTableBase;
    uint32_t eprocessDirectoryTableBase;
    uint32_t eprocessUserDirectoryTableBase;
    uint32_t eprocessPeb;
    uint32_t eprocessUniqueProcessId;
    uint32_t eprocessActiveProcessLinks;
    uint32_t reserved0;
} ErebusKernelLayout;

static_assert(sizeof(ErebusCommand) == 480, "ErebusCommand layout changed; update src/payload/erebus_abi.h");
static_assert(sizeof(ErebusKernelLayout) == 64, "ErebusKernelLayout layout changed; update src/payload/erebus_abi.h");
#pragma pack(pop)
