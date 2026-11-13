#pragma once
#include <ntifs.h>
#include <ntddscsi.h>
#include <intrin.h>
#include "erebus_defines.h"
#pragma warning(disable: 4201 4996)
extern "C" void LoaderASM();
extern "C" void LoaderASMEnd();
extern "C" UINT64 ExecuteCPUID(...);
typedef union
{
    struct
    {
        UINT64 Present : 1;
        UINT64 Write : 1;
        UINT64 Supervisor : 1;
        UINT64 PageLevelWriteThrough : 1;
        UINT64 PageLevelCacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Reserved1 : 1;
        UINT64 LargePage : 1;
        UINT64 Ignored1 : 4;
        UINT64 PageFrameNumber : 40;
        UINT64 Ignored2 : 11;
        UINT64 ExecuteDisable : 1;
    };

    UINT64 Flags;
} EPT_ENTRY64;
static_assert(sizeof(EPT_ENTRY64) == 8, "size mismatch");

typedef struct _DISK {
    PDEVICE_OBJECT Device;
    UINT8 Buffer[PAGE_SIZE];
} DISK, * PDISK;
extern "C" POBJECT_TYPE* IoDriverObjectType;
extern "C" NTSTATUS ObReferenceObjectByName(IN PUNICODE_STRING objectName, IN ULONG attributes,
    IN PACCESS_STATE passedAccessState,
    IN ACCESS_MASK desiredAccess,
    IN POBJECT_TYPE objectType,
    IN KPROCESSOR_MODE accessMode,
    IN OUT PVOID parseContext, OUT PVOID* object);
typedef struct {
    SCSI_PASS_THROUGH_DIRECT spt;
    ULONG		Filler;
    UCHAR		ucSenseBuf[36];
} SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, * PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;
