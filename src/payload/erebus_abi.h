#pragma once

#include <intrin.h>
#include "../../shared/erebus_defines.h"

using UINT8 = unsigned char;
using UINT16 = unsigned short;
using UINT32 = unsigned int;
using UINT64 = unsigned long long;

struct ErebusCpuidContext
{
    UINT64 Rax;
    UINT64 Rcx;
    UINT64 Rdx;
    UINT64 Rbx;
};

// Snapshot of the intercepted CPUID context captured by the call dispatcher.
// ErebusPostVmExitHandler runs after the original handler returns, so the
// guest context is no longer directly reachable at that point.
struct ErebusCpuidPostSnapshot
{
    ErebusCpuidContext* Context;
    UINT64 Rax;
    UINT64 Rbx;
    UINT64 Rcx;
};

// Keep this definition in sync with shared/erebus_api.h; the static
// assertions at the bottom guard the wire layout.
struct ErebusCommand
{
    UINT64 Magic;
    UINT32 Size;
    UINT32 Operation;
    UINT64 SourceCr3;
    UINT64 DestinationCr3;
    UINT64 SourceAddress;
    UINT64 DestinationAddress;
    UINT64 BytesRequested;
    UINT64 BytesTransferred;
    UINT64 PayloadStatus;
    UINT64 Result0;
    UINT64 Result1;
    UINT64 Result2;
    UINT16 ModuleName[EREBUS_MAX_MODULE_NAME_CHARS];
    UINT8 Data[EREBUS_MAX_TRANSFER];
};

struct ErebusKernelLayoutBlob
{
    UINT64 Magic;
    UINT32 Size;
    UINT64 NtBuildNumber;
    UINT64 PsInitialSystemProcess;
    UINT64 SystemDirectoryTableBase;
    UINT32 EprocessDirectoryTableBase;
    UINT32 EprocessUserDirectoryTableBase;
    UINT32 EprocessPeb;
    UINT32 EprocessUniqueProcessId;
    UINT32 EprocessActiveProcessLinks;
    UINT32 Reserved0;
};

struct ErebusListEntry64
{
    UINT64 Flink;
    UINT64 Blink;
};

struct ErebusUnicodeString64
{
    UINT16 Length;
    UINT16 MaximumLength;
    UINT32 Padding;
    UINT64 Buffer;
};

struct ErebusPeb64
{
    UINT8 Reserved0[0x18];
    UINT64 Ldr;
};

struct ErebusPebLdrData64
{
    UINT8 Reserved0[0x10];
    ErebusListEntry64 InLoadOrderModuleList;
};

struct ErebusLdrDataTableEntry64
{
    ErebusListEntry64 InLoadOrderLinks;
    ErebusListEntry64 InMemoryOrderModuleList;
    ErebusListEntry64 InInitializationOrderModuleList;
    UINT64 DllBase;
    UINT64 EntryPoint;
    UINT32 SizeOfImage;
    UINT32 Padding;
    ErebusUnicodeString64 FullDllName;
    ErebusUnicodeString64 BaseDllName;
};

extern "C" __declspec(dllexport) UINT64 ErebusOriginalHandler;
extern "C" __declspec(dllexport) UINT64 ErebusAfterCallDelta;
extern "C" __declspec(dllexport) volatile ErebusKernelLayoutBlob ErebusKernelLayout;
extern "C" __declspec(dllexport) volatile UINT64 ErebusImagePt[512];

extern "C" __declspec(dllexport) UINT64 __fastcall ErebusVmExitHandler(void* arg1, void* arg2, void* arg3, void* arg4);
extern "C" __declspec(dllexport) void __fastcall ErebusPostVmExitHandler(ErebusCpuidPostSnapshot* pending);

// Cross-TU helpers (plain C++ linkage, internal to the payload image).
bool VmRead(UINT64 field, UINT64* value);
bool IsCanonicalPointer(UINT64 value);
UINT64 ReadGuestPhysicalBytes(UINT64 eptp, UINT64 gpa, void* buffer, UINT64 size);
UINT64 WriteGuestPhysicalBytes(UINT64 eptp, UINT64 gpa, const void* buffer, UINT64 size);
UINT64 ReadGuestVirtualBytes(UINT64 eptp, UINT64 directoryBase, UINT64 guestVirtual, void* buffer, UINT64 size);
UINT64 ReadGuestVirtualU64(UINT64 eptp, UINT64 directoryBase, UINT64 guestVirtual, UINT64* valueOut);
UINT64 WriteGuestVirtualBytes(UINT64 eptp, UINT64 directoryBase, UINT64 guestVirtual, const void* buffer, UINT64 size);
bool GuestDirectoryBaseValid(UINT64 directoryBase);
UINT64 ResolveProcessByPid(UINT64 eptp, UINT64 pid, UINT64 kernelDirectoryBase, UINT64* processOut, UINT64* directoryBaseOut, UINT64* pebOut);
bool CommandHeaderValid(const ErebusCommand* command);
UINT64 FindModuleInPeb(UINT64 eptp, UINT64 directoryBase, UINT64 pebAddress, const UINT16* moduleName, UINT64* moduleBaseOut, UINT64* moduleSizeOut);

static_assert(sizeof(ErebusCommand) == 480, "ErebusCommand layout differs from shared/erebus_api.h");
static_assert(sizeof(ErebusKernelLayoutBlob) == 64, "ErebusKernelLayoutBlob layout differs from shared/erebus_api.h");
