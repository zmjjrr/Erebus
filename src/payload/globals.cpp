#include "erebus_abi.h"

extern "C" __declspec(dllexport) UINT64 ErebusOriginalHandler = 0;
extern "C" __declspec(dllexport) UINT64 ErebusAfterCallDelta = 0;
extern "C" __declspec(dllexport) volatile ErebusKernelLayoutBlob ErebusKernelLayout = {};

#pragma section(".1", read, write)
// These arrays anchor the .1/.2/.3 PE sections that PreparePayload() patches.
// Keep the definitions and their exports: dropping them lets the linker drop
// the sections, and PreparePayload() then fails with STATUS_INVALID_IMAGE_FORMAT.
extern "C" __declspec(allocate(".1")) __declspec(dllexport) volatile UINT64 ErebusImagePt[512] = {};
#pragma section(".2", read, write)
extern "C" __declspec(allocate(".2")) __declspec(dllexport) volatile UINT64 ErebusImagePd[512] = {};
#pragma section(".3", read, write)
extern "C" __declspec(allocate(".3")) __declspec(dllexport) volatile UINT64 ErebusImagePdpt[512] = {};
