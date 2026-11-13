#pragma once

#include "disk.hpp"
#include "erebus_api.h"
#include "payloadbytes.h"
#include <intrin.h>
#include "erebus_defines.h"

static BOOLEAN PayloadNameEqualsBounded(IN const char* left, IN UINT32 leftSize, IN const char* right)
{
	for (UINT32 index = 0; index < leftSize; ++index) {
		if (left[index] != right[index]) {
			return FALSE;
		}

		if (left[index] == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

static BOOLEAN PayloadRvaRangeValid(IN UINT32 rva, IN UINT32 size, IN UINT32 imageSize)
{
	return rva <= imageSize && size <= imageSize - rva;
}

static BOOLEAN FindPayloadExportRva(IN PUINT8 mappedImage, IN PIMAGE_NT_HEADERS64 ntHeaders, IN const char* exportName, OUT UINT32* exportRva)
{
	IMAGE_DATA_DIRECTORY* exportDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	UINT32 imageSize = ntHeaders->OptionalHeader.SizeOfImage;
	if (!exportDirectory->VirtualAddress ||
		!exportDirectory->Size ||
		!PayloadRvaRangeValid(exportDirectory->VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), imageSize)) {
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(mappedImage + exportDirectory->VirtualAddress);
	if (!PayloadRvaRangeValid(exports->AddressOfNames, exports->NumberOfNames * sizeof(ULONG), imageSize) ||
		!PayloadRvaRangeValid(exports->AddressOfNameOrdinals, exports->NumberOfNames * sizeof(USHORT), imageSize) ||
		!PayloadRvaRangeValid(exports->AddressOfFunctions, exports->NumberOfFunctions * sizeof(ULONG), imageSize)) {
		return FALSE;
	}

	PULONG names = reinterpret_cast<PULONG>(mappedImage + exports->AddressOfNames);
	PUSHORT ordinals = reinterpret_cast<PUSHORT>(mappedImage + exports->AddressOfNameOrdinals);
	PULONG functions = reinterpret_cast<PULONG>(mappedImage + exports->AddressOfFunctions);

	for (ULONG i = 0; i < exports->NumberOfNames; ++i) {
		if (!PayloadRvaRangeValid(names[i], 1, imageSize)) {
			return FALSE;
		}

		const char* name = reinterpret_cast<const char*>(mappedImage + names[i]);
		if (PayloadNameEqualsBounded(name, imageSize - names[i], exportName)) {
			USHORT ordinalIndex = ordinals[i];
			if (ordinalIndex >= exports->NumberOfFunctions) {
				return FALSE;
			}

			*exportRva = functions[ordinalIndex];
			return TRUE;
		}
	}

	return FALSE;
}

NTSTATUS PreparePayload(unsigned char* ImageBase, PVOID* buffer, UINT32 physicalPagesUsed, PHYSICAL_ADDRESS allocationBase, OUT PHYSICAL_ADDRESS* pdptPhysicalAddress, OUT UINT32* originalHookOffset, OUT UINT32* entryPoint, OUT UINT32* callDispatcherOffset, OUT UINT32* afterCallDeltaOffset, OUT UINT32* kernelLayoutOffset)
{
	IMAGE_DOS_HEADER* dosHeaders = reinterpret_cast<IMAGE_DOS_HEADER*>(ImageBase);
	if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
	{
		DbgMsg("Invalid DOS signature: %04X", dosHeaders->e_magic);
		return STATUS_INVALID_IMAGE_FORMAT;
	}
	IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(ImageBase + dosHeaders->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return STATUS_INVALID_IMAGE_FORMAT;
	RtlZeroMemory(*buffer, ntHeaders->OptionalHeader.SizeOfImage);
	memcpy((PUINT8)(*buffer), ImageBase, ntHeaders->OptionalHeader.SizeOfHeaders);
	IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((UINT8*)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
	PHYSICAL_ADDRESS pdPhysicalBase{ };
	PHYSICAL_ADDRESS pdptPhysicalBase{ };
	PHYSICAL_ADDRESS ptPhysicalBase{ };

	for (UINT32 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER* section = &sections[i];
		if (memcmp(section->Name, ".1", 2) == 0)
		{
			ptPhysicalBase.QuadPart = section->VirtualAddress + allocationBase.QuadPart;
		}
		else if (memcmp(section->Name, ".2", 2) == 0)
		{
			pdPhysicalBase.QuadPart = section->VirtualAddress + allocationBase.QuadPart;
		}
		else if (memcmp(section->Name, ".3", 2) == 0)
		{
			pdptPhysicalBase.QuadPart = section->VirtualAddress + allocationBase.QuadPart;
		}
	}

	if (!ptPhysicalBase.QuadPart || !pdPhysicalBase.QuadPart || !pdptPhysicalBase.QuadPart)
	{
		DbgMsg("Missing payload page table sections: pt=%p pd=%p pdpt=%p",
			ptPhysicalBase.QuadPart, pdPhysicalBase.QuadPart, pdptPhysicalBase.QuadPart);
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	for (UINT32 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER* section = &sections[i];
		if (section->SizeOfRawData)
		{
			memcpy
			(
				(PUINT8)(*buffer) + section->VirtualAddress,
				ImageBase + section->PointerToRawData,
				section->SizeOfRawData
			);
		}
		if (memcmp(section->Name, ".3", 2) == 0)
		{
			EPT_ENTRY64* pdpt = reinterpret_cast<EPT_ENTRY64*>((PUINT8)(*buffer) + section->VirtualAddress);
			pdpt[511].Present = 1;
			pdpt[511].PageFrameNumber = pdPhysicalBase.QuadPart >> 12;
			pdpt[511].Supervisor = 0;
			pdpt[511].Write = 1;
		}
		if (memcmp(section->Name, ".2", 2) == 0)
		{
			EPT_ENTRY64* pd = reinterpret_cast<EPT_ENTRY64*>((PUINT8)(*buffer) + section->VirtualAddress);
			pd[511].Present = 1;
			pd[511].PageFrameNumber = ptPhysicalBase.QuadPart >> 12;
			pd[511].Supervisor = 0;
			pd[511].Write = 1;
		}
		if (memcmp(section->Name, ".1", 2) == 0)
		{
			EPT_ENTRY64* pt = reinterpret_cast<EPT_ENTRY64*>((PUINT8)(*buffer) + section->VirtualAddress);
			for (UINT32 idx = 0; idx < physicalPagesUsed; idx++)
			{
				pt[idx].Present = 1;
				pt[idx].Supervisor = 0;
				pt[idx].Write = 1;

				UINT64 pagePhysicalAddress = allocationBase.QuadPart + idx * PAGE_SIZE;
				UINT64 pfn = pagePhysicalAddress >> 12;
				pt[idx].PageFrameNumber = pfn;
			}
		}

	}

	UINT32 handlerRva = 0;
	UINT32 originalHandlerSlotRva = 0;
	UINT32 postHandlerRva = 0;
	UINT32 callDispatcherRva = 0;
	UINT32 afterCallDeltaRva = 0;
	UINT32 kernelLayoutRva = 0;
	PUINT8 mappedImage = (PUINT8)(*buffer);

	if (!FindPayloadExportRva(mappedImage, ntHeaders, EREBUS_EXPORT_HANDLER, &handlerRva) ||
		!FindPayloadExportRva(mappedImage, ntHeaders, EREBUS_EXPORT_ORIGINAL_HANDLER, &originalHandlerSlotRva) ||
		!FindPayloadExportRva(mappedImage, ntHeaders, EREBUS_EXPORT_POST_HANDLER, &postHandlerRva) ||
		!FindPayloadExportRva(mappedImage, ntHeaders, EREBUS_EXPORT_CALL_DISPATCHER, &callDispatcherRva) ||
		!FindPayloadExportRva(mappedImage, ntHeaders, EREBUS_EXPORT_AFTER_CALL_DELTA, &afterCallDeltaRva) ||
		!FindPayloadExportRva(mappedImage, ntHeaders, EREBUS_EXPORT_KERNEL_LAYOUT, &kernelLayoutRva)) {
		DbgMsg("Payload is missing required exports: %s / %s / %s / %s / %s / %s",
			EREBUS_EXPORT_HANDLER,
			EREBUS_EXPORT_ORIGINAL_HANDLER,
			EREBUS_EXPORT_POST_HANDLER,
			EREBUS_EXPORT_CALL_DISPATCHER,
			EREBUS_EXPORT_AFTER_CALL_DELTA,
			EREBUS_EXPORT_KERNEL_LAYOUT);
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	if (handlerRva >= ntHeaders->OptionalHeader.SizeOfImage ||
		postHandlerRva >= ntHeaders->OptionalHeader.SizeOfImage ||
		callDispatcherRva >= ntHeaders->OptionalHeader.SizeOfImage ||
		originalHandlerSlotRva + sizeof(UINT64) > ntHeaders->OptionalHeader.SizeOfImage ||
		afterCallDeltaRva + sizeof(UINT64) > ntHeaders->OptionalHeader.SizeOfImage ||
		kernelLayoutRva + sizeof(ErebusKernelLayout) > ntHeaders->OptionalHeader.SizeOfImage) {
		DbgMsg("Payload export RVA out of image: handler=%x post_handler=%x call_dispatcher=%x slot=%x after_delta=%x layout=%x size=%x",
			handlerRva,
			postHandlerRva,
			callDispatcherRva,
			originalHandlerSlotRva,
			afterCallDeltaRva,
			kernelLayoutRva,
			ntHeaders->OptionalHeader.SizeOfImage);
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	IMAGE_DATA_DIRECTORY* baseRelocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (baseRelocDir->VirtualAddress)
	{
		IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)((PUINT8)(*buffer) + baseRelocDir->VirtualAddress);
		for (UINT32 currentSize = 0; currentSize < baseRelocDir->Size; )
		{
			UINT32 relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);
			UINT16* relocData = (UINT16*)((UINT8*)reloc + sizeof(IMAGE_BASE_RELOCATION));
			UINT8* relocBase = (PUINT8)(*buffer) + reloc->VirtualAddress;

			for (UINT32 i = 0; i < relocCount; ++i, ++relocData)
			{
				UINT16 data = *relocData;
				UINT16 type = data >> 12;
				UINT16 offset = data & 0xFFF;

				switch (type)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_DIR64:
				{
					UINT64* rva = (UINT64*)(relocBase + offset);
					*rva = (UINT64)(PAYLOAD_VIRTUAL_BASE + (*rva - ntHeaders->OptionalHeader.ImageBase));
					break;
				}
				default:
					return STATUS_UNSUCCESSFUL;
				}
			}

			currentSize += reloc->SizeOfBlock;
			reloc = (IMAGE_BASE_RELOCATION*)relocData;
		}
	}
	*pdptPhysicalAddress = pdptPhysicalBase;
	*originalHookOffset = originalHandlerSlotRva;
	*entryPoint = handlerRva;
	*callDispatcherOffset = callDispatcherRva;
	*afterCallDeltaOffset = afterCallDeltaRva;
	*kernelLayoutOffset = kernelLayoutRva;
	return STATUS_SUCCESS;
}

UINT32 PayLoadPageCount(VOID)
{
	IMAGE_DOS_HEADER* RecordDosImageHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(payloadData);
	if (RecordDosImageHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	IMAGE_NT_HEADERS64* RecordNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<UINT64>(RecordDosImageHeader) + RecordDosImageHeader->e_lfanew);
	if (RecordNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	UINT32 imageSize = RecordNtHeaders->OptionalHeader.SizeOfImage;
	return (imageSize + 0xFFF) / 0x1000;
}
