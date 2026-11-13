#pragma once

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

#define EREBUS_API_MAGIC 0x4552454255534131ULL /* "EREBUSA1" */

#define EREBUS_CPUID_LEAF 0xDEADBEEFULL
#define EREBUS_CPUID_HV_VENDOR_LEAF 0x40000000

#define EREBUS_CPUID_READY_SUBLEAF 0x00114514ULL
#define EREBUS_CPUID_READY_VALUE 0x01919810ULL

// CPUID command selectors (passed in RCX). They deliberately overlap the
// low 32 bits of the matching status codes below.
#define EREBUS_READ_VA 0xE2B00042ULL
#define EREBUS_WRITE_VA 0xE2B00043ULL
#define EREBUS_GET_MODULE_INFO 0xE2B00044ULL
#define EREBUS_RESOLVE_PROCESS 0xE2B0004CULL

// Wire operation ids (stored in ErebusCommand.operation).
#define EREBUS_OP_READ_VA 3U
#define EREBUS_OP_WRITE_VA 4U
#define EREBUS_OP_GET_MODULE_INFO 5U
#define EREBUS_OP_RESOLVE_PROCESS 7U

// Status codes returned in RAX / ErebusCommand.payloadStatus.
#define EREBUS_STATUS_OK 0xE2B00000ULL
#define EREBUS_STATUS_UNSUPPORTED 0xE2B00001ULL
#define EREBUS_STATUS_VMREAD_FAILED 0xE2B00002ULL
#define EREBUS_STATUS_EPT_NOT_PRESENT 0xE2B00003ULL
#define EREBUS_STATUS_BAD_EPTP 0xE2B00004ULL
#define EREBUS_STATUS_BAD_REQUEST 0xE2B00031ULL
#define EREBUS_STATUS_TRANSLATION_FAILED 0xE2B00032ULL
#define EREBUS_STATUS_BAD_SIZE 0xE2B00034ULL
#define EREBUS_STATUS_MODULE_NOT_FOUND 0xE2B00035ULL
#define EREBUS_STATUS_PROCESS_NOT_FOUND 0xE2B00039ULL

// Bounded transfer limits for the command buffer.
#define EREBUS_MAX_TRANSFER 256U
#define EREBUS_MAX_MODULE_NAME_CHARS 64U

// ---------------------------------------------------------------------------
// Payload / kernel handoff
// ---------------------------------------------------------------------------

#define EREBUS_KERNEL_LAYOUT_MAGIC 0x4552454B4C415931ULL /* "EREKLAY1" */

#define PAYLOAD_VIRTUAL_BASE (0x0000327FFFE00000)

#define EREBUS_HYPERV_SCAN_FLOOR (0x4000000ULL)

// Payload exports resolved by name from the mapped payload image.
#define EREBUS_EXPORT_HANDLER "ErebusVmExitHandler"
#define EREBUS_EXPORT_ORIGINAL_HANDLER "ErebusOriginalHandler"
#define EREBUS_EXPORT_POST_HANDLER "ErebusPostVmExitHandler"
#define EREBUS_EXPORT_CALL_DISPATCHER "ErebusVmExitCallDispatcher"
#define EREBUS_EXPORT_AFTER_CALL_DELTA "ErebusAfterCallDelta"
#define EREBUS_EXPORT_KERNEL_LAYOUT "ErebusKernelLayout"

// Handler return values consumed by vmexit_dispatcher.asm.
#define EREBUS_HANDLER_PASS 0ULL
#define EREBUS_HANDLER_POST 1ULL

// ---------------------------------------------------------------------------
// Disk bounce copy
// ---------------------------------------------------------------------------

#define SCSI_SECTOR_SIZE (0x200)
#define EREBUS_SCRATCH_LBA 8

// ---------------------------------------------------------------------------
// Intel VMCS fields and exit reasons
// ---------------------------------------------------------------------------

#define VMCS_EXIT_REASON 0x00004402
#define VMCS_GUEST_CR3 0x00006802
#define VMCS_CTRL_EPT_POINTER 0x0000201A

#define VMX_EXIT_REASON_BASIC_MASK 0xFFFF
#define VMX_EXIT_REASON_EXECUTE_CPUID 0x0000000A

// ---------------------------------------------------------------------------
// Paging / EPT masks
// ---------------------------------------------------------------------------

#define EREBUS_PHYS_MASK_4KB 0x000FFFFFFFFFF000ULL
#define EREBUS_PHYS_MASK_2MB 0x000FFFFFFFE00000ULL
#define EREBUS_PHYS_MASK_1GB 0x000FFFFFC0000000ULL

#define EREBUS_PAGE_OFFSET_4KB 0xFFFULL
#define EREBUS_PAGE_OFFSET_2MB 0x1FFFFFULL
#define EREBUS_PAGE_OFFSET_1GB 0x3FFFFFFFULL

#define EREBUS_EPT_PRESENT_MASK 0x7ULL
#define EREBUS_EPT_LARGE_PAGE 0x80ULL

#define EREBUS_GUEST_PAGING_PRESENT 0x1ULL
#define EREBUS_GUEST_PAGING_LARGE_PAGE 0x80ULL

// Slot 510 of the payload page table maps one host physical page on demand.
#define EREBUS_HOST_PHYS_MAP_SLOT 510ULL
#define EREBUS_HOST_PHYS_MAP_FLAGS 0x3ULL
#define EREBUS_HOST_PHYS_MAP_VA \
    (PAYLOAD_VIRTUAL_BASE + EREBUS_HOST_PHYS_MAP_SLOT * 0x1000ULL)

// ---------------------------------------------------------------------------
// Kernel debug output
// ---------------------------------------------------------------------------

#define DbgMsg(x, ...) DbgPrintEx(0, 0, x##"\n", __VA_ARGS__)
