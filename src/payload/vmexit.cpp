#include "erebus_abi.h"

static void SetCpuidOutputs(ErebusCpuidContext* context, UINT64 rax, UINT64 rbx, UINT64 rcx, UINT64 rdx)
{
    context->Rax = rax;
    context->Rbx = rbx;
    context->Rcx = rcx;
    context->Rdx = rdx;
}

static bool IsErebusCommand(UINT64 subleaf)
{
    switch (static_cast<UINT32>(subleaf)) {
    case EREBUS_CPUID_READY_SUBLEAF:
    case EREBUS_READ_VA:
    case EREBUS_WRITE_VA:
    case EREBUS_GET_MODULE_INFO:
    case EREBUS_RESOLVE_PROCESS:
        return true;
    default:
        return false;
    }
}

static UINT32 OperationFromCpuidCommand(UINT32 command)
{
    switch (command) {
    case EREBUS_READ_VA:
        return EREBUS_OP_READ_VA;
    case EREBUS_WRITE_VA:
        return EREBUS_OP_WRITE_VA;
    case EREBUS_GET_MODULE_INFO:
        return EREBUS_OP_GET_MODULE_INFO;
    case EREBUS_RESOLVE_PROCESS:
        return EREBUS_OP_RESOLVE_PROCESS;
    default:
        return 0;
    }
}

static UINT64 ExecuteCommand(UINT32 operation, UINT64 commandVirtual, UINT64* result0Out, UINT64* result1Out, UINT64* result2Out)
{
    *result0Out = 0;
    *result1Out = 0;
    *result2Out = 0;

    UINT64 eptp = 0;
    UINT64 currentCr3 = 0;
    if (!VmRead(VMCS_CTRL_EPT_POINTER, &eptp) ||
        !VmRead(VMCS_GUEST_CR3, &currentCr3)) {
        return EREBUS_STATUS_VMREAD_FAILED;
    }

    if (commandVirtual == 0) {
        return EREBUS_STATUS_BAD_REQUEST;
    }

    ErebusCommand command = {};
    UINT64 status = ReadGuestVirtualBytes(eptp, currentCr3, commandVirtual, &command, sizeof(command));
    if (status != EREBUS_STATUS_OK) {
        return status;
    }
    if (!CommandHeaderValid(&command) || command.Operation != operation) {
        return EREBUS_STATUS_BAD_REQUEST;
    }

    UINT64 transferSize = command.BytesRequested;
    command.PayloadStatus = EREBUS_STATUS_OK;
    command.BytesTransferred = 0;
    command.Result0 = 0;
    command.Result1 = 0;
    command.Result2 = 0;

    switch (operation) {
    case EREBUS_OP_READ_VA:
    {
        UINT64 sourceCr3 = command.SourceCr3 ? command.SourceCr3 : currentCr3;
        if (transferSize == 0 || transferSize > EREBUS_MAX_TRANSFER) {
            status = EREBUS_STATUS_BAD_SIZE;
            break;
        }
        status = ReadGuestVirtualBytes(eptp, sourceCr3, command.SourceAddress, command.Data, transferSize);
        if (status == EREBUS_STATUS_OK) {
            command.BytesTransferred = transferSize;
            command.Result0 = sourceCr3;
            command.Result1 = command.SourceAddress;
        }
        break;
    }
    case EREBUS_OP_WRITE_VA:
    {
        UINT64 destinationCr3 = command.DestinationCr3 ? command.DestinationCr3 : currentCr3;
        if (transferSize == 0 || transferSize > EREBUS_MAX_TRANSFER) {
            status = EREBUS_STATUS_BAD_SIZE;
            break;
        }
        status = WriteGuestVirtualBytes(eptp, destinationCr3, command.DestinationAddress, command.Data, transferSize);
        if (status == EREBUS_STATUS_OK) {
            command.BytesTransferred = transferSize;
            command.Result0 = destinationCr3;
            command.Result1 = command.DestinationAddress;
        }
        break;
    }
    case EREBUS_OP_GET_MODULE_INFO:
    {
        UINT64 sourceCr3 = command.SourceCr3 ? command.SourceCr3 : currentCr3;
        UINT64 moduleBase = 0;
        UINT64 moduleSize = 0;
        status = FindModuleInPeb(
            eptp,
            sourceCr3,
            command.SourceAddress,
            command.ModuleName,
            &moduleBase,
            &moduleSize);
        if (status == EREBUS_STATUS_OK) {
            command.Result0 = moduleBase;
            command.Result1 = moduleSize;
            command.Result2 = command.SourceAddress;
        }
        break;
    }
    case EREBUS_OP_RESOLVE_PROCESS:
    {
        UINT64 process = 0;
        UINT64 directoryBase = 0;
        UINT64 peb = 0;
        status = ResolveProcessByPid(
            eptp,
            command.SourceAddress,
            command.SourceCr3,
            &process,
            &directoryBase,
            &peb);
        if (status == EREBUS_STATUS_OK) {
            command.Result0 = directoryBase;
            command.Result1 = peb;
            command.Result2 = process;
        }
        break;
    }
    default:
        status = EREBUS_STATUS_UNSUPPORTED;
        break;
    }

    command.PayloadStatus = status;
    UINT64 storeStatus = WriteGuestVirtualBytes(eptp, currentCr3, commandVirtual, &command, sizeof(command));
    if (storeStatus != EREBUS_STATUS_OK && status == EREBUS_STATUS_OK) {
        status = storeStatus;
    }

    *result0Out = command.Result0;
    *result1Out = command.Result1;
    *result2Out = command.BytesTransferred;
    return status;
}

extern "C" __declspec(dllexport) UINT64 __fastcall ErebusVmExitHandler(void* arg1, void* arg2, void* arg3, void* arg4)
{
    (void)arg2;
    (void)arg3;
    (void)arg4;

    UINT64 exitReason = 0;
    if (VmRead(VMCS_EXIT_REASON, &exitReason)) {
        UINT32 basicExitReason = static_cast<UINT32>(exitReason & VMX_EXIT_REASON_BASIC_MASK);

        if (basicExitReason == VMX_EXIT_REASON_EXECUTE_CPUID && arg1) {
            ErebusCpuidContext* context = *reinterpret_cast<ErebusCpuidContext**>(arg1);
            if (context &&
                static_cast<UINT32>(context->Rax) == EREBUS_CPUID_LEAF &&
                IsErebusCommand(context->Rcx)) {
                return EREBUS_HANDLER_POST;
            }
        }
    }

    return EREBUS_HANDLER_PASS;
}

extern "C" __declspec(dllexport) void __fastcall ErebusPostVmExitHandler(ErebusCpuidPostSnapshot* pending)
{
    if (!pending || !pending->Context) {
        return;
    }

    ErebusCpuidContext* context = pending->Context;
    UINT32 pendingCommand = static_cast<UINT32>(pending->Rcx);

    switch (pendingCommand) {
    case EREBUS_CPUID_READY_SUBLEAF:
        SetCpuidOutputs(context, EREBUS_CPUID_READY_VALUE, 0, 0, 0);
        break;

    case EREBUS_READ_VA:
    case EREBUS_WRITE_VA:
    case EREBUS_GET_MODULE_INFO:
    case EREBUS_RESOLVE_PROCESS:
    {
        UINT32 operation = OperationFromCpuidCommand(pendingCommand);
        if (operation == 0) {
            SetCpuidOutputs(context, EREBUS_STATUS_UNSUPPORTED, pendingCommand, 0, 0);
            break;
        }

        UINT64 result0 = 0;
        UINT64 result1 = 0;
        UINT64 result2 = 0;
        UINT64 status = ExecuteCommand(
            operation,
            pending->Rbx,
            &result0,
            &result1,
            &result2);
        SetCpuidOutputs(context, status, result0, result1, result2);
        break;
    }
    default:
        SetCpuidOutputs(context, EREBUS_STATUS_UNSUPPORTED, pending->Rcx, 0, 0);
        break;
    }
}
