#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <random>
#include <vector>
#include "../../shared/erebus_api.h"

struct CpuidResult { UINT64 rax, rbx, rcx, rdx; };
typedef void (__fastcall *CpuidThunk)(UINT64, UINT64, UINT64, UINT64, CpuidResult*);

static const UINT8 kCpuidStub[] = {
    0x53, 0x48, 0x89, 0xC8, 0x48, 0x89, 0xD3, 0x4C, 0x89, 0xC1,
    0x4C, 0x89, 0xCA, 0x4C, 0x8B, 0x54, 0x24, 0x30, 0x0F, 0xA2,
    0x49, 0x89, 0x02, 0x49, 0x89, 0x5A, 0x08, 0x49, 0x89, 0x4A,
    0x10, 0x49, 0x89, 0x52, 0x18, 0x5B, 0xC3
};

static CpuidResult Run(CpuidThunk thunk, UINT64 rax, UINT64 rbx, UINT64 rcx, UINT64 rdx)
{
    CpuidResult result = {};
    thunk(rax, rbx, rcx, rdx, &result);
    return result;
}

static UINT64 ParseU64(const char* value)
{
    return _strtoui64(value, nullptr, (value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) ? 16 : 10);
}

static bool ParseBytes(const char* text, std::vector<UINT8>* bytes)
{
    const char* cursor = text;
    while (*cursor) {
        while (*cursor == ' ' || *cursor == ',' || *cursor == '\t') {
            ++cursor;
        }
        if (!*cursor) {
            break;
        }
        char* end = nullptr;
        unsigned long value = strtoul(cursor, &end, 16);
        if (end == cursor || value > 0xFF) {
            return false;
        }
        bytes->push_back(static_cast<UINT8>(value));
        cursor = end;
    }
    return !bytes->empty() && bytes->size() <= EREBUS_MAX_TRANSFER;
}

static const char* StatusName(UINT64 status)
{
    switch (status) {
    case EREBUS_STATUS_OK: return "OK";
    case EREBUS_STATUS_BAD_REQUEST: return "BAD_REQUEST";
    case EREBUS_STATUS_BAD_SIZE: return "BAD_SIZE";
    case EREBUS_STATUS_VMREAD_FAILED: return "VMREAD_FAILED";
    case EREBUS_STATUS_EPT_NOT_PRESENT: return "EPT_NOT_PRESENT";
    case EREBUS_STATUS_BAD_EPTP: return "BAD_EPTP";
    case EREBUS_STATUS_TRANSLATION_FAILED: return "TRANSLATION_FAILED";
    case EREBUS_STATUS_MODULE_NOT_FOUND: return "MODULE_NOT_FOUND";
    case EREBUS_STATUS_PROCESS_NOT_FOUND: return "PROCESS_NOT_FOUND";
    case EREBUS_STATUS_UNSUPPORTED: return "UNSUPPORTED";
    default: return "UNKNOWN";
    }
}

static void PrintJsonString(const char* value)
{
    putchar('"');
    for (const char* cursor = value; *cursor; ++cursor) {
        if (*cursor == '"' || *cursor == '\\') {
            putchar('\\');
        }
        putchar(*cursor);
    }
    putchar('"');
}

static void PrintJsonU64(const char* name, UINT64 value)
{
    printf("\"%s\":\"0x%016" PRIX64 "\"", name, value);
}

static void PrintJsonStatus(const char* command, UINT64 status)
{
    printf("{\"ok\":%s,\"command\":", status == EREBUS_STATUS_OK ? "true" : "false");
    PrintJsonString(command);
    printf(",\"status\":");
    PrintJsonString(StatusName(status));
    printf(",\"statusCode\":\"0x%016" PRIX64 "\"", status);
}

static void InitCommand(ErebusCommand* command, UINT32 operation)
{
    ZeroMemory(command, sizeof(*command));
    command->magic = EREBUS_API_MAGIC;
    command->size = sizeof(*command);
    command->operation = operation;
}

static UINT64 Execute(CpuidThunk thunk, UINT32 operation, ErebusCommand* command)
{
    UINT32 commandId = operation == EREBUS_OP_READ_VA ? EREBUS_READ_VA :
        operation == EREBUS_OP_WRITE_VA ? EREBUS_WRITE_VA :
        operation == EREBUS_OP_GET_MODULE_INFO ? EREBUS_GET_MODULE_INFO :
        EREBUS_RESOLVE_PROCESS;
    CpuidResult result = Run(
        thunk,
        EREBUS_CPUID_LEAF,
        reinterpret_cast<UINT64>(command),
        commandId,
        0);
    return result.rax;
}

static UINT64 CheckReady(CpuidThunk thunk)
{
    CpuidResult result = Run(thunk, EREBUS_CPUID_LEAF, 0, EREBUS_CPUID_READY_SUBLEAF, 0);
    return result.rax == EREBUS_CPUID_READY_VALUE ? EREBUS_STATUS_OK : result.rax;
}

static bool ResolveProcess(CpuidThunk thunk, UINT32 pid, UINT64* process, UINT64* cr3, UINT64* peb, UINT64* statusOut)
{
    ErebusCommand command = {};
    InitCommand(&command, EREBUS_OP_RESOLVE_PROCESS);
    command.sourceAddress = pid;
    UINT64 status = Execute(thunk, EREBUS_OP_RESOLVE_PROCESS, &command);
    *statusOut = status;
    *process = command.result2;
    *cr3 = command.result0;
    *peb = command.result1;
    return status == EREBUS_STATUS_OK;
}

static bool ReadVa(CpuidThunk thunk, UINT64 cr3, UINT64 address, UINT32 size, UINT8* data, UINT64* statusOut)
{
    ErebusCommand command = {};
    InitCommand(&command, EREBUS_OP_READ_VA);
    command.sourceCr3 = cr3;
    command.sourceAddress = address;
    command.bytesRequested = size;
    *statusOut = Execute(thunk, EREBUS_OP_READ_VA, &command);
    if (*statusOut == EREBUS_STATUS_OK) {
        memcpy(data, command.data, size);
    }
    return *statusOut == EREBUS_STATUS_OK;
}

static bool WriteVa(CpuidThunk thunk, UINT64 cr3, UINT64 address, const UINT8* data, UINT32 size, UINT64* statusOut)
{
    ErebusCommand command = {};
    InitCommand(&command, EREBUS_OP_WRITE_VA);
    command.destinationCr3 = cr3;
    command.destinationAddress = address;
    command.bytesRequested = size;
    memcpy(command.data, data, size);
    *statusOut = Execute(thunk, EREBUS_OP_WRITE_VA, &command);
    return *statusOut == EREBUS_STATUS_OK;
}

static bool FindModule(CpuidThunk thunk, UINT64 cr3, UINT64 peb, const char* name, UINT64* base, UINT64* size, UINT64* statusOut)
{
    ErebusCommand command = {};
    InitCommand(&command, EREBUS_OP_GET_MODULE_INFO);
    command.sourceCr3 = cr3;
    command.sourceAddress = peb;
    size_t length = strlen(name);
    if (length == 0 || length >= EREBUS_MAX_MODULE_NAME_CHARS) {
        *statusOut = EREBUS_STATUS_BAD_REQUEST;
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        command.moduleName[i] = static_cast<UINT8>(name[i]);
    }
    *statusOut = Execute(thunk, EREBUS_OP_GET_MODULE_INFO, &command);
    *base = command.result0;
    *size = command.result1;
    return *statusOut == EREBUS_STATUS_OK;
}

static void PrintBytes(const UINT8* data, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        printf("%02X%s", data[i], i + 1 == size ? "" : " ");
    }
}

static bool DoReady(CpuidThunk thunk)
{
    UINT64 status = CheckReady(thunk);
    PrintJsonStatus("ready", status);
    printf("}\n");
    return status == EREBUS_STATUS_OK;
}

static bool DoResolveProcess(CpuidThunk thunk, UINT32 pid)
{
    UINT64 process = 0, cr3 = 0, peb = 0;
    UINT64 status = 0;
    bool ok = ResolveProcess(thunk, pid, &process, &cr3, &peb, &status);
    PrintJsonStatus("resolve-process", status);
    printf(",\"pid\":%u,", pid);
    PrintJsonU64("eprocess", process); putchar(',');
    PrintJsonU64("cr3", cr3); putchar(',');
    PrintJsonU64("peb", peb); printf("}\n");
    return ok;
}

static bool DoModule(CpuidThunk thunk, UINT32 pid, const char* name)
{
    UINT64 process = 0, cr3 = 0, peb = 0, base = 0, size = 0, status = 0;
    bool ok = ResolveProcess(thunk, pid, &process, &cr3, &peb, &status) &&
        FindModule(thunk, cr3, peb, name, &base, &size, &status);
    if (ok) status = EREBUS_STATUS_OK;
    PrintJsonStatus("module", status);
    printf(",\"pid\":%u,\"name\":", pid); PrintJsonString(name); putchar(',');
    PrintJsonU64("base", base); putchar(',');
    PrintJsonU64("size", size); printf("}\n");
    return ok;
}

static bool DoRead(CpuidThunk thunk, UINT32 pid, UINT64 address, UINT32 size)
{
    UINT64 process = 0, cr3 = 0, peb = 0, status = 0;
    UINT8 data[EREBUS_MAX_TRANSFER] = {};
    bool ok = ResolveProcess(thunk, pid, &process, &cr3, &peb, &status) &&
        ReadVa(thunk, cr3, address, size, data, &status);
    PrintJsonStatus("read-va", ok ? EREBUS_STATUS_OK : status);
    printf(",\"pid\":%u,", pid); PrintJsonU64("address", address);
    printf(",\"size\":%u,\"data\":\"", size); PrintBytes(data, ok ? size : 0); printf("\"}\n");
    return ok;
}

static bool DoWrite(CpuidThunk thunk, UINT32 pid, UINT64 address, const std::vector<UINT8>& data)
{
    UINT64 process = 0, cr3 = 0, peb = 0, status = 0;
    bool ok = ResolveProcess(thunk, pid, &process, &cr3, &peb, &status) &&
        WriteVa(thunk, cr3, address, data.data(), static_cast<UINT32>(data.size()), &status);
    PrintJsonStatus("write-va", ok ? EREBUS_STATUS_OK : status);
    printf(",\"pid\":%u,", pid); PrintJsonU64("address", address);
    printf(",\"size\":%zu,\"data\":\"", data.size()); PrintBytes(data.data(), data.size()); printf("\"}\n");
    return ok;
}

static bool DoDemo(CpuidThunk thunk)
{
    UINT32 pid = GetCurrentProcessId();
    volatile UINT64 value = 0;
    std::random_device device;
    UINT64 before = (static_cast<UINT64>(device()) << 32) ^ device();
    UINT64 after = (static_cast<UINT64>(device()) << 32) ^ device();
    value = before;

    printf("Erebus demo\n===========\n");
    UINT64 ready = CheckReady(thunk);
    printf("[%s] Payload ready\n", ready == EREBUS_STATUS_OK ? "PASS" : "FAIL");
    if (ready != EREBUS_STATUS_OK) return false;

    UINT64 process = 0, cr3 = 0, peb = 0, status = 0;
    if (!ResolveProcess(thunk, pid, &process, &cr3, &peb, &status)) return false;
    printf("[PASS] Resolve current process (PID %u)\n      CR3: 0x%016" PRIX64 "\n      PEB: 0x%016" PRIX64 "\n", pid, cr3, peb);

    UINT64 base = 0, moduleSize = 0;
    if (!FindModule(thunk, cr3, peb, "kernel32.dll", &base, &moduleSize, &status)) return false;
    printf("[PASS] Find module kernel32.dll\n      Base: 0x%016" PRIX64 "\n      Size: 0x%016" PRIX64 "\n", base, moduleSize);

    UINT8 bytes[sizeof(value)] = {};
    if (!ReadVa(thunk, cr3, reinterpret_cast<UINT64>(&value), sizeof(value), bytes, &status) ||
        *reinterpret_cast<UINT64*>(bytes) != before) return false;
    printf("[PASS] Read random value\n      Value: 0x%016" PRIX64 "\n", before);

    UINT8 newBytes[sizeof(after)] = {};
    memcpy(newBytes, &after, sizeof(after));
    if (!WriteVa(thunk, cr3, reinterpret_cast<UINT64>(&value), newBytes, sizeof(newBytes), &status)) return false;
    printf("[PASS] Write random value\n      Value: 0x%016" PRIX64 "\n", after);

    ZeroMemory(bytes, sizeof(bytes));
    if (!ReadVa(thunk, cr3, reinterpret_cast<UINT64>(&value), sizeof(value), bytes, &status) ||
        *reinterpret_cast<UINT64*>(bytes) != after) return false;
    printf("[PASS] Verify written value\n      Value: 0x%016" PRIX64 "\n\nDemo completed successfully.\n", after);
    return true;
}

static void Usage()
{
    printf("Usage:\n"
        "  ErebusClient.exe demo\n"
        "  ErebusClient.exe ready\n"
        "  ErebusClient.exe resolve-process --pid <pid>\n"
        "  ErebusClient.exe module --pid <pid> --name <module>\n"
        "  ErebusClient.exe read-va --pid <pid> --address <va> --size <bytes>\n"
        "  ErebusClient.exe write-va --pid <pid> --address <va> --data \"AA BB CC\"\n");
}

static const char* Option(int argc, char** argv, const char* name)
{
    for (int i = 2; i + 1 < argc; ++i) {
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    }
    return nullptr;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        Usage();
        return 2;
    }
    void* code = VirtualAlloc(nullptr, sizeof(kCpuidStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!code) {
        fprintf(stderr, "ErebusClient: VirtualAlloc failed\n");
        return 1;
    }
    memcpy(code, kCpuidStub, sizeof(kCpuidStub));
    CpuidThunk thunk = reinterpret_cast<CpuidThunk>(code);
    const char* command = argv[1];
    bool ok = false;

    if (strcmp(command, "demo") == 0) {
        ok = DoDemo(thunk);
    } else if (strcmp(command, "ready") == 0) {
        ok = DoReady(thunk);
    } else if (strcmp(command, "resolve-process") == 0) {
        const char* pid = Option(argc, argv, "--pid");
        if (!pid) { Usage(); ok = false; }
        else ok = DoResolveProcess(thunk, static_cast<UINT32>(ParseU64(pid)));
    } else if (strcmp(command, "module") == 0) {
        const char* pid = Option(argc, argv, "--pid");
        const char* name = Option(argc, argv, "--name");
        if (!pid || !name) { Usage(); ok = false; }
        else ok = DoModule(thunk, static_cast<UINT32>(ParseU64(pid)), name);
    } else if (strcmp(command, "read-va") == 0) {
        const char* pid = Option(argc, argv, "--pid");
        const char* address = Option(argc, argv, "--address");
        const char* size = Option(argc, argv, "--size");
        if (!pid || !address || !size || ParseU64(size) == 0 || ParseU64(size) > EREBUS_MAX_TRANSFER) {
            Usage(); ok = false;
        } else {
            ok = DoRead(thunk, static_cast<UINT32>(ParseU64(pid)), ParseU64(address), static_cast<UINT32>(ParseU64(size)));
        }
    } else if (strcmp(command, "write-va") == 0) {
        const char* pid = Option(argc, argv, "--pid");
        const char* address = Option(argc, argv, "--address");
        const char* data = Option(argc, argv, "--data");
        std::vector<UINT8> bytes;
        if (!pid || !address || !data || !ParseBytes(data, &bytes)) {
            Usage(); ok = false;
        } else {
            ok = DoWrite(thunk, static_cast<UINT32>(ParseU64(pid)), ParseU64(address), bytes);
        }
    } else {
        Usage();
    }

    VirtualFree(code, 0, MEM_RELEASE);
    return ok ? 0 : 1;
}
