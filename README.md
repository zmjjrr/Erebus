# Erebus

Erebus is a small [VMI](https://en.wikipedia.org/wiki/Virtual_machine_introspection)
research toolkit for Windows x64. Rather than build a full [hypervisor](https://en.wikipedia.org/wiki/Hypervisor)
or hook [Hyper-V](https://en.wikipedia.org/wiki/Hyper-V) at boot time, it
redirects Hyper-V's own VM-exit handler at runtime to a small resident payload,
which a user-mode client drives over CPUID.

## Architecture

Erebus has three components:

| Component | Role |
| --- | --- |
| `src/kernel/` | One-shot bootstrap driver: finds Hyper-V's VM-exit handler, relocates the payload into hidden pages and redirects the call site. |
| `src/payload/` | Position-independent resident image: VM-exit call dispatcher plus the EPT/PEB VMI primitives. |
| `tools/erebus_client/` | User-mode CPUID client for the payload control plane. |

### Bootstrap flow

```text
prepare_erebus_disk.ps1  ->  attached vhdmp-backed VHD (SCSI scratch sector)
        |
        v
loader (kdmapper / SCM / WinDbg)  ->  DriverEntry
  1. IsHyperVRunning()               CPUID 0x40000000 vendor leaf
  2. DiskFind()                      locate the vhdmp-backed SCSI disk
  3. FindVMExitHandler()             signature-scan physical memory for the
                                     hvix64 VM-exit call site
  4. FindContinuousEmptyPagesInRange()  find all-ones pages; Hyper-V hides its
                                     code pages from CPU loads, so candidate
                                     pages are read through the disk DMA bounce
  5. PreparePayload()                relocate the PE image, build the .1/.2/.3
                                     page tables, write the kernel-layout blob
                                     and the original-call delta
  6. DiskCopyPages()                 DMA the payload pages into place
  7. HijackVMExitHandler()           loader stub maps the payload PDPT into
                                     PML4[100] and captures the original handler
                                     target; then the final 53-byte cave is
                                     written, the call site is redirected and the
                                     patched instruction is read back and checked

The VHD is only needed during bootstrap. Once the call site is redirected the
resident payload no longer performs disk I/O, so the VHD can be detached.
```

### Runtime flow

```text
ErebusClient.exe
   |  CPUID leaf 0xDEADBEEF
   |  RCX = command selector, RBX = VA of ErebusCommand
   v
hvix64 VM-exit call site (patched: E9 rel32 -> final cave)
   |
   v
final cave: maps the payload PDPT into PML4[100], calls the payload
   |
   v
ErebusVmExitCallDispatcher
   |
   +-- ErebusVmExitHandler        filters leaf/subleaf
   |      |
   |      +-- not ours: jump to the original handler
   |      |
   |      `-- ours: call the original handler first, then
   |                ErebusPostVmExitHandler
   |                   |
   |                   v
   |                read/write guest VA, resolve modules/processes through
   |                EPT and the guest PEB, write results back into the command
   |
   `-- jump back to the instruction after the original call
```

The client command struct stays in the caller's address space; the payload
translates that VA to a GPA/HPA and reads or writes it in place. Non-Erebus
CPUID leaves pass straight through to the original Hyper-V handler.

## Source Map

| Path | Responsibility |
| --- | --- |
| `src/kernel/` | Temporary bootstrap driver, payload installation, and kernel-layout handoff |
| `src/payload/` | Resident Intel VM-exit payload and call dispatcher |
| `shared/erebus_defines.h` | Shared ABI constants |
| `shared/erebus_api.h` | Shared wire structures |
| `tools/erebus_client/` | User-mode diagnostic client for the payload control plane |
| `scripts/prepare_erebus_disk.ps1` | Lab helper that creates/attaches the vhdmp bounce disk |
| `build.ps1` | Windows build entry point |

`build.ps1` generates `src/kernel/payloadbytes.h`; it is a git-ignored build
artifact.
`out/`, the MSBuild `x64/` directories, and Visual Studio state are ignored as
well.

## Build

Prerequisites:

- Windows x64
- Visual Studio 2022 with MSBuild
- Windows Driver Kit
- PowerShell 5+

Build from a Visual Studio Developer PowerShell or an environment where MSBuild
and WDK targets are installed:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

The default build emits:

- `out\Erebus.sys`
- `out\Erebus.pdb`
- `out\ErebusClient.exe`

## Preconditions

1. Intel CPU
2. Hyper-V hypervisor running
3. Intel VT-d / IOMMU disabled
4. Windows 11 25H2

## Usage

1. Attach the scratch VHD. The driver requires an attached vhdmp-backed SCSI
   disk for its bounce-copy path. Run this from an elevated PowerShell:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\prepare_erebus_disk.ps1 -Action Prepare
   ```

2. Load `Erebus.sys`

3. Detach and remove the VHD once the loader has returned:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\prepare_erebus_disk.ps1 -Action Cleanup
   ```

4. Drive the payload from the client.

   ```powershell
   .\out\ErebusClient.exe demo
   .\out\ErebusClient.exe ready
   .\out\ErebusClient.exe resolve-process --pid $PID
   .\out\ErebusClient.exe module --pid $PID --name kernel32.dll
   .\out\ErebusClient.exe read-va --pid $PID --address 0x1234 --size 8
   .\out\ErebusClient.exe write-va --pid $PID --address 0x1234 --data "AA BB CC"
   ```

## Credits

- [Diskjacker](https://github.com/LabGuy94/Diskjacker) by LabGuy94: runtime
  Hyper-V hijacking with DDMA. The VM-exit hijack/bootstrap approach used here
  derives from it.
- [DDMA](https://github.com/cutecatsandvirtualmachines/DDMA) by
  cutecatsandvirtualmachines: SCSI DMA support used by the bounce-copy path.
- [btbd/ddma](https://github.com/btbd/ddma) by BTBD: the original DDMA
  implementation.
- [hyper-reV](https://github.com/noahware/hyper-reV) by noahware: memory
  introspection and reverse-engineering hypervisor built on Hyper-V.

## License

MIT
