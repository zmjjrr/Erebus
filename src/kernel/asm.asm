.code
LoaderASM PROC
    ; Save registers
    push rax
    push rbx
    ; Load base of self ref PML4
    mov rbx, 0FFFFFF7FBFDFE000h

    ; Load physical address to map
    mov rax, 0CAFEBABEDEADBEEFh  ; (to be patched)

    ; Set flags: Present=1, Write=1, Supervisor=0
    or rax, 3

    ; Write into PML4[100]
    mov [rbx + 100d * 8], rax

    ; Flush cache
    mov rbx, cr3
    mov cr3, rbx
    mov rbx, 0000327FFFE00000h   ; load the base of the image we just mapped
    mov rax, [rbx]         ; attempt to read from base as a confirmation the tables worked

    ; Write the real Hyper-V runtime target, not the driver bounce-buffer VA.
    call get_rip
get_rip:
    pop rax
    and rax, 0FFFFFFFFFFFFF000h
    add rax, 0BABECAFEh

    add rbx, 0DEADBEEFh
    mov [rbx], rax

    ; Restore registers
    pop rbx
    pop rax
LoaderASM ENDP

LoaderASMEnd PROC
    ret
LoaderASMEnd ENDP

ExecuteCPUID PROC
    cpuid
    ret
ExecuteCPUID ENDP

END
