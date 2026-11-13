.code

EXTERN ErebusVmExitHandler:PROC
EXTERN ErebusPostVmExitHandler:PROC
EXTERN ErebusOriginalHandler:QWORD
EXTERN ErebusAfterCallDelta:QWORD

PUBLIC ErebusVmExitCallDispatcher

; The kernel redirects the Hyper-V VM-exit call site into this dispatcher.
; ErebusVmExitHandler returns EREBUS_HANDLER_PASS (0) or EREBUS_HANDLER_POST
; (1); the post path runs the original handler first, then applies the CPUID
; command through ErebusPostVmExitHandler.
ErebusVmExitCallDispatcher PROC
    pushfq
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    sub rsp, 28h
    call ErebusVmExitHandler
    add rsp, 28h

    test rax, rax
    jne CallOriginalThenPost

CallPassOriginal:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    popfq

    jmp qword ptr [ErebusOriginalHandler]

CallOriginalThenPost:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    popfq

    ; Reserve room for the fake return address plus the CPUID context snapshot.
    sub rsp, 80
    mov qword ptr [rsp + 8], r10
    mov qword ptr [rsp + 16], r11
    xor r10, r10
    mov qword ptr [rsp + 40], r10
    mov qword ptr [rsp + 48], r10
    mov qword ptr [rsp + 56], r10
    mov qword ptr [rsp + 64], r10
    test rcx, rcx
    je CallDispatcherSnapshotReady
    mov r10, qword ptr [rcx]
    mov qword ptr [rsp + 40], r10
    test r10, r10
    je CallDispatcherSnapshotReady
    mov r11, qword ptr [r10]
    mov qword ptr [rsp + 48], r11
    mov r11, qword ptr [r10 + 18h]
    mov qword ptr [rsp + 56], r11
    mov r11, qword ptr [r10 + 8]
    mov qword ptr [rsp + 64], r11

CallDispatcherSnapshotReady:
    lea r11, PostOriginalContinuation
    mov qword ptr [rsp], r11
    mov r10, qword ptr [rsp + 8]
    mov r11, qword ptr [rsp + 16]
    jmp qword ptr [ErebusOriginalHandler]

PostOriginalContinuation:
    lea rcx, [rsp + 32]
    push rax
    sub rsp, 28h
    call ErebusPostVmExitHandler
    add rsp, 28h
    pop rax
    add rsp, 80
    mov r11, qword ptr [ErebusOriginalHandler]
    add r11, qword ptr [ErebusAfterCallDelta]
    jmp r11

ErebusVmExitCallDispatcher ENDP

END
