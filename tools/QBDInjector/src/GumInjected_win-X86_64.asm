; 
; This file is part of QBDI.
; 
; Copyright 2017 Quarkslab
; 
; Licensed under the Apache License, Version 2.0 (the "License");
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
; 
;     http://www.apache.org/licenses/LICENSE-2.0
; 
; Unless required by applicable law or agreed to in writing, software
; distributed under the License is distributed on an "AS IS" BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the specific language governing permissions and
; limitations under the License.
; 

PUBLIC __qbdinjected_enter
PUBLIC __qbdinjected_change_stack
PUBLIC __qbdinjected_exit

__qbdinjected_allocate PROTO

.CODE
    
__qbdinjected_enter PROC
    push rbp;
    mov rbp, rsp;
    sub rsp, 1024;
    and rsp, -1024;
    ; create FPRstate
    fxsave [rsp];
    vextractf128 xmmword ptr [rsp+512], ymm0, 1;
    vextractf128 xmmword ptr [rsp+528], ymm1, 1;
    vextractf128 xmmword ptr [rsp+544], ymm2, 1;
    vextractf128 xmmword ptr [rsp+560], ymm3, 1;
    vextractf128 xmmword ptr [rsp+576], ymm4, 1;
    vextractf128 xmmword ptr [rsp+592], ymm5, 1;
    vextractf128 xmmword ptr [rsp+608], ymm6, 1;
    vextractf128 xmmword ptr [rsp+624], ymm7, 1;
    vextractf128 xmmword ptr [rsp+640], ymm8, 1;
    vextractf128 xmmword ptr [rsp+656], ymm9, 1;
    vextractf128 xmmword ptr [rsp+672], ymm10, 1;
    vextractf128 xmmword ptr [rsp+688], ymm11, 1;
    vextractf128 xmmword ptr [rsp+704], ymm12, 1;
    vextractf128 xmmword ptr [rsp+720], ymm13, 1;
    vextractf128 xmmword ptr [rsp+736], ymm14, 1;
    vextractf128 xmmword ptr [rsp+752], ymm15, 1;
    ; create GPRstate
    pushfq;
    ; rip will be set with frida gum context
    push 0;
    ; rsp will be set later
    push 0;
    ; rbp will be set later
    push 0;
    push r15;
    push r14;
    push r13;
    push r12;
    push r11;
    push r10;
    push r9;
    push r8;
    push rdi;
    push rsi;
    push rdx;
    push rcx;
    push rbx;
    push rax;

    ; set origin rbp
    mov rax, [rbp];
    mov [rsp+112], rax;

    ; set origin rsp
    mov rax, rbp;
    add rax, 8;
    mov [rsp+120], rax;

    ; rcx = GRPState*
    ; rdx = FPRstate*
    mov rcx, rsp;
    lea rdx, [rsp+144];
    push rdx;
    push rcx;
    call __qbdinjected_allocate;
__qbdinjected_enter ENDP

__qbdinjected_change_stack PROC
    ; rcx = GRPState* gpr
    ; rdx = FPRstate* fpr
    ; r8 = void* new_stack
    ; r9 = void* next_call
    
    mov rsp, r8;
    push rdx;
    push rcx;
    jmp r9;
__qbdinjected_change_stack ENDP


__qbdinjected_exit PROC
    ; rcx = GRPState* gpr
    ; rdx = FPRstate* fpr

    mov rsp, [rcx+120];

    ; copy some register on the stack
    push [rcx+128]; // gpr->rip
    push [rcx+136]; // gpr->eflags

    fxrstor [rdx];
    vinsertf128 ymm0, ymm0, xmmword ptr [rdx+512], 1;
    vinsertf128 ymm1, ymm1, xmmword ptr [rdx+528], 1;
    vinsertf128 ymm2, ymm2, xmmword ptr [rdx+544], 1;
    vinsertf128 ymm3, ymm3, xmmword ptr [rdx+560], 1;
    vinsertf128 ymm4, ymm4, xmmword ptr [rdx+576], 1;
    vinsertf128 ymm5, ymm5, xmmword ptr [rdx+592], 1;
    vinsertf128 ymm6, ymm6, xmmword ptr [rdx+608], 1;
    vinsertf128 ymm7, ymm7, xmmword ptr [rdx+624], 1;
    vinsertf128 ymm8, ymm8, xmmword ptr [rdx+640], 1;
    vinsertf128 ymm9, ymm9, xmmword ptr [rdx+656], 1;
    vinsertf128 ymm10, ymm10, xmmword ptr [rdx+672], 1;
    vinsertf128 ymm11, ymm11, xmmword ptr [rdx+688], 1;
    vinsertf128 ymm12, ymm12, xmmword ptr [rdx+704], 1;
    vinsertf128 ymm13, ymm13, xmmword ptr [rdx+720], 1;
    vinsertf128 ymm14, ymm14, xmmword ptr [rdx+736], 1;
    vinsertf128 ymm15, ymm15, xmmword ptr [rdx+752], 1;


    mov rax, [rcx];
    mov rbx, [rcx+8];
    ; rcx will be done at the end
    mov rdx, [rcx+24];
    mov rsi, [rcx+32];
    mov rdi, [rcx+40];
    mov r8,  [rcx+48];
    mov r9,  [rcx+56];
    mov r10, [rcx+64];
    mov r11, [rcx+72];
    mov r12, [rcx+80];
    mov r13, [rcx+88];
    mov r14, [rcx+96];
    mov r15, [rcx+104];
    mov rbp, [rcx+112];
    ; rsp is already updated
    ; rip is on the stack
    ; eflags is on the stack

    mov rcx, [rcx+16];

    popfq;
    ret;
__qbdinjected_exit ENDP


END