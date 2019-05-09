/*
 * This file is part of QBDI.
 *
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
.intel_syntax noprefix

.text

.globl __qbdinjected_enter
.globl __qbdinjected_change_stack
.globl __qbdinjected_exit
    
__qbdinjected_enter:
    push rbp;
    mov rbp, rsp;
    sub rsp, 1024;
    and rsp, -1024;
    // create FPRstate
    fxsave [rsp];
    vextractf128 [rsp+512], ymm0, 1;
    vextractf128 [rsp+528], ymm1, 1;
    vextractf128 [rsp+544], ymm2, 1;
    vextractf128 [rsp+560], ymm3, 1;
    vextractf128 [rsp+576], ymm4, 1;
    vextractf128 [rsp+592], ymm5, 1;
    vextractf128 [rsp+608], ymm6, 1;
    vextractf128 [rsp+624], ymm7, 1;
    vextractf128 [rsp+640], ymm8, 1;
    vextractf128 [rsp+656], ymm9, 1;
    vextractf128 [rsp+672], ymm10, 1;
    vextractf128 [rsp+688], ymm11, 1;
    vextractf128 [rsp+704], ymm12, 1;
    vextractf128 [rsp+720], ymm13, 1;
    vextractf128 [rsp+736], ymm14, 1;
    vextractf128 [rsp+752], ymm15, 1;
    // create GPRstate
    pushfq;
    push 0x0; // rip will be set with firda gum context
    push 0x0; // rsp will be set later
    push 0x0; // rbp will be set later
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

    // set origin rbp
    mov rax, [rbp];
    mov [rsp+112], rax;

    // set origin rsp
    mov rax, rbp;
    add rax, 8;
    mov [rsp+120], rax;

    // rdi = GRPState*
    // rsi = FPRstate*
    mov rdi, rsp;
    lea rsi, [rsp+144];
    call __qbdinjected_allocate;

__qbdinjected_change_stack:
    // rdi = GRPState* gpr
    // rsi = FPRstate* fpr
    // rdx = void* new_stack
    // rcx = void* next_call
    
    mov rsp, rdx;
    jmp rcx;


__qbdinjected_exit:
    // rdi = GRPState* gpr
    // rsi = FPRstate* fpr

    mov rsp, [rdi+120];

    // copy some register on the stack
    push [rdi+128]; // gpr->rip
    push [rdi+136]; // gpr->eflags

    fxrstor [rsi];
    vinsertf128 ymm0, ymm0, [rsi+512], 1;
    vinsertf128 ymm1, ymm1, [rsi+528], 1;
    vinsertf128 ymm2, ymm2, [rsi+544], 1;
    vinsertf128 ymm3, ymm3, [rsi+560], 1;
    vinsertf128 ymm4, ymm4, [rsi+576], 1;
    vinsertf128 ymm5, ymm5, [rsi+592], 1;
    vinsertf128 ymm6, ymm6, [rsi+608], 1;
    vinsertf128 ymm7, ymm7, [rsi+624], 1;
    vinsertf128 ymm8, ymm8, [rsi+640], 1;
    vinsertf128 ymm9, ymm9, [rsi+656], 1;
    vinsertf128 ymm10, ymm10, [rsi+672], 1;
    vinsertf128 ymm11, ymm11, [rsi+688], 1;
    vinsertf128 ymm12, ymm12, [rsi+704], 1;
    vinsertf128 ymm13, ymm13, [rsi+720], 1;
    vinsertf128 ymm14, ymm14, [rsi+736], 1;
    vinsertf128 ymm15, ymm15, [rsi+752], 1;


    mov rax, [rdi];
    mov rbx, [rdi+8];
    mov rcx, [rdi+16];
    mov rdx, [rdi+24];
    mov rsi, [rdi+32];
    // rdi will be done at the end
    mov r8, [rdi+48];
    mov r9, [rdi+56];
    mov r10, [rdi+64];
    mov r11, [rdi+72];
    mov r12, [rdi+80];
    mov r13, [rdi+88];
    mov r14, [rdi+96];
    mov r15, [rdi+104];
    mov rbp, [rdi+112];
    // rsp is already updated
    // rip is on the stack
    // eflags is on the stack

    mov rdi, [rdi+40];

    popfq;
    ret;
