
#include <string.h>
#include <windows.h>
#include <TlHelp32.h>
#include <winbase.h>

#include "Injected.h"

static struct _win_Injected_ctx {
    void* thread_ctx_buff;
    CONTEXT *thread_ctx;
} ctx;

void __main_windows_entrypoint();

int get_maintid(int pid) {
    bool valid = true;
    THREADENTRY32 th32;
    th32.dwSize = sizeof(THREADENTRY32);

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return -1;
    }
    for(valid = Thread32First(hThreadSnap, &th32); valid; valid = Thread32Next(hThreadSnap, &th32)) {
        if (th32.th32OwnerProcessID == pid) {
            CloseHandle(hThreadSnap);
            return th32.th32ThreadID;
        }
    }
    CloseHandle(hThreadSnap);
    return -1;
}

void prepare_inject(int res) {
    LOG1("[+] create virtual stack ...\n");
    void* page = VirtualAlloc(NULL, STACK_SIZE, MEM_COMMIT, PAGE_READWRITE);
    if (page == NULL) {
        perror("[-] VirtualAlloc failled ...");
        goto fail1;
    }

#if defined(QBDI_ARCH_X86)
    rword stack = ((rword) page) + STACK_SIZE - 4;
#else
    rword stack = ((rword) page) + STACK_SIZE - 8;
#endif

    LOG1("[+] get main thread id ...\n");
    int maintid = get_maintid(GetCurrentProcessId());

    if (maintid < 0) {
        fprintf(stderr, "[-] Fail to find main tid\n");
        goto fail1;
    }

    LOG1("[+] main thread id : %d\n", maintid);
    HANDLE MainThread = OpenThread(THREAD_ALL_ACCESS, TRUE, maintid);
    if (MainThread == NULL) {
        fprintf(stderr, "[-] Fail to OpenThread on tid %d (error: %d)\n", maintid, GetLastError());
        goto fail1;
    }

    int contextSize = 0;

    // https://docs.microsoft.com/en-us/windows/desktop/Debug/working-with-xstate-context
    LOG1("[+] get main thread context ...\n");
    if (InitializeContext(NULL, CONTEXT_ALL | CONTEXT_XSTATE, NULL, &contextSize) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        fprintf(stderr, "[-] Fail to get size of context (error: %d)\n", GetLastError());
        goto fail2;
    }

    ctx.thread_ctx_buff = malloc(contextSize);
    void* modified_ctx_buff = malloc(contextSize);
    if (ctx.thread_ctx_buff == NULL || modified_ctx_buff == NULL) {
        fprintf(stderr, "[-] Fail to get size of context\n");
        goto fail2;
    }

    CONTEXT* modified_ctx;
    int contextSize2 = contextSize;
    if (!InitializeContext(ctx.thread_ctx_buff, CONTEXT_ALL | CONTEXT_XSTATE, &ctx.thread_ctx, &contextSize) ||
            !InitializeContext(modified_ctx_buff, CONTEXT_ALL | CONTEXT_XSTATE, &modified_ctx, &contextSize2)) {
        fprintf(stderr, "[-] Fail to get size of context (error: %d)\n", GetLastError());
        goto fail2;
    }
    if (contextSize2 != contextSize) {
        // may never append
        fprintf(stderr, "[-] ContextSize error (error: %d)\n", GetLastError());
        goto fail2;
    }

    if (!SetXStateFeaturesMask(ctx.thread_ctx, XSTATE_MASK_AVX)) {
        fprintf(stderr, "[-] Fail to set AVX mask (error: %d)\n", GetLastError());
        goto fail2;
    }

    if (!GetThreadContext(MainThread, ctx.thread_ctx)) {
        fprintf(stderr, "[-] Fail to get context (error: %d)\n", GetLastError());
        goto fail2;
    }

    // copy context to a new buffer to modify it;
    memcpy(modified_ctx, ctx.thread_ctx, contextSize);

    // modify main thread
    LOG1("[+] modify main thread context ...\n");
    modified_ctx->Rsp = stack;
    modified_ctx->Rip = (rword) &__main_windows_entrypoint;

    if (!SetThreadContext(MainThread, modified_ctx)) {
        fprintf(stderr, "[-] Fail to set context (error: %d)\n", GetLastError());
        goto fail2;
    }
    free(modified_ctx_buff);
    CloseHandle(MainThread);

    // inform injection and return
    send_message((char*) &res, sizeof(int));
    return;

fail2:
    CloseHandle(MainThread);
fail1:
    int stop = QBDINJECTOR_STOP;
    send_message((char*) &stop, sizeof(int));
    close_pipe();
    return;
}

//void ptrace_to_GPRState(const struct user_regs_struct* gprCtx, GPRState* gprState) {
//#if defined(QBDI_ARCH_X86_64)
//    gprState->rax = gprCtx->rax;
//    gprState->rbx = gprCtx->rbx;
//    gprState->rcx = gprCtx->rcx;
//    gprState->rdx = gprCtx->rdx;
//    gprState->rsi = gprCtx->rsi;
//    gprState->rdi = gprCtx->rdi;
//    gprState->rbp = gprCtx->rbp;
//    gprState->rsp = gprCtx->rsp;
//    gprState->r8 = gprCtx->r8;
//    gprState->r9 = gprCtx->r9;
//    gprState->r10 = gprCtx->r10;
//    gprState->r11 = gprCtx->r11;
//    gprState->r12 = gprCtx->r12;
//    gprState->r13 = gprCtx->r13;
//    gprState->r14 = gprCtx->r14;
//    gprState->r15 = gprCtx->r15;
//    gprState->rip = gprCtx->rip;
//    gprState->eflags = gprCtx->eflags;
//#else
//#error "Not Implemented"
//#endif
//}
//
//void ptrace_to_FPRState(const user_floatingregister_struct* fprCtx, FPRState* fprState) {
//#if defined(QBDI_ARCH_X86_64)
//    fprState->rfcw = fprCtx->cwd;
//    fprState->rfsw = fprCtx->swd;
//    fprState->ftw = fprCtx->ftw & 0xFF;
//    fprState->rsrv1 = (fprCtx->ftw >> 8 ) & 0xFF;
//
//    fprState->ip = fprCtx->rip & 0xFFFFFFFF;
//    fprState->cs = (fprCtx->rip >> 32) & 0xFFFF;
//    fprState->rsrv2 = (fprCtx->rip >> 48) & 0xFFFF;
//
//    fprState->dp = fprCtx->rdp & 0xFFFFFFFF;
//    fprState->ds = (fprCtx->rdp >> 32) & 0xFFFF;
//    fprState->rsrv3 = (fprCtx->rdp >> 48) & 0xFFFF;
//
//    fprState->mxcsr = fprCtx->mxcsr;
//    fprState->mxcsrmask = fprCtx->mxcr_mask;
//
//    memcpy(&fprState->stmm0, &fprCtx->st_space[0], 128);
//    memcpy(&fprState->xmm0, &fprCtx->xmm_space[0], 256);
//#else
//#error "Not Implemented"
//#endif
//}

void __main_windows_entrypoint() {
    LOG1("[+] Hello from main thread ...\n");
//    GPRState gprState = {0};
//    FPRState fprState = {0};
//    struct user_regs_struct origin_regs;
//    user_floatingregister_struct origin_fregs;
//
//    if (qbdinjector_earlyinit())
//        exit(0);
//
//    // get origin register state
//    int len_struct;
//    read_message((char*) &len_struct, sizeof(len_struct), false);
//    if (len_struct != sizeof(origin_regs)) {
//        fprintf(stderr, "[-] length of general register structure missmatched between the Injector and the Injected\n");
//        close_pipe();
//        exit(1);
//    }
//    read_message((char*) &origin_regs, sizeof(origin_regs), false);
//
//    read_message((char*) &len_struct, sizeof(len_struct), false);
//    if (len_struct != sizeof(origin_fregs)) {
//        fprintf(stderr, "[-] length of floating register structure missmatched between the Injector and the Injected\n");
//        close_pipe();
//        exit(1);
//    }
//    read_message((char*) &origin_fregs, sizeof(origin_fregs), false);
//
//    ptrace_to_GPRState(&origin_regs, &gprState);
//    ptrace_to_FPRState(&origin_fregs, &fprState);
//
//    if (qbdinjector_init(&gprState, &fprState))
//        return;
//
//    VMInstanceRef vm;
//    qbdi_initVM(&vm, NULL, NULL);
//    qbdi_instrumentAllExecutableMaps(vm);
//
//    size_t size = 0, i = 0;
//    char **modules = qbdi_getModuleNames(&size);
//
//    // Filter some modules to avoid conflicts
//    qbdi_removeInstrumentedModuleFromAddr(vm, (rword) &__main_linux_entrypoint);
//    qbdi_removeInstrumentedModuleFromAddr(vm, (rword) &qbdi_removeInstrumentedModuleFromAddr);
//    for(i = 0; i < size; i++) {
//        if (strstr(modules[i], "libc-2.") ||
//            strstr(modules[i], "ld-2.") ||
//            strstr(modules[i], "libcofi")) {
//            qbdi_removeInstrumentedModule(vm, modules[i]);
//        }
//    }
//    for(i = 0; i < size; i++) {
//        free(modules[i]);
//    }
//    free(modules);
//
//    // Set original states
//    qbdi_setGPRState(vm, &gprState);
//    qbdi_setFPRState(vm, &fprState);
//
//    rword start = QBDI_GPR_GET(&gprState, REG_PC);
//    rword stop = 0;
//
//    qbdinjector_on_entrypoint(vm, start, stop);
//
    exit(0);
}


