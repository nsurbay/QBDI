
#include <string.h>
#include <windows.h>
#include <TlHelp32.h>
#include <winbase.h>

#include "Injected.h"

static struct _win_Injected_ctx {
    void* thread_ctx_buff;
    CONTEXT *thread_ctx;
} ctx = {NULL, NULL};

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
    if (ctx.thread_ctx_buff == NULL) {
        fprintf(stderr, "[-] Fail to get size of context\n");
        goto fail2;
    }

    if (!InitializeContext(ctx.thread_ctx_buff, CONTEXT_ALL | CONTEXT_XSTATE, &ctx.thread_ctx, &contextSize)) {
        fprintf(stderr, "[-] Fail to get size of context (error: %d)\n", GetLastError());
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

    // modify main thread
    LOG1("[+] modify main thread context ...\n");
    rword save_rsp = ctx.thread_ctx->Rsp;
    rword save_rip = ctx.thread_ctx->Rip;
    ctx.thread_ctx->Rsp = stack;
    ctx.thread_ctx->Rip = (rword) &__main_windows_entrypoint;

    if (!SetThreadContext(MainThread, ctx.thread_ctx)) {
        fprintf(stderr, "[-] Fail to set context (error: %d)\n", GetLastError());
        goto fail2;
    }

    // restore previous value in context
    ctx.thread_ctx->Rsp = save_rsp;
    ctx.thread_ctx->Rip = save_rip;

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

void ThreadContext_to_GPRState(CONTEXT* ctx, GPRState* gprState) {
#if defined(QBDI_ARCH_X86_64)
    // http://winappdbg.sourceforge.net/doc/v1.3/winappdbg.win32.context_amd64-pysrc.html
    gprState->rax = ctx->Rax;
    gprState->rbx = ctx->Rbx;
    gprState->rcx = ctx->Rcx;
    gprState->rdx = ctx->Rdx;
    gprState->rsi = ctx->Rsi;
    gprState->rdi = ctx->Rdi;
    gprState->rbp = ctx->Rbp;
    gprState->rsp = ctx->Rsp;
    gprState->r8 = ctx->R8;
    gprState->r9 = ctx->R9;
    gprState->r10 = ctx->R10;
    gprState->r11 = ctx->R11;
    gprState->r12 = ctx->R12;
    gprState->r13 = ctx->R13;
    gprState->r14 = ctx->R14;
    gprState->r15 = ctx->R15;
    gprState->rip = ctx->Rip;
    gprState->eflags = ctx->EFlags;
#else
#error "Not Implemented"
#endif
}

void ThreadContext_to_FPRState(CONTEXT* ctx, FPRState* fprState) {
#if defined(QBDI_ARCH_X86_64)
    fprState->rfcw = ctx->FltSave.ControlWord;
    fprState->rfsw = ctx->FltSave.StatusWord;
    fprState->ftw = ctx->FltSave.TagWord;
    fprState->rsrv1 = ctx->FltSave.Reserved1;

    fprState->fop = ctx->FltSave.ErrorOpcode;
    fprState->ip = ctx->FltSave.ErrorOffset;
    fprState->cs = ctx->FltSave.ErrorSelector;
    fprState->rsrv2 = ctx->FltSave.Reserved2;

    fprState->dp = ctx->FltSave.DataOffset;
    fprState->ds = ctx->FltSave.DataSelector;
    fprState->rsrv3 = ctx->FltSave.Reserved3;

    fprState->mxcsr = ctx->FltSave.MxCsr;
    fprState->mxcsrmask = ctx->FltSave.MxCsr_Mask;

    memcpy(&fprState->stmm0, &ctx->FltSave.FloatRegisters, 128);
    memcpy(&fprState->xmm0, &ctx->FltSave.XmmRegisters, 256);
    memcpy(&fprState->ymm0, LocateXStateFeature(ctx, XSTATE_AVX, NULL), 256);
#else
#error "Not Implemented"
#endif
}

void __main_windows_entrypoint() {
    LOG1("[+] Hello from main thread ...\n");
    GPRState gprState = {0};
    FPRState fprState = {0};

    LOG1("[+] Call qbdinjector_earlyinit ...\n");
    if (qbdinjector_earlyinit())
        exit(0);

    if (ctx.thread_ctx == NULL) {
        fprintf(stderr, "[-] Cannot Found thread state\n");
        exit(127);
    }
    LOG1("[+] Create Context ...\n");
    ThreadContext_to_GPRState(ctx.thread_ctx, &gprState);
    ThreadContext_to_FPRState(ctx.thread_ctx, &fprState);

    LOG1("[+] Call qbdinjector_init ...\n");
    if (qbdinjector_init(&gprState, &fprState))
        exit(0);

    LOG1("[+] Create VM ...\n");
    VMInstanceRef vm;
    qbdi_initVM(&vm, NULL, NULL);
    qbdi_instrumentAllExecutableMaps(vm);

    size_t size = 0, i = 0;
    char **modules = qbdi_getModuleNames(&size);

    // Filter some modules to avoid conflicts
    qbdi_removeInstrumentedModuleFromAddr(vm, (rword) &__main_windows_entrypoint);
    qbdi_removeInstrumentedModuleFromAddr(vm, (rword) &qbdi_removeInstrumentedModuleFromAddr);
    // TODO
    //for(i = 0; i < size; i++) {
    //    if (strstr(modules[i], "libc-2.") ||
    //        strstr(modules[i], "ld-2.") ||
    //        strstr(modules[i], "libcofi")) {
    //        qbdi_removeInstrumentedModule(vm, modules[i]);
    //    }
    //}
    for(i = 0; i < size; i++) {
        free(modules[i]);
    }
    free(modules);

    // Set original states
    qbdi_setGPRState(vm, &gprState);
    qbdi_setFPRState(vm, &fprState);

    rword start = QBDI_GPR_GET(&gprState, REG_PC);
    rword stop = 0;

    LOG1("[+] Call qbdinjector_on_entrypoint ...\n");
    qbdinjector_on_entrypoint(vm, start, stop);

    exit(0);
}


