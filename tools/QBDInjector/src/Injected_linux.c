
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)

#include "Injected.h"
#include "QBDInjector_linux.h"

void __main_linux_entrypoint();


void __attribute__ ((visibility ("default")))
_qbdinjector_frida_entrypoint(const char* msg, bool* stay_resident) {

    *stay_resident = true;

    LOG1("[+] call qbdinjector_frida_earlyinit ...\n");
    int res = qbdinjector_frida_earlyinit(msg, stay_resident);
    if (res)
        return;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

#ifdef _QBDI_DEBUG
    init_client(msg, 1);
#else
    init_client(msg, 0);
#endif
    open_pipe();
    int len_parameter;
    read_message((char*) &len_parameter, sizeof(len_parameter), false);
    char* parameter = malloc(len_parameter+1);
    if (parameter == NULL) {
        fprintf(stderr, "[-] Failled malloc\n");
        return;
    }
    read_message(parameter, len_parameter, false);
    parameter[len_parameter] = '\0';

    LOG1("[+] call qbdinjector_frida_init ...\n");
    res = qbdinjector_frida_init(parameter);

    if (res & QBDINJECTOR_STOP) {
        send_message((char*) &res, sizeof(res));
        close_pipe();
        return;
    }

    // prepare page to trigger sighandler
    void* page = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (page == MAP_FAILED) {
        perror("[-] mmap failled ...");
        int stop = QBDINJECTOR_STOP;
        send_message((char*) &stop, sizeof(int));
        close_pipe();
        return;
    }

#if defined(QBDI_ARCH_X86)
    rword stack = ((rword) page) + STACK_SIZE - 4;
#else
    rword stack = ((rword) page) + STACK_SIZE - 8;
#endif

    // inform injection
    send_message((char*) &res, sizeof(int));
    // send new executive address
    rword new_entrypoint_addr = (rword) &__main_linux_entrypoint;
    send_message(((char*) &new_entrypoint_addr), sizeof(rword));
    // send new stack address
    send_message((char*) &stack, sizeof(rword));
}

void ptrace_to_GPRState(const struct user_regs_struct* gprCtx, GPRState* gprState) {
#if defined(QBDI_ARCH_X86_64)
    gprState->rax = gprCtx->rax;
    gprState->rbx = gprCtx->rbx;
    gprState->rcx = gprCtx->rcx;
    gprState->rdx = gprCtx->rdx;
    gprState->rsi = gprCtx->rsi;
    gprState->rdi = gprCtx->rdi;
    gprState->rbp = gprCtx->rbp;
    gprState->rsp = gprCtx->rsp;
    gprState->r8 = gprCtx->r8;
    gprState->r9 = gprCtx->r9;
    gprState->r10 = gprCtx->r10;
    gprState->r11 = gprCtx->r11;
    gprState->r12 = gprCtx->r12;
    gprState->r13 = gprCtx->r13;
    gprState->r14 = gprCtx->r14;
    gprState->r15 = gprCtx->r15;
    gprState->rip = gprCtx->rip;
    gprState->eflags = gprCtx->eflags;
#else
#error "Not Implemented"
#endif
}

void ptrace_to_FPRState(const user_floatingregister_struct* fprCtx, FPRState* fprState) {
#if defined(QBDI_ARCH_X86_64)
    fprState->rfcw = fprCtx->cwd;
    fprState->rfsw = fprCtx->swd;
    fprState->ftw = fprCtx->ftw & 0xFF;
    fprState->rsrv1 = (fprCtx->ftw >> 8 ) & 0xFF;

    fprState->fop = fprCtx->fop;
    fprState->ip = fprCtx->rip & 0xFFFFFFFF;
    fprState->cs = (fprCtx->rip >> 32) & 0xFFFF;
    fprState->rsrv2 = (fprCtx->rip >> 48) & 0xFFFF;

    fprState->dp = fprCtx->rdp & 0xFFFFFFFF;
    fprState->ds = (fprCtx->rdp >> 32) & 0xFFFF;
    fprState->rsrv3 = (fprCtx->rdp >> 48) & 0xFFFF;

    fprState->mxcsr = fprCtx->mxcsr;
    fprState->mxcsrmask = fprCtx->mxcr_mask;

    memcpy(&fprState->stmm0, &fprCtx->st_space[0], 128);
    memcpy(&fprState->xmm0, &fprCtx->xmm_space[0], 256);
#else
#error "Not Implemented"
#endif
}

void __main_linux_entrypoint() {
    GPRState gprState = {0};
    FPRState fprState = {0};
    struct user_regs_struct origin_regs;
    user_floatingregister_struct origin_fregs;

    if (qbdinjector_earlyinit())
        exit(0);

    // get origin register state
    int len_struct;
    read_message((char*) &len_struct, sizeof(len_struct), false);
    if (len_struct != sizeof(origin_regs)) {
        fprintf(stderr, "[-] length of general register structure missmatched between the Injector and the Injected\n");
        close_pipe();
        exit(1);
    }
    read_message((char*) &origin_regs, sizeof(origin_regs), false);

    read_message((char*) &len_struct, sizeof(len_struct), false);
    if (len_struct != sizeof(origin_fregs)) {
        fprintf(stderr, "[-] length of floating register structure missmatched between the Injector and the Injected\n");
        close_pipe();
        exit(1);
    }
    read_message((char*) &origin_fregs, sizeof(origin_fregs), false);

    ptrace_to_GPRState(&origin_regs, &gprState);
    ptrace_to_FPRState(&origin_fregs, &fprState);

    if (qbdinjector_init(&gprState, &fprState))
        return;

    VMInstanceRef vm;
    qbdi_initVM(&vm, NULL, NULL);
    qbdi_instrumentAllExecutableMaps(vm);

    size_t size = 0, i = 0;
    char **modules = qbdi_getModuleNames(&size);

    // Filter some modules to avoid conflicts
    qbdi_removeInstrumentedModuleFromAddr(vm, (rword) &__main_linux_entrypoint);
    qbdi_removeInstrumentedModuleFromAddr(vm, (rword) &qbdi_removeInstrumentedModuleFromAddr);
    for(i = 0; i < size; i++) {
        if (strstr(modules[i], "libc-2.") ||
            strstr(modules[i], "ld-2.") ||
            strstr(modules[i], "libcofi")) {
            qbdi_removeInstrumentedModule(vm, modules[i]);
        }
    }
    for(i = 0; i < size; i++) {
        free(modules[i]);
    }
    free(modules);

    // Set original states
    qbdi_setGPRState(vm, &gprState);
    qbdi_setFPRState(vm, &fprState);

    rword start = QBDI_GPR_GET(&gprState, REG_PC);
    rword stop = 0;

    qbdinjector_on_entrypoint(vm, start, stop);

    exit(0);
}


