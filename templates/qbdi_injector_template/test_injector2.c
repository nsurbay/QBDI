
#include "QBDInjector.h"
#include <dlfcn.h>
#include <assert.h>


static void* libc = NULL;
static rword libc_start_main = 0;

VMAction onInstruction(VMInstanceRef vm, GPRState *gprState, FPRState *fprState, void *data) {
    const InstAnalysis* instAnalysis = qbdi_getInstAnalysis(vm, QBDI_ANALYSIS_INSTRUCTION | QBDI_ANALYSIS_DISASSEMBLY | QBDI_ANALYSIS_SYMBOL);
    if (instAnalysis->symbol != NULL) {
        printf("%20s+%05u\t", instAnalysis->symbol, instAnalysis->symbolOffset);
    } else {
        printf("%26s\t", "");
    }
    printf("0x%" PRIRWORD " %s\n", instAnalysis->address, instAnalysis->disassembly);
    return QBDI_CONTINUE;
}

struct trampoline {
    rword origin;
    rword tramp;
};

static VMAction on_tramp_ret(VMInstanceRef vm, GPRState *gprState, FPRState *fprState, void *data) {
    struct trampoline* t = (struct trampoline*) data;
    qbdi_removeTrampolineCB(vm, t->tramp);
    gprState->rip = t->origin;

    printf("\ton_tramp_ret called to addr 0x%lx\n", t->origin);
    if (gprState->rax == 1) {
        printf("\tChange return value to 0\n");
        gprState->rax = 0;
    }
    qbdi_addExecBrokerNoRetAddr(vm, t->origin);
    free(data);
    return QBDI_CONTINUE;
}

static VMAction on_tramp(VMInstanceRef vm, GPRState *gprState, FPRState *fprState, void *data) {
    struct trampoline* t = (struct trampoline*) data;
    gprState->rip = t->origin;

    if (gprState->rdi != 1) {
        printf("\tChange call to 1\n");
        gprState->rdi = 1;
    }
    if (qbdi_isInstrumented(vm, t->origin)) {
        printf("\ton_tramp called to instrumented addr 0x%lx\n", t->origin);

    } else {
        printf("\ton_tramp called to not instrumented addr 0x%lx\n", t->origin);
        qbdi_addExecBrokerNoRetAddr(vm, t->origin);

    }

    struct trampoline* t2 = (struct trampoline*) malloc(sizeof(struct trampoline));
    assert(t2 != NULL);
    t2->origin = *((rword*) gprState->rsp);
    t2->tramp = qbdi_addTrampolineCB(vm, on_tramp_ret, t2);
    *((rword*) gprState->rsp) = t2->tramp;
    return QBDI_CONTINUE;
}

static VMAction on_libc_start_main(VMInstanceRef vm, const VMState *vmState, GPRState *gprState, FPRState *fprState, void *data) {

    printf("\ton_libc_start_main called\n");

    {
        struct trampoline* t = (struct trampoline*) malloc(sizeof(struct trampoline));
        assert(t != NULL);

        t->origin = gprState->rdi;
        t->tramp = qbdi_addTrampolineCB(vm, on_tramp, t);
        assert(t->tramp != 0);

        gprState->rdi = t->tramp;
    }
    {
        struct trampoline* t = (struct trampoline*) malloc(sizeof(struct trampoline));
        assert(t != NULL);

        t->origin = gprState->rcx;
        t->tramp = qbdi_addTrampolineCB(vm, on_tramp, t);
        assert(t->tramp != 0);

        gprState->rcx = t->tramp;
    }
    {
        struct trampoline* t = (struct trampoline*) malloc(sizeof(struct trampoline));
        assert(t != NULL);

        t->origin = gprState->r8;
        t->tramp = qbdi_addTrampolineCB(vm, on_tramp, t);
        assert(t->tramp != 0);

        gprState->r8 = t->tramp;
    }
    return QBDI_CONTINUE;
}



// QBDInjector part

int qbdinjector_frida_earlyinit(const char* msg, bool* stay_resident) {
    return QBDINJECTOR_CONTINUE;
}

int qbdinjector_frida_init(const char* msg) {
    printf("recv msg : %s\n", msg);
    return QBDINJECTOR_WAIT | QBDINJECTOR_INJECT;
}

int qbdinjector_earlyinit() {
    return QBDINJECTOR_CONTINUE;
}

int qbdinjector_init(GPRState *gprState, FPRState *fprState) {
    //qbdi_addLogFilter("getRemoteProcessMaps", QBDI_DEBUG);
    return QBDINJECTOR_CONTINUE;
}

int qbdinjector_on_entrypoint(VMInstanceRef vm, rword start, rword stop) {

    libc = dlopen("libc-2.28.so", RTLD_NOW | RTLD_NOLOAD);
    if (libc == NULL) {
        printf("%s\n", dlerror());
        exit(1);
    }

    libc_start_main = (rword) dlsym(libc, "__libc_start_main");
    if (libc_start_main == 0) {
        printf("%s\n", dlerror());
        exit(1);
    }

    qbdi_addExecBrokerAddrCB(vm, libc_start_main, on_libc_start_main, NULL);
    qbdi_addCodeCB(vm, QBDI_PREINST, onInstruction, NULL);
    //qbdi_addLogFilter("Engine*", QBDI_DEBUG);
    //qbdi_addLogFilter("Exec*", QBDI_DEBUG);
    qbdi_addLogFilter("ExecBroker::getTrampoline", QBDI_DEBUG);
    qbdi_run(vm, start, stop);
    return QBDINJECTOR_STOP;
}
