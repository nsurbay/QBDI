
#include "QBDInjector.h"

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
    return QBDINJECTOR_CONTINUE;
}

int qbdinjector_on_entrypoint(VMInstanceRef vm, rword start, rword stop) {
    qbdi_addCodeCB(vm, QBDI_PREINST, onInstruction, NULL);
    qbdi_addLogFilter("*", QBDI_DEBUG);
    qbdi_run(vm, start, stop);
    return QBDINJECTOR_STOP;
}
