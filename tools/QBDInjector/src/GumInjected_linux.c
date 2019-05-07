#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "frida-gum.h"
#include "GumInjected.h"

void __attribute__ ((visibility ("default")))
_qbdiguminjector_frida_entrypoint(const char* param, bool* persistent) {
    *persistent = true;

    if (qbdiguminjector_frida_earlyinit(param, persistent))
        return;


    gum_init_embedded();
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (qbdiguminjector_frida_init(param))
        return;
    if (qbdiguminjector_frida_run(param))
        return;
}

void* get_stack() {
    void* qbdi_stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (qbdi_stack == MAP_FAILED) {
        perror("[-] mmap failled ...");
        abort();
    }
#if defined(QBDI_ARCH_X86)
    qbdi_stack += STACK_SIZE - 4;
#else
    qbdi_stack += STACK_SIZE - 8;
#endif

    return qbdi_stack;
}

VMInstanceRef qbdiguminjector_init_vm(GPRState* gpr, FPRState* fpr) {
    VMInstanceRef vm;
    qbdi_initVM(&vm, NULL, NULL);
    qbdi_instrumentAllExecutableMaps(vm);

    size_t size = 0, i = 0;
    char **modules = qbdi_getModuleNames(&size);

    // Filter some modules to avoid conflicts
    qbdi_removeInstrumentedModuleFromAddr(vm, (rword) &qbdiguminjector_init_vm);
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
    qbdi_setGPRState(vm, gpr);
    qbdi_setFPRState(vm, fpr);

    return vm;
}


void qbdiguminjector_stop_vm(VMInstanceRef vm, GPRState* gpr, FPRState* fpr) {
    memcpy(gpr, qbdi_getGPRState(vm), sizeof(GPRState));
    memcpy(fpr, qbdi_getFPRState(vm), sizeof(FPRState));
    qbdi_terminateVM(vm);
}
