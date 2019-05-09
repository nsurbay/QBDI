#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <windows.h>
#include <TlHelp32.h>

#include "GumInjected.h"

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

void _qbdiguminjector_frida_entrypoint(const char* param, bool* persistent) {
    *persistent = true;

    if (qbdiguminjector_frida_earlyinit(param, persistent))
        return;

    gum_init_embedded();
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (qbdiguminjector_frida_init(param))
        return;

    int maintid = get_maintid(GetCurrentProcessId());
    if (maintid < 0) {
        fprintf(stderr, "[-] Fail to find main tid\n");
        return;
    }

    HANDLE MainThread = OpenThread(THREAD_ALL_ACCESS, TRUE, maintid);
    if (MainThread == NULL) {
        fprintf(stderr, "[-] Fail to OpenThread on tid %d (error: %d)\n", maintid, GetLastError());
        return;
    }
    ResumeThread(MainThread);
    CloseHandle(MainThread);

    if (qbdiguminjector_frida_run(param))
        return;
}

void* get_stack() {
    void* qbdi_stack = VirtualAlloc(NULL, STACK_SIZE, MEM_COMMIT, PAGE_READWRITE);
    if (qbdi_stack == NULL) {
        perror("[-] VirtualAlloc failled ...");
        abort();
    }

#if defined(QBDI_ARCH_X86)
    qbdi_stack = ((void*) ((rword) qbdi_stack + STACK_SIZE - 4));
#else
    qbdi_stack = ((void*) ((rword) qbdi_stack + STACK_SIZE - 8));
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
        if (strstr(modules[i], "ntdll.") ||
                strstr(modules[i], "ucrtbased.")) {
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
