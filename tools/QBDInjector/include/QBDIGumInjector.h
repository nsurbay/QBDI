#ifndef QBDI_QBDIGumInjector_h
#define QBDI_QBDIGumInjector_h

#include <stdbool.h>
#include "QBDI.h"


#ifdef __cplusplus
namespace QBDInjector {
using namespace QBDI;
extern "C" {
#endif

/*
 * Force define symbol
 * Don't call or implement this method
 */

#if defined(QBDI_OS_WIN)
#include <windows.h>
#pragma comment(linker, "/export:_qbdiguminjector_frida_entrypoint")
#pragma comment(linker, "/export:__qbdinjected_allocate")
#else
void _qbdiguminjector_frida_entrypoint(const char* msg, bool* stay_resident);
static void __attribute__ ((used)) *___qbdiguminjector_frida_entrypoint__fp = (void*) &_qbdiguminjector_frida_entrypoint;
void __qbdinjected_allocate(GPRState* gpr, FPRState* fpr);
static void __attribute__ ((used)) *____qbdinjected_allocate__fp = (void*) &__qbdinjected_allocate;
#endif

/*
 * method called in frida injected thread
 */

#define QBDINJECTOR_CONTINUE 0x0
#define QBDINJECTOR_STOP 0x1

// at begin of frida injected thread, before gum_initialise. need return CONTINUE | STOP
extern int qbdiguminjector_frida_earlyinit(const char* msg, bool* stay_resident);

// on frida thread with '-p' parameter, after gum_initialise, can use API. need to return CONTINUE | STOP
// Early instrumented has to be place here
// If plateform support resume thread in the same processus, the main thread is stopped
extern int qbdiguminjector_frida_init(const char* parameter);

// Same as qbdiguminjector_frida_init
// If plateform support resume thread in the same processus, the main thread is running
extern int qbdiguminjector_frida_run(const char* parameter);

/*
 * API Callback when hook
 * start == gpr->rip
 * end == *(gpr->rsp) on x86-64
 *
 * /!\ if this callback return, the next state must be set on gpr and fpr
 */
typedef void(*QBDIGumCB)(GPRState* gpr, FPRState* fpr, rword start, rword end, void* data);

/*
 * addr a callback in the given address.
 * return 0 on success
 */
int qbdiguminjector_hook_addr(rword addr, QBDIGumCB cb, void* data);

/*
 * addr a callback in the given exported symbol.
 * return 0 on success
 */
int qbdiguminjector_hook_name(char* name, QBDIGumCB cb, void* data);

/*
 * remove hook on addr
 */
void qbdiguminjector_remove_hook_addr(rword addr);

/*
 * remove hook on name
 */
void qbdiguminjector_remove_hook_name(char* name);

/*
 * initialise a VM with standard for the current environnemnt
 */
VMInstanceRef qbdiguminjector_init_vm(GPRState* gpr, FPRState* fpr);

/*
 * Delete vm and set the current state in given gpr/fpr
 */
void qbdiguminjector_stop_vm(VMInstanceRef vm, GPRState* gpr, FPRState* fpr);


#ifdef __cplusplus
}
}
#endif

#endif /* QBDI_QBDIGumInjector_h */
