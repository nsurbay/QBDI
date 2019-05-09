#ifndef QBDI_GumInjected_h
#define QBDI_GumInjected_h

#include "QBDInjector_common.h"
#include "QBDIGumInjector.h"
#include "frida-gum.h"

#ifdef _QBDI_DEBUG
#define LOG1(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG1(...)
#endif

#ifdef __cplusplus
namespace QBDInjector {
using namespace QBDI;
extern "C" {
#endif

#if defined(QBDI_OS_WIN)
    void __qbdinjected_enter();
    rword __qbdinjected_change_stack(GPRState* gpr, FPRState* fpr, void* new_rsp, void (*next_call)(GPRState*, FPRState*));
    void __qbdinjected_exit(GPRState* gpr, FPRState* fpr);
#else
    void __qbdinjected_enter() asm ("__qbdinjected_enter");
    rword __qbdinjected_change_stack(GPRState* gpr, FPRState* fpr, void* new_rsp, void (*next_call)(GPRState*, FPRState*)) asm ("__qbdinjected_change_stack");
    void __qbdinjected_exit(GPRState* gpr, FPRState* fpr) asm ("__qbdinjected_exit");
#endif

void __qbdinjected_allocate(GPRState* gpr, FPRState* fpr);
void* get_stack();

struct Registered_CB {
    rword addr;
    QBDIGumCB cb;
    void* data;
};


#ifdef __cplusplus
}
}
#endif

#endif /* QBDI_GumInjected_h */
