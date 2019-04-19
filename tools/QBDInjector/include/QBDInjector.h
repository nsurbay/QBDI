#ifndef _QBDInjector_h
#define _QBDInjector_h

#include <stdbool.h>
#include "QBDI.h"

#ifdef __cplusplus
namespace QBDInjector {
extern "C" {
#endif

#if defined(QBDI_OS_WIN)
#pragma comment(linker, "/export:_qbdinjector_frida_entrypoint")
#endif

/*
 * method called in frida injected thread
 */

#define QBDINJECTOR_CONTINUE 0x0
#define QBDINJECTOR_STOP 0x1

// at begin of frida injected thread. need return CONTINUE | STOP
extern int qbdinjector_frida_earlyinit(const char* msg, bool* stay_resident);

#define QBDINJECTOR_INJECT 0x2
#define QBDINJECTOR_WAIT 0x4

// on frida thread with '-p' parameter. need to return STOP | INJECT | WAIT
extern int qbdinjector_frida_init(const char* parameter);

/*
 * method called in main thread after QBDINJECTOR_INJECT
 */

// call after inject in main thread, need return CONTINUE | STOP
extern int qbdinjector_earlyinit();

// call with init state of the process, need return CONTINUE | STOP
extern int qbdinjector_init(GPRState *gprState, FPRState *fprState);

extern int qbdinjector_on_entrypoint(VMInstanceRef vm, rword start, rword stop);

#ifdef __cplusplus
}
}
#endif

#endif /* _QBDInjector_h */
