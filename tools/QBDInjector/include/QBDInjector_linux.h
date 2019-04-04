#ifndef _QBDINJECTOR_LINUX_H
#define _QBDINJECTOR_LINUX_H

#include "QBDInjector_common.h"

#ifdef __cplusplus
extern "C" {
#endif


static const size_t STACK_SIZE = 8388608;

#if defined(QBDI_ARCH_X86)
#define QBDI_PTRACE_GETFREG PTRACE_GETFPXREGS
typedef struct user_fpxregs_struct user_floatingregister_struct;

#elif defined(QBDI_ARCH_X86_64)
#define QBDI_PTRACE_GETFREG PTRACE_GETFPREGS
typedef struct user_fpregs_struct user_floatingregister_struct;

#else
#error "Not Implemented"
#endif



#ifdef __cplusplus
}
#endif

#endif /* _QBDINJECTOR_LINUX_H */
