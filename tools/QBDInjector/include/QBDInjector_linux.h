#ifndef QBDI_QBDINJECTOR_LINUX_H
#define QBDI_QBDINJECTOR_LINUX_H

#include "QBDInjector_common.h"

#ifdef __cplusplus
extern "C" {
#endif


#if defined(QBDI_ARCH_X86)
#define QBDI_PTRACE_GETFREG PTRACE_GETFPXREGS
typedef struct user_fpxregs_struct user_floatingregister_struct;

#elif defined(QBDI_ARCH_X86_64)
#define QBDI_PTRACE_GETFREG PTRACE_GETFPREGS
typedef struct user_fpregs_struct user_floatingregister_struct;

#else
#error "Not Implemented"
#endif

// communication method
char* init_server(int verbose);
void init_client(const char* pipename, int verbose);
void open_pipe();
void close_pipe();
void send_message(char* buf, size_t len);
int read_message(char *buf, size_t len, bool allow_EOF);

#ifdef __cplusplus
}
#endif

#endif /* QBDI_QBDINJECTOR_LINUX_H */
