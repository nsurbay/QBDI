#ifndef _QBDINJECTOR_COMMON_H
#define _QBDINJECTOR_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "QBDI/Platform.h"
#include "QBDI/State.h"

#ifdef __cplusplus
extern "C" {
#endif

// macro user result
#define QBDINJECTOR_STOP 0x1
#define QBDINJECTOR_INJECT 0x2
#define QBDINJECTOR_WAIT 0x4

// common communication method
char* init_server(int verbose);
void init_client(const char* pipename, int verbose);
void open_pipe();
void close_pipe();
void send_message(char* buf, size_t len);
int read_message(char *buf, size_t len, bool allow_EOF);

#ifdef __cplusplus
}
#endif

#endif /* _QBDINJECTOR_COMMON_H */
