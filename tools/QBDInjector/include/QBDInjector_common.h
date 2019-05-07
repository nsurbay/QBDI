#ifndef QBDI_QBDINJECTOR_COMMON_H
#define QBDI_QBDINJECTOR_COMMON_H

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

// Size of QBDI STACK
static const size_t STACK_SIZE = 8388608;


#ifdef __cplusplus
}
#endif

#endif /* QBDI_QBDINJECTOR_COMMON_H */
