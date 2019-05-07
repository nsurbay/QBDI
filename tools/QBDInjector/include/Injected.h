#ifndef QBDI_Injected_h
#define QBDI_Injected_h

#include "QBDInjector_common.h"
#include "QBDInjector.h"

#ifdef _QBDI_DEBUG
#define LOG1(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG1(...)
#endif

#endif /* QBDI_Injected_h */
