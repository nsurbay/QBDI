#ifndef _Injected_h
#define _Injected_h

#include "QBDInjector_common.h"
#include "QBDInjector.h"

#ifdef _QBDI_DEBUG
#define LOG1(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG1(...)
#endif

// OS specific to begin inject in main thread
void prepare_inject(int res);

#endif /* _Injected_h */
