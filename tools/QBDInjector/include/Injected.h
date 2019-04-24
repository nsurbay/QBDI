#ifndef _Injected_h
#define _Injected_h

#include "QBDInjector_common.h"
#include "QBDInjector.h"

#ifdef _QBDI_DEBUG
#define LOG1(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG1(...)
#endif

#endif /* _Injected_h */
