#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <vector>
#include <algorithm>

#include "GumInjected.h"

namespace QBDInjector {

static std::vector<Registered_CB> callback_list;
static bool enable_cb = true;

void enable_callback() {
    if (enable_cb)
        return;
    GumInterceptor* interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction(interceptor);
    for (Registered_CB& cb : callback_list) {
        gum_interceptor_replace_function(interceptor, GSIZE_TO_POINTER(cb.addr), GSIZE_TO_POINTER(__qbdinjected_enter), GSIZE_TO_POINTER(cb.addr));
    }
    gum_interceptor_end_transaction(interceptor);
    enable_cb = true;
}

void disable_callback() {
    if (!enable_cb)
        return;
    GumInterceptor* interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction(interceptor);
    for (Registered_CB& cb : callback_list) {
        gum_interceptor_revert_function(interceptor, GSIZE_TO_POINTER(cb.addr));
    }
    gum_interceptor_end_transaction(interceptor);
    enable_cb = false;
}


int qbdiguminjector_hook_addr(QBDI::rword addr, QBDIGumCB cb, void* data) {
    if (cb == NULL) {
        return -2;
    }
    for (Registered_CB& cb : callback_list) {
        if (cb.addr == addr) {
            return -3;
        }
    }

    callback_list.push_back({addr, cb, data});

    if (enable_cb) {
        GumInterceptor* interceptor = gum_interceptor_obtain();
        gum_interceptor_begin_transaction(interceptor);
        gum_interceptor_replace_function(interceptor, GSIZE_TO_POINTER(addr), GSIZE_TO_POINTER(__qbdinjected_enter), GSIZE_TO_POINTER(addr));
        gum_interceptor_end_transaction(interceptor);
    }

    return 0;
}

int qbdiguminjector_hook_name(char* name, QBDIGumCB cb, void* data) {
    QBDI::rword addr = gum_module_find_export_by_name (NULL, name);
    if (addr != 0) {
        return qbdiguminjector_hook_addr(addr, cb, data);
    } else {
        return -1;
    }
}

void qbdiguminjector_remove_hook_addr(QBDI::rword addr) {
    callback_list.erase(std::remove_if(callback_list.begin(), callback_list.end(),
                         [addr](Registered_CB& elem){
                                if (elem.addr == addr) {
                                    if (enable_cb) {
                                        GumInterceptor* interceptor = gum_interceptor_obtain();
                                        gum_interceptor_begin_transaction(interceptor);
                                        gum_interceptor_revert_function(interceptor, GSIZE_TO_POINTER(addr));
                                        gum_interceptor_end_transaction(interceptor);
                                    }
                                    return true;
                                } else {
                                    return false;
                                }
                         } ),
          callback_list.end());
}

void qbdiguminjector_remove_hook_name(char* name) {
    QBDI::rword addr = gum_module_find_export_by_name (NULL, name);
    if (addr != 0) {
        qbdiguminjector_remove_hook_addr(addr);
    }
}

void __qbdinjected_qbdi_main(QBDI::GPRState* gpr, QBDI::FPRState* fpr) {

    disable_callback();
    bool instrumented = false;
    QBDI::rword start = gpr->rip;
    QBDI::rword end = *((QBDI::rword*) gpr->rsp);

    for (Registered_CB& cb : callback_list) {
        if (cb.addr == start) {
            instrumented = true;
            cb.cb(gpr, fpr, start, end, cb.data);
            break;
        }
    }
    if (!instrumented) {
        fprintf(stderr, "[-] Fail to get callback\n");
        abort();
    }

    // instrument
    enable_callback();
    gum_interceptor_unignore_current_thread(gum_interceptor_obtain());
    __qbdinjected_exit(gpr, fpr);
    //__builtin_unreachable();
    abort();
}

void __qbdinjected_allocate(QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
    static void* qbdi_stack = NULL;
    static QBDI::GPRState* gprtransfert = NULL;
    static QBDI::FPRState* fprtransfert = NULL;
    gum_interceptor_ignore_current_thread(gum_interceptor_obtain());

    // set RIP
    GumInvocationContext* ctx = gum_interceptor_get_current_invocation ();
    if (ctx == NULL) {
        fprintf(stderr, "[-] Fail to get current context\n");
        abort();
    }
    gpr->rip = (QBDI::rword) gum_invocation_context_get_replacement_function_data (ctx);

    if (qbdi_stack == NULL) {
        qbdi_stack = get_stack();
    }

    if (gprtransfert == NULL) {
        gprtransfert = new QBDI::GPRState;
    }
    if (fprtransfert == NULL) {
        fprtransfert = new QBDI::FPRState;
    }

    memcpy(gprtransfert, gpr, sizeof(QBDI::GPRState));
    memcpy(fprtransfert, fpr, sizeof(QBDI::FPRState));

    __qbdinjected_change_stack(gprtransfert, fprtransfert, qbdi_stack, __qbdinjected_qbdi_main);
    //__builtin_unreachable();
    abort();
}

}
