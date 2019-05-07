#ifndef QBDI_Injector_h
#define QBDI_Injector_h

#include <vector>
#include <memory>
#include "frida-core.h"
#include "QBDInjector_common.h"

#define SYNC_ENTRYPOINT_NAME "_qbdinjector_frida_entrypoint"
#define GUM_ENTRYPOINT_NAME "_qbdiguminjector_frida_entrypoint"

namespace QBDInjector {

#define LOG1(...) if (arg->verbose >= 1) {fprintf(stderr, __VA_ARGS__);}
#define LOGE() \
    if (error != nullptr) { \
        fprintf(stderr, "[-] Error %s:%d: %s\n", __FILE__, __LINE__, error->message); \
        g_error_free(error); \
        return 1; \
    }

enum ExecType {
    NONE = 0,
    ATTACH,
    SPAWN,
    SYNC,
    GUM
};

struct Arguments {
    enum ExecType exectype;
    int pid;
    int verbose;
    bool wait;
    bool resume;
    char* injectlibrary;
    char* command;
    char* entrypoint_name;
    char* entrypoint_parameter;
    char* parameter;
    std::vector<char*> arguments;
    std::vector<char*> env;
};

int inject(FridaDevice* device, Arguments* arg);
int gum(FridaDevice* device, Arguments* arg);
int sync(FridaDevice* device, Arguments* arg);

// OS specific method
void wait_end_child(Arguments* arg);
bool test_library(Arguments* arg);

}

#endif /* QBDI_Injector_h */
