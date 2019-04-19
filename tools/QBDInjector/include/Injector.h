#ifndef _Injector_h
#define _Injector_h

#include <vector>
#include <memory>
#include "frida-core.h"
#include "QBDInjector_common.h"

#define ENTRYPOINT_NAME "_qbdinjector_frida_entrypoint"

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
    SYNC
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
int sync(FridaDevice* device, Arguments* arg);

// OS specific method
void wait_end_child(Arguments* arg);
int setup_inject(FridaDevice* device, Arguments* arg);

}

#endif /* _Injector_h */
