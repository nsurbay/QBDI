#ifndef _QBDInjector_hpp
#define _QBDInjector_hpp

#include <vector>
#include "frida-core.h"

enum ExecType {
    NONE = 0,
    ATTACH,
    SPAWN,
    SYNC
};

struct arguments {
    enum ExecType exectype;
    int pid;
    int verbose;
    int wait;
    int resume;
    char* injectlibrary;
    char* command;
    char* entrypoint_name;
    char* entrypoint_parameter;
    char* parameter;
    std::vector<char*> arguments;
    std::vector<char*> env;
};

int inject(FridaDevice* device, struct arguments* arg);
int sync(FridaDevice* device, struct arguments* arg);
void wait_end_child(struct arguments* arg);


#endif /* _QBDInjector_hpp */
