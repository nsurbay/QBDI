#include <stdio.h>
#include <windows.h>

#include "Injector.h"

namespace QBDInjector {

void wait_end_child(Arguments* arg) {
     HANDLE h = OpenProcess(SYNCHRONIZE, TRUE, arg->pid);
     WaitForSingleObject(h, INFINITE );
}

int gum(FridaDevice* device, Arguments* arg) {
    return sync(device, arg);
}

int sync(FridaDevice* device, Arguments* arg) {

    GError* error = nullptr;

    LOG1("[+] Inject lib %s and call %s(\"%s\")\n", arg->injectlibrary, arg->entrypoint_name, arg->entrypoint_parameter);
    inject(device, arg);

    // injected library will resume the thread
    arg->resume = false;
    return 0;
}

}
