#include <stdio.h>
#include <windows.h>

#include "Injector.h"

namespace QBDInjector {

void wait_end_child(Arguments* arg) {
     HANDLE h = OpenProcess(SYNCHRONIZE, TRUE, arg->pid);
     WaitForSingleObject(h, INFINITE );
}

int setup_inject(FridaDevice* device, Arguments* arg) {
    arg->resume = true;
    return 0;
}

}
