
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "Injected.h"
#include "QBDInjector.h"


void __attribute__ ((visibility ("default")))
_qbdinjector_frida_entrypoint(const char* msg, bool* stay_resident) {

    *stay_resident = true;

    int res = qbdinjector_frida_earlyinit(msg, stay_resident);
    if (res)
        return;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

#ifdef _QBDI_DEBUG
    init_client(msg, 1);
#else
    init_client(msg, 0);
#endif
    open_pipe();
    int len_parameter;
    read_message((char*) &len_parameter, sizeof(len_parameter), false);
    char* parameter = malloc(len_parameter+1);
    if (parameter == NULL) {
        fprintf(stderr, "[-] Failled malloc\n");
        return;
    }
    read_message(parameter, len_parameter, false);
    parameter[len_parameter] = '\0';

    res = qbdinjector_frida_init(parameter);

    if (!(res & QBDINJECTOR_STOP) && res & QBDINJECTOR_INJECT) {
        return prepare_inject(res);
    } else {
        send_message((char*) &res, sizeof(res));
        close_pipe();
    }
}

