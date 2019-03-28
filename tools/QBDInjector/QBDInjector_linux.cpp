#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "QBDInjector.hpp"


int sync(FridaDevice* device, struct arguments* arg) {
    return -1;
}


void wait_end_child(struct arguments* arg) {
    int res;
    while (0 == (res = kill(arg->pid, 0))) {
        usleep(10);
    }

    if (errno != ESRCH) {
        perror("[-] Error when wait end of child process");
    }

}
