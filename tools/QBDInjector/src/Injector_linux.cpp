#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "Injector.h"
#include "QBDInjector_linux.h"

namespace QBDInjector {

void wait_end_child(Arguments* arg) {
    int res;
    while (0 == (res = kill(arg->pid, 0))) {
        usleep(100);
    }

    if (errno != ESRCH) {
        perror("[-] Error when wait end of child process");
    }
}

int sync(FridaDevice* device, Arguments* arg) {
    // need to create a pipe to communicate with child process (problem with ptrace and frida)

    GError* error = nullptr;

    LOG1("[+] create pipe\n")
    arg->entrypoint_parameter = init_server(arg->verbose);
    LOG1("[+] Inject lib %s and call %s(\"%s\")\n", arg->injectlibrary, arg->entrypoint_name, arg->entrypoint_parameter);
    inject(device, arg);
    LOG1("[+] connect to pipe\n");
    open_pipe();

    LOG1("[+] Send parameter : %s\n", arg->parameter);
    int len_parameter = strlen(arg->parameter) + 1;
    send_message((char*) &len_parameter, sizeof(len_parameter));
    send_message(arg->parameter, len_parameter);

    int result_user_init;
    read_message((char*) &result_user_init, sizeof(result_user_init), false);

    if (result_user_init & QBDINJECTOR_STOP) {
        arg->wait = false;
        arg->resume = false;
        LOG1("[+] Received stop message, immediatly exit\n");
        frida_device_kill_sync(device, arg->pid, &error);
        LOGE();
        close_pipe();
        return 0;
    }

    // receive this before stop the process, the thread will be affected by the signal
    QBDI::rword new_addr;
    QBDI::rword new_stack;
    read_message((char*) &new_addr, sizeof(QBDI::rword), false);
    read_message((char*) &new_stack, sizeof(QBDI::rword), false);
    printf("[+] new addr : 0x%lx\n", new_addr);
    printf("[+] new stack : 0x%lx\n", new_stack);

    // send stop signal to process
    LOG1("[+] Stop process and detach ptrace of frida\n");
    kill(arg->pid, SIGSTOP);

    // detach ptrace of frida, process will be stopped by the signal
    frida_device_resume_sync(device, arg->pid, &error);
    LOGE();

    // resume isn't done in spawn method
    LOG1("[+] Attach and retrived internal state\n")
    arg->resume = false;
    if (ptrace(PTRACE_ATTACH, arg->pid, NULL, NULL)) {
        perror("[-] ptrace failled to attach");
        frida_device_kill_sync(device, arg->pid, &error);
        LOGE();
        close_pipe();
        exit(1);
    }


    // get entrypoint and his value
    struct user_regs_struct regs, origin_regs;
    user_floatingregister_struct origin_fregs;

    ptrace(PTRACE_GETREGS, arg->pid, NULL, &origin_regs);
    ptrace(QBDI_PTRACE_GETFREG, arg->pid, NULL, &origin_fregs);

    memcpy(&regs, &origin_regs, sizeof(struct user_regs_struct));

#if defined(QBDI_ARCH_X86_64)
    QBDI::rword origin_addr = regs.rip;
    QBDI::rword origin_stack = regs.rsp;
    regs.rip = new_addr;
    regs.rsp = new_stack;
#else
#error "Not Implemented"
#endif

    printf("[+] origin addr : 0x%lx\n", origin_addr);
    printf("[+] origin stack : 0x%lx\n", origin_stack);

    LOG1("[+] Set new internal state\n");
    ptrace(PTRACE_SETREGS, arg->pid, NULL, &regs);

    LOG1("[+] Detach and send resume signal\n");
    ptrace(PTRACE_DETACH, arg->pid, NULL, NULL);
    kill(arg->pid, SIGCONT);

    LOG1("[+] Send register state\n");
    int len = sizeof(origin_regs);
    send_message((char*) &len, sizeof(len));
    send_message((char*) &origin_regs, len);

    len = sizeof(origin_fregs);
    send_message((char*) &len, sizeof(len));
    send_message((char*) &origin_fregs, len);

    close_pipe();
    return 0;
}

}
