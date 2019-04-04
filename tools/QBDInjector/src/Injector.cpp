
#include "Injector.h"

#include <iostream>
#include <argp.h>
#include <unistd.h>
#include <errno.h>


namespace QBDInjector {

const char DEFAULT_ENTRYPOINT[] =  "entrypoint";

void help(int exit_value, char* arg0) __attribute__((noreturn));
void help(int exit_value, char* arg0) {
    const char help_text[] =
        "%1$s [-v] [-p ARG] -i INJECT-LIBRARY [-n ENTRYPOINT] -a pid\n"
        "%1$s [-v] [-p ARG] -i INJECT-LIBRARY [-n ENTRYPOINT] [-q|-r|-w] [-e ENV_VARIABLE] -S command [arguments]\n"
        "%1$s [-v] [-p ARG] -i INJECT-LIBRARY [-e ENV_VARIABLE] -s command [arguments]\n"
        "\n"
        "inject a library in a process and call ENTRYPOINT\n"
        "\n"
        "Main options:\n"
        "    -a | --attach                Inject library to a running process\n"
        "    -S | --spawn                 Create a nex process\n"
        "    -s | --sync                  Create and sync with a new process\n"
        "\n"
        "Generic arguments (available for all main option):\n"
        "    -h | --help                  Show this help\n"
        "    -i | --inject-library        Library to inject\n"
        "    -p | --parameter             Additionnal parameter passed to entrypoint\n"
        "    -v | --verbose               Enable verbose log of QBDInjector\n"
        "\n"
        "Others arguments:\n"
        "    -e | --env                   Add a environment variable to the new processus (only with -s|-S)\n"
        "    -n | --entrypoint-name       Set entrypoint (default : \"%2$s\") (only with -a|-S)\n"
        "    -q | --quit                  Don't resume and wait the process to terminated (only with -S)\n"
        "    -r | --resume                Resume the process but don't wait (only with -S)\n"
        "    -w | --wait                  Resume and wait the process (only with -S) (default)\n";

    if (exit_value == 0) {
        printf(help_text, arg0, DEFAULT_ENTRYPOINT);
    } else {
        fprintf(stderr, help_text, arg0, DEFAULT_ENTRYPOINT);
    }

    exit(exit_value);
}

struct arguments* parse_argv(int argc, char** argv) {
    struct arguments* arg = new struct arguments;
    int c;
    static struct option long_options[] = {
        {"attach",               required_argument, 0, 'a'},
        {"spawn",                required_argument, 0, 'S'},
        {"sync",                 required_argument, 0, 's'},

        {"inject-library",       required_argument, 0, 'i'},
        {"entrypoint-parameter", required_argument, 0, 'p'},
        {"verbose",              no_argument,       0, 'v'},
        {"help",                 no_argument,       0, 'h'},

        {"entrypoint-name",      required_argument, 0, 'n'},
        {"env",                  required_argument, 0, 'e'},
        {"quit",                 no_argument,       0, 'q'},
        {"resume",               no_argument,       0, 'r'},
        {"wait",                 no_argument,       0, 'w'},
        {0}
    };
    int option_index = 0;

    arg->command = NULL;
    arg->entrypoint_name = NULL;
    arg->injectlibrary = NULL;
    arg->exectype = ExecType::NONE;
    arg->entrypoint_name = NULL;
    arg->parameter = NULL;
    arg->verbose = 0;
    arg->wait = true;
    arg->resume = true;

    while ((c = getopt_long (argc, argv, "a:s:S:i:n:p:e:hvqrw", long_options, &option_index)) != -1) {
        switch (c) {
            case 'S':
            case 's':
                if (arg->exectype != ExecType::NONE) {
                    fprintf(stderr, "--attach, --spawn and --sync are mutually incompatible.\n");
                    help(1, argv[0]);
                }
                if (c == 'S') {
                    arg->exectype = ExecType::SPAWN;
                } else {
                    arg->exectype = ExecType::SYNC;
                }
                arg->command = optarg;
                // follow argument were command arguments, don't parse it
                while (argv[optind] != NULL) {
                    arg->arguments.push_back(argv[optind]);
                    optind++;
                }
                break;
            case 'a':
                char* end;
                if (arg->exectype != ExecType::NONE) {
                    fprintf(stderr, "--attach, --spawn and --sync are mutually incompatible.\n");
                    help(1, argv[0]);
                }
                arg->exectype = ExecType::ATTACH;
                arg->pid = strtol(optarg, &end, 10);
                if (*end != '\0') {
                    fprintf(stderr, "--attach need a pid number\n");
                    help(1, argv[0]);
                }
                break;
            case 'i':
                if (arg->injectlibrary != NULL) {
                    fprintf(stderr, "--inject-library can be use only once\n");
                    help(1, argv[0]);
                }
                arg->injectlibrary = optarg;
                break;
            case 'n':
                if (arg->entrypoint_name != NULL) {
                    fprintf(stderr, "--entrypoint-name can be use only once\n");
                    help(1, argv[0]);
                }
                arg->entrypoint_name = optarg;
                break;
            case 'p':
                if (arg->parameter != NULL) {
                    fprintf(stderr, "--parameter can be use only once\n");
                    help(1, argv[0]);
                }
                arg->parameter = optarg;
                break;
            case 'e':
                arg->env.push_back(optarg);
                break;
            case 'h':
                help(0, argv[0]);
                break;
            case 'v':
                arg->verbose++;
                break;
            case 'q':
                arg->wait = false;
                arg->resume = false;
                break;
            case 'r':
                arg->wait = false;
                arg->resume = true;
                break;
            case 'w':
                arg->wait = true;
                arg->resume = true;
                break;
            default:
                help(1, argv[0]);
        }
    }
    if (arg->exectype == ExecType::NONE) {
        fprintf(stderr, "Need --attach,--spawn or --sync\n");
        help(1, argv[0]);
    }

    if (arg->exectype == ExecType::SYNC) {
        if (arg->entrypoint_name != NULL) {
            fprintf(stderr, "Cannot use --entrypoint_name with --sync\n");
            help(1, argv[0]);
        }
        arg->entrypoint_name = strdup(ENTRYPOINT_NAME);
    }

    if (arg->entrypoint_name == NULL) {
        arg->entrypoint_name = strdup(DEFAULT_ENTRYPOINT);
    }

    if (arg->parameter == NULL) {
        arg->parameter = strdup("");
    }

    arg->entrypoint_parameter = arg->parameter;

    return arg;
}

int inject(FridaDevice* device, struct arguments* arg) {
    GError* error = nullptr;
    frida_device_inject_library_file_sync(device, arg->pid, arg->injectlibrary, arg->entrypoint_name,  arg->entrypoint_parameter, &error);
    LOGE();
    return 0;
}

int sync(FridaDevice* device, struct arguments* arg) {

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

    arg->wait = result_user_init & QBDINJECTOR_WAIT;
    if (result_user_init & QBDINJECTOR_INJECT) {
        setup_inject(device, arg);
    }

    close_pipe();
    return 0;
}

int spawn(struct arguments* arg) {
    GError* error = nullptr;
    FridaDeviceManager* manager = frida_device_manager_new();
    FridaDevice* device = frida_device_manager_get_device_by_type_sync(manager, FRIDA_DEVICE_TYPE_LOCAL, 0, NULL, &error);
    LOGE();

    FridaSpawnOptions* options = frida_spawn_options_new();
    frida_spawn_options_set_stdio(options, FRIDA_STDIO_INHERIT);

    { // set ARGV
        gchar** argv = new gchar*[arg->arguments.size() + 1];
        argv[0] = arg->command;
        for (unsigned int i = 0; i < arg->arguments.size(); i++) {
            argv[i+1] = arg->arguments[i];
        }
        frida_spawn_options_set_argv(options, argv, arg->arguments.size() + 1);

        delete argv;
    }

    if (arg->env.size() != 0) { // set envp
        gchar** envp = new gchar*[arg->env.size()];
        for (unsigned int i = 0; i < arg->env.size(); i++) {
            envp[i] = arg->env[i];
        }
        frida_spawn_options_set_envp(options, envp, arg->env.size());

        delete envp;
    }

    LOG1("[+] Spawn\n");
    arg->pid = frida_device_spawn_sync(device, arg->command, options, &error);
    LOGE();
    LOG1("[+] pid %d\n", arg->pid);

    LOG1("[+] Attach...\n");
    FridaSession* session = frida_device_attach_sync(device, arg->pid, &error);
    LOGE();
    frida_session_enable_child_gating_sync(session, &error);
    LOGE();

    int ret;
    if (arg->exectype == ExecType::SPAWN) {
        LOG1("[+] Inject lib %s and call %s(\"%s\")\n", arg->injectlibrary, arg->entrypoint_name, arg->entrypoint_parameter);
        ret = inject(device, arg);
    } else {
        ret = sync(device, arg);
    }

    if (!ret && arg->resume) {
        LOG1("[+] Resume\n");
        frida_device_resume_sync(device, arg->pid, &error);
        LOGE();
    }

    if (!frida_session_is_detached(session)) {
        LOG1("[+] Detach\n");
        frida_session_detach_sync(session);
        LOGE();
    }

    frida_unref(session);
    LOGE();
    frida_unref(device);
    LOGE();
    frida_device_manager_close_sync(manager);
    LOGE();
    frida_unref (manager);
    LOGE();

    if (!ret && arg->wait) {
        wait_end_child(arg);
    }

    return ret;
}


int attach(struct arguments* arg) {
    GError* error = nullptr;

    FridaInjector* injector = frida_injector_new();

    LOG1("[+] Attach %d\n", arg->pid);
    LOG1("[+] Inject lib %s and call %s(%s)\n", arg->injectlibrary, arg->entrypoint_name, arg->entrypoint_parameter);
    frida_injector_inject_library_file_sync(injector, arg->pid, arg->injectlibrary, arg->entrypoint_name,  arg->entrypoint_parameter, &error);
    LOGE();
    LOG1("[+] Done\n");

    frida_injector_close_sync(injector);
    LOGE();

    g_object_unref(injector);
    return 0;
}


extern "C" {
int main(int argc, char** argv) {
    struct arguments* arg = parse_argv(argc, argv);
    int res = 0;

    frida_init();

    if (arg->exectype == ExecType::ATTACH) {
        res = attach(arg);
    } else {
        res = spawn(arg);
    }

    frida_deinit();

    delete arg;
    return res;
}
}

}