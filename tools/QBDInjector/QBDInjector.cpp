#include <iostream>
#include <vector>
#include <string>
#include <errno.h>
#include <argp.h>

#include "frida-core.h"

enum ExecType {
    NONE = 0,
    ATTACH,
    SPAWN
};

struct arguments {
    enum ExecType exectype;
    int pid;
    int verbose;
    char* injectlibrary;
    char* command;
    char* entrypoint_name;
    char* entrypoint_parameter;
    std::vector<char*> arguments;
    std::vector<char*> env;
};

char DEFAULT_ENTRYPOINT[] =  "_qbdinjector_entrypoint";

void help(int exit_value, char* arg0) __attribute__((noreturn));
void help(int exit_value, char* arg0) {
    char help_text[] =
        "%s [-v] [-n ENTRYPOINT] [-p ARG] -i INJECT-LIBRARY -a pid\n"
        "%s [-v] [-n ENTRYPOINT] [-p ARG] -i INJECT-LIBRARY [-e ENV_VARIABLE] -s command [arguments]\n"
        "\n"
        "inject a library in a process and call ENTRYPOINT\n"
        "\n"
        "    -e | --env                   Add a environment variable to the new processus\n"
        "    -n | --entrypoint-name       Set entrypoint (default : \"%s\")\n"
        "    -p | --entrypoint_parameter  Additionnal parameter passed to entrypoint\n"
        "    -i | --inject-library        Library to inject\n"
        "    -a | --attach                Inject library to a running process\n"
        "    -s | --spawn                 Create a nex process\n";
    if (exit_value == 0) {
        printf(help_text, arg0, arg0, DEFAULT_ENTRYPOINT);
    } else {
        fprintf(stderr, help_text, arg0, arg0, DEFAULT_ENTRYPOINT);
    }
    exit(exit_value);
}

struct arguments* parse_argv(int argc, char** argv) {
    struct arguments* arg = new struct arguments;
    int c;
    static struct option long_options[] = {
        {"spawn",                required_argument, 0, 's'},
        {"attach",               required_argument, 0, 'a'},
        {"inject-library",       required_argument, 0, 'i'},
        {"entrypoint-name",      required_argument, 0, 'n'},
        {"entrypoint-parameter", required_argument, 0, 'p'},
        {"env",                  required_argument, 0, 'e'},
        {"help",                 no_argument,       0, 'h'},
        {"verbose",              no_argument,       0, 'v'},
        {0}
    };
    int option_index = 0;

    arg->command = NULL;
    arg->entrypoint_name = NULL;
    arg->injectlibrary = NULL;
    arg->exectype = ExecType::NONE;
    arg->entrypoint_name = NULL;
    arg->entrypoint_parameter = NULL;
    arg->verbose = 0;

    while ((c = getopt_long (argc, argv, "a:s:i:n:p:e:hv", long_options, &option_index)) != -1) {
        switch (c) {
            case 's':
                if (arg->exectype != ExecType::NONE) {
                    fprintf(stderr, "--spawn and --attach cannot be use at the same time.\n");
                    help(1, argv[0]);
                }
                arg->exectype = ExecType::SPAWN;
                arg->command = optarg;
                // follow argument was argument for command, don't parse it
                while (argv[optind] != NULL) {
                    arg->arguments.push_back(argv[optind]);
                    optind++;
                }
                break;
            case 'a':
                char* end;
                if (arg->exectype != ExecType::NONE) {
                    fprintf(stderr, "--spawn and --attach cannot be use at the same time.\n");
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
                if (arg->entrypoint_parameter != NULL) {
                    fprintf(stderr, "--entrypoint_parameter can be use only once\n");
                    help(1, argv[0]);
                }
                arg->entrypoint_parameter = optarg;
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
            default:
                help(1, argv[0]);
        }
    }
    if (arg->exectype == ExecType::NONE) {
        fprintf(stderr, "Need --attach or --spawn\n");
        help(1, argv[0]);
    }

    if (arg->entrypoint_name == NULL) {
        arg->entrypoint_name = DEFAULT_ENTRYPOINT;
    }

    if (arg->entrypoint_parameter == NULL) {
        arg->entrypoint_parameter = strdup("");
    }

    return arg;
}

#define LOG1(...) if (arg->verbose >= 1) {fprintf(stderr, __VA_ARGS__);}
#define LOGE() \
    if (error != nullptr) { \
        fprintf(stderr, "[-] Error %s:%d: %s\n", __FILE__, __LINE__, error->message); \
        g_error_free(error); \
        return 1; \
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
    pid_t pid = frida_device_spawn_sync(device, arg->command, options, &error);
    LOGE();
    LOG1("[+] pid %d\n", pid);

    LOG1("[+] Inject lib %s and call %s(\"%s\")\n", arg->injectlibrary, arg->entrypoint_name, arg->entrypoint_parameter);

    frida_device_inject_library_file_sync(device, pid, arg->injectlibrary, arg->entrypoint_name,  arg->entrypoint_parameter, &error);
    LOGE();

    LOG1("[+] Attach...\n");
    FridaSession* session = frida_device_attach_sync(device, pid, &error);
    LOGE();

    frida_session_enable_child_gating_sync(session, &error);
    LOGE();
    LOG1("[+] Done\n");
    frida_device_resume_sync(device, pid, &error);
    LOGE();
    frida_session_detach_sync(session);
    LOGE();
    frida_unref(session);
    LOGE();
    frida_unref(device);
    LOGE();
    frida_device_manager_close_sync(manager);
    LOGE();
    frida_unref (manager);
    LOGE();
    return 0;
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


int main(int argc, char** argv) {
    struct arguments* arg = parse_argv(argc, argv);
    int res = 0;

    frida_init();

    if (arg->exectype == ExecType::ATTACH) {
        res = attach(arg);
    } else if (arg->exectype == ExecType::SPAWN) {
        res = spawn(arg);
    }

    frida_deinit();

    delete arg;
    return res;
}
