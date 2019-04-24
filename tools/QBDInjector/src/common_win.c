#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "QBDInjector_common.h"

#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <windows.h>


#define LOG1(fmt, ...) if (ctx.verbose >= 1) { \
    fprintf(stderr, fmt, (ctx.server? "server:":"client:"), __VA_ARGS__ );\
}

#define LOG1_dump(fmt, buf, len, ...) if (ctx.verbose >= 1) { \
    int slen = snprintf(NULL, 0 , fmt, (ctx.server? "server:":"client:"), __VA_ARGS__ );\
    int blen = slen + len*3 + 2; \
    char* msg = (char*) malloc(blen); \
    if (msg == NULL) { \
        fprintf(stderr, "[-] fail malloc\n"); \
        exit(1); \
    } \
    slen = snprintf(msg, blen, fmt, (ctx.server? "server:":"client:"), __VA_ARGS__ );\
    for (int i = 0; i<len; i++) { \
        slen += snprintf(msg + slen, 4, " %02x", (unsigned char) buf[i]); \
    } \
    fprintf(stderr, "%s\n", msg);\
    free(msg);\
}

static struct _ctx {
    HANDLE Pipe;
    bool server;
    int verbose;

} ctx = {0};

char* init_server(int verbose) {
    ctx.verbose = verbose;
    ctx.server = true;
    srand(time(NULL));
    char named_pipe[256];
    snprintf(named_pipe, 256, "\\\\.\\pipe\\QBDInjector_%d", rand());

    LOG1("[+] %s Create NamedPipe %s\n", named_pipe);
    ctx.Pipe = CreateNamedPipe( TEXT(named_pipe),
                                PIPE_ACCESS_DUPLEX,
                                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                1,
                                2 * sizeof(__int64),
                                2 * sizeof(__int64),
                                0,
                                NULL);
    if (ctx.Pipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Failled to create namedPipe. GLE=%d\n", GetLastError());
        exit(1);
    }
    return strdup(named_pipe);
}

void init_client(const char* pipename, int verbose) {
    ctx.verbose = verbose;
    ctx.server = false;
    LOG1("[+] %s Connect to NamedPipe %s\n", pipename);
    ctx.Pipe = CreateFile(  TEXT(pipename),
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
    if (ctx.Pipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Failled to create namedPipe. GLE=%d\n", GetLastError());
        exit(1);
    }
}

void open_pipe() {
    if (ctx.server) {
        LOG1("[+] %s Connect to Named Pipe \n");
        if (ConnectNamedPipe(ctx.Pipe, NULL) == FALSE) {
            fprintf(stderr, "[-] Failled to connect to Named Pipe. GLE=%d\n", GetLastError());
            exit(1);
        }
    } else {
        // already connected
    }
}

void close_pipe() {
    LOG1("[+] %s Close pipe\n");
    CloseHandle(ctx.Pipe);
}

void send_message(char* buf, size_t len) {

    LOG1_dump("[+] %s write %zu :", buf, len, len);
    if (!WriteFile(ctx.Pipe, buf, len, NULL, NULL)) {
        fprintf(stderr, "[-] Error when writting Pipe. GLE : %d\n", GetLastError());
        exit(1);
    }
}

int read_message(char *buf, size_t len, bool allow_EOF) {
    int nb_read = 0;
    if (!ReadFile(ctx.Pipe, buf, len, &nb_read, NULL)) {
        int GLE = GetLastError();
        if (!allow_EOF || GLE != ERROR_BROKEN_PIPE) {
            fprintf(stderr, "[-] Error when reading Pipe. GLE : %d\n", GLE);
            exit(1);
        }
    }
    LOG1_dump("[+] %s read %u :", buf, nb_read, nb_read);
    return nb_read;
}
