#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "QBDInjector_common.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>


#define LOG1(fmt, ...) if (ctx.verbose >= 1) { \
    fprintf(stderr, fmt, (ctx.server? "server:":"client:") __VA_OPT__(,) __VA_ARGS__ );\
}

#define LOG1_dump(fmt, buf, len, ...) if (ctx.verbose >= 1) { \
    char* msg; \
    asprintf(&msg, fmt, (ctx.server? "server:":"client:") __VA_OPT__(,) __VA_ARGS__ );\
    int blen = strlen(msg) + len*3 + 2; \
    msg = realloc(msg, blen); \
    for (int i = 0; i<len; i++) { \
        char *tmp; \
        asprintf(&tmp, " %02x", (unsigned char) buf[i]); \
        strncat(msg, tmp, 3); \
        free(tmp); \
    } \
    fprintf(stderr, "%s\n", msg);\
    free(msg);\
}

static struct {
    char* named_pipe;
    char* named_read;
    char* named_write;
    bool server;
    int fd_read;
    int fd_write;
    int verbose;
} ctx = {0};

char* init_server(int verbose) {
    ctx.verbose = verbose;
    ctx.server = true;
    ctx.named_pipe = mkdtemp(strdup("/tmp/QBDInjector_XXXXXX"));

    if (asprintf(&ctx.named_read, "%s/1", ctx.named_pipe) == -1 ||
            asprintf(&ctx.named_write, "%s/2", ctx.named_pipe) == -1) {
        fprintf(stderr, "Failled to malloc\n");
        exit(1);
    }

    LOG1("[+] %s Create fifo %s and %s\n", ctx.named_read, ctx.named_write);
    if (mkfifo(ctx.named_read, S_IRUSR | S_IWUSR) != 0 ||
            mkfifo(ctx.named_write, S_IRUSR | S_IWUSR) != 0) {
        perror("[-] Cannot create pipe");
        exit(1);
    }
    return strdup(ctx.named_pipe);
}

void init_client(const char* pipename, int verbose) {
    ctx.verbose = verbose;
    ctx.server = false;
    ctx.named_pipe = NULL;
    if (asprintf(&ctx.named_write, "%s/1", pipename) == -1 ||
            asprintf(&ctx.named_read, "%s/2", pipename) == -1) {
        fprintf(stderr, "Failled to malloc\n");
        exit(1);
    }
}

void open_pipe() {
    if (ctx.server) {
        LOG1("[+] %s Connect to fifo %s\n", ctx.named_read);
        ctx.fd_read = open(ctx.named_read, O_RDONLY);
        LOG1("[+] %s Connect to fifo %s\n", ctx.named_write);
        ctx.fd_write = open(ctx.named_write, O_WRONLY);
    } else {
        LOG1("[+] %s Connect to fifo %s\n", ctx.named_write);
        ctx.fd_write = open(ctx.named_write, O_WRONLY);
        LOG1("[+] %s Connect to fifo %s\n", ctx.named_read);
        ctx.fd_read = open(ctx.named_read, O_RDONLY);
    }
}

void close_pipe() {
    LOG1("[+] %s Close pipe\n");
    close(ctx.fd_write);
    close(ctx.fd_read);

    if (ctx.server) {
        LOG1("[+] %s Remove pipe\n");
        remove(ctx.named_write);
        remove(ctx.named_read);
        rmdir(ctx.named_pipe);
        free(ctx.named_pipe);
        ctx.named_pipe = NULL;
    }
    free(ctx.named_write);
    ctx.named_write = NULL;
    free(ctx.named_read);
    ctx.named_read = NULL;
}

void send_message(char* buf, size_t len) {

    uint32_t nb_write = 0;
    LOG1_dump("[+] %s write %lu :", buf, len, len);
    while (nb_write < len) {
        int rret = write(ctx.fd_write,  buf + nb_write, len - nb_write);
        if (rret < 0) {
            perror("[-] fail to write");
            exit(1);
        }
        if (rret == 0) {
            fprintf(stderr, "[-] EOF before end of write pipe\n");
            exit(1);
        }
        nb_write += rret;
    }
}

ssize_t read_message(char *buf, size_t len, bool allow_EOF) {
    uint32_t nb_read = 0;
    while (nb_read < len) {
        int rret = read(ctx.fd_read, buf + nb_read, len - nb_read);
        if (rret < 0) {
            close_pipe();
            perror("[-] fail to read");
            exit(1);
        }
        if (rret == 0) {
            // pipe was closed by the remote, clean and exit|return
            close_pipe();
            if (!allow_EOF) {
                fprintf(stderr, "[-] EOF before end of read pipe\n");
                exit(1);
            }
            return nb_read;
        }
        nb_read += rret;
    }
    LOG1_dump("[+] %s read %u :", buf, nb_read, nb_read);
    return nb_read;
}
