
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/nbd.h>
#include <linux/types.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "aio.h"
#include "block-swap.h"
#include "ioh.h"
#include "tinyuuid.h"
#include "safeio.h"

extern void dump_swapstat(void);

static FILE *tracefile = NULL;

static int should_exit = 0;
static int should_close = 0;
static int can_exit = 0;
static int snapshot_requested = 0;

struct sock_info {
    int sock;
};

struct BlockDriverState;
struct client_info {
    struct BlockDriverState *bs;
    int sock;
};

struct read_info {
    int sock;
    uint8_t *buffer;
    int len;
    struct nbd_reply reply;
};

struct flush_info {
    int sock;
    struct nbd_reply reply;
};

struct snapshot_info {
    struct BlockDriverState *bs;
    char *script;
    int sock;
};

static void got_data(void *opaque);

static BlockDriverState bs;
static ioh_event exit_event;
static ioh_event close_event;
static ioh_event snapshot_event;
static ioh_event flushed_event;

static pid_t shell(char *arg, ...) {

    pid_t child = fork();
    if (!child) {
        char *list[16];
        int l = 0;
        va_list ap;
        va_start(ap, arg);
        char *a = arg;
        while (a) {
            list[l++] = a;
            a = va_arg(ap, char *);
        }
        va_end(ap);
        list[l] = NULL;
        char *rp = realpath(list[0], NULL);
        if (!rp) {
            err(1, "realpath failed for %s", list[0]);
        }
        if (execvp(rp, list)) {
            err(1, "execvp error");
        }
        exit(0);
    } else {
        return child;
    }
}

static void nbd_read_done(void *opaque, int ret) {
    (void) ret;
    int r;
    struct read_info *ri = opaque;

    r = safe_write(ri->sock, &ri->reply, sizeof(ri->reply));
    if (r != sizeof(ri->reply)) {
        err(1, "sock write (a) failed, sock=%d", ri->sock);
    }

    r = safe_write(ri->sock, ri->buffer, ri->len);
    if (r != ri->len) {
        err(1, "sock write (b) failed, sock=%d", ri->sock);
    }

    free(ri->buffer);
    free(ri);
}

static void nbd_write_done(void *buffer, int ret) {
    (void) ret;
    free(buffer);
}

static void nbd_flush_done(void *opaque, int ret) {
    (void) ret;
    struct flush_info *fi = opaque;
    int r = safe_write(fi->sock, &fi->reply, sizeof(fi->reply));
    if (r != sizeof(fi->reply)) {
        err(1, "sock write (c) failed, sock=%d", fi->sock);
    }
    free(fi);
}

static void nbd_final_flush_done(void *opaque, int ret) {
    (void) ret;
    ioh_event *event = (ioh_event *) opaque;
    ioh_event_set(event);
}

static void nbd_snapshot_flush_done(void *opaque, int ret) {
    (void) ret;
    struct snapshot_info *si = opaque;
    (void) si;

    uuid_t uuid;
    char uuid_str[37];
    swap_snapshot(si->bs, uuid);
    tiny_uuid_unparse(uuid, uuid_str);

    aio_resume_wait_object(si->sock);

    setenv("SNAPSHOT_UUID", uuid_str, 1);
    shell(si->script, "snapshot", NULL);
    free(si);
}


static void got_data(void *opaque)
{
    struct client_info *ci = opaque;
    struct nbd_request request;
    struct nbd_reply reply = {};
    int r;

    r = safe_read(ci->sock, &request, sizeof(request));
    if (r == sizeof(request)) {
        memcpy(reply.handle, request.handle, sizeof(reply.handle));
        reply.magic = htonl(NBD_REPLY_MAGIC);
        reply.error = htonl(0);
        if (request.magic != htonl(NBD_REQUEST_MAGIC)) {
            printf("skipping request with bad magic %x\n", htonl(request.magic));
            return;
        }
        switch(ntohl(request.type)) {

            case NBD_CMD_FLUSH: {
                struct flush_info *fi = malloc(sizeof(struct read_info));
                fi->sock = ci->sock;
                fi->reply = reply;
                swap_flush(ci->bs, nbd_flush_done, fi);
                break;
            }

            case NBD_CMD_DISC: {
                printf("got disc\n");
                break;
            }

            case NBD_CMD_READ: {
                int len = ntohl(request.len);
                uint64_t offset =  be64toh(request.from);
                struct read_info *ri = malloc(sizeof(struct read_info));
                ri->sock = ci->sock;
                ri->buffer = malloc(len);
                ri->len = len;
                ri->reply = reply;

                if (tracefile) {
                    fprintf(tracefile, "%" PRIx64 " %x\n", offset / 512, len / 512);
                }
                swap_aio_read(ci->bs, offset / 512, ri->buffer, len / 512, nbd_read_done, ri);
                break;
            }

            case NBD_CMD_WRITE: {
                r = safe_write(ci->sock, &reply, sizeof(reply));
                int len = ntohl(request.len);
                uint8_t *buffer = malloc(len);
                uint64_t offset = be64toh(request.from);
                uint8_t *b;
                int left;

                for (left = len, b = buffer; left > 0; b += r, left -= r)  {
                    r = safe_read(ci->sock, b, left);
                    if (r < 0) {
                        err(1, "sock read failed");
                    }
                }
                swap_aio_write(ci->bs, offset / 512, buffer, len / 512, nbd_write_done, buffer);
                break;
            }

            case NBD_CMD_TRIM: {
                r = safe_write(ci->sock, &reply, sizeof(reply));
                int len = ntohl(request.len);
                uint64_t offset = be64toh(request.from);
                uint8_t *zero = calloc(1, len);
                swap_aio_write(ci->bs, offset / 512, zero, len / 512, nbd_write_done, zero);
                break;
            }

            default: {
                printf("default %x\n", ntohl(request.type));
                r = safe_write(ci->sock, &reply, sizeof(reply));
                if (r != sizeof(reply)) {
                    err(1, "sock write (d) failed");
                }
                break;
            }
        };
    }
}

static void close_event_cb(void *opaque)
{
    int *pi = opaque;
    *pi = 1;
}

static void signal_handler(int s)
{
    if (s == SIGINT) {
        ioh_event_set(&exit_event);
    } else if (s == SIGHUP) {
        ioh_event_set(&close_event);
    } else if (s == SIGUSR1) {
        ioh_event_set(&snapshot_event);
    } else if (s == SIGCHLD) {
        int wstatus;
        wait(&wstatus);
        if (WIFSIGNALED(wstatus)) {
            printf("child signaled with %u\n", WTERMSIG(wstatus));
            exit(1);
        }
    }
}

int main(int argc, char **argv)
{
    int r;
    uint64_t size_gb = 100;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s [filename.swap] [statechange-script]\n", argv[0]);
        exit(1);
    }

    --argc;
    ++argv;

    if (argc >= 4 && !strcmp(argv[0], "-t")) {
        printf("writing read-trace to %s\n", argv[1]);
        tracefile = fopen(argv[1], "w");
        argc -= 2;
        argv += 2;
    }

    if (argc >= 4 && !strcmp(argv[0], "-s")) {
        size_gb = atoll(argv[1]);
        argc -= 2;
        argv += 2;
    }

    char *script = argv[1];

    shell("/sbin/modprobe", "nbd", NULL);

    r = mlockall(MCL_CURRENT | MCL_FUTURE);
    if (r < 0) {
        err(1, "mlockall failed");
    }

    char *fn = argv[0];

    printf("opening swapimage %s...\n", fn);
    aio_global_init();

    int needs_format = 0;
    if (!file_exists(fn)) {
        r = swap_create(fn, size_gb << 30ULL, 0);
        if (r < 0) {
            printf("error creating %s\n", fn);
            exit(1);
        }
        needs_format = 1;
    }
    r = swap_open(&bs, fn, 0);
    if (r < 0) {
        printf("error opening %s\n", fn);
        exit(1);
    }

    int sp[2];
    int sp2[2];
    r = socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    if (r) {
        err(1, "socketpair (a) failed");
    }

    r = socketpair(AF_UNIX, SOCK_STREAM, 0, sp2);
    if (r) {
        err(1, "socketpair (b) failed");
    }

    char dev[32];
    int device;
    pid_t child = -1;
    for (int i = 0; ; ++i) {
        sprintf(dev, "/dev/nbd%u", i);
        device = open(dev, O_RDWR);
        if (device < 0) {
            err(1, "nbd device open failed for %s", dev);
        }

        int ok = 0;
        child = fork();
        if (child == 0) {
            printf("connecting to %s...\n", dev);
            close(sp[0]);
            if (ioctl(device, NBD_SET_SOCK, sp[1]) == -1){
                fprintf(stderr, "NBD_SET_SOCK on %s failed %s\n", dev, strerror(errno));
                ok = 0;
                r = safe_write(sp2[1], &ok, sizeof(ok));
                exit(1);
            } else {
                ok = 1;
                r = safe_write(sp2[1], &ok, sizeof(ok));

                r = ioctl(device, NBD_SET_BLKSIZE, 512);
                if (r) {
                    err(1, "device ioctl (b) failed");
                }

                size_t swap_size = 0;
                r = swap_getsize(&bs, &swap_size);
                if (r< 0) {
                    errx(1, "swap_getsize failed!");
                }

                r = ioctl(device, NBD_SET_SIZE_BLOCKS, swap_size / 512);
                if (r) {
                    err(1, "device ioctl (a) failed");
                }

                r = ioctl(device, NBD_SET_TIMEOUT, 120);
                if (r) {
                    err(1, "device ioctl (c) failed");
                }

                r = ioctl(device, NBD_SET_FLAGS, NBD_FLAG_SEND_FLUSH); // || NBD_FLAG_SEND_TRIM);
                if (r) {
                    err(1, "device ioctl (c) failed");
                }

                r = ioctl(device, NBD_DO_IT);
                fprintf(stderr, "nbd device terminated %d\n", r);
                if (r == -1) {
                    fprintf(stderr, "%s\n", strerror(errno));
                }
                ioctl(device, NBD_CLEAR_QUE);
                ioctl(device, NBD_CLEAR_SOCK);
                exit(0);
            }
        }

        r = safe_read(sp2[0], &ok, sizeof(ok));
        if (r != sizeof(ok)) {
            err(1, "socket pair read failed");
        }
        if (ok) {
            break;
        }
    }
    printf("configuring %s using %s\n", dev, script);

    struct client_info *ci = malloc(sizeof(struct client_info));
    ci->sock = sp[0];
    ci->bs = &bs;
    aio_add_wait_object(ci->sock, got_data, ci);

    uuid_t uuid;
    swap_ioctl(&bs, 0, uuid);
    char uuid_str[37];
    tiny_uuid_unparse(uuid, uuid_str);

    char pid_str[16];
    sprintf(pid_str, "%d", getpid());

    setenv("DEVICE", dev, 1);
    setenv("UUID", uuid_str, 1);
    setenv("PID", pid_str, 1);

    ioh_event_init(&close_event, close_event_cb, &should_close);
    ioh_event_init(&exit_event, close_event_cb, &should_exit);
    ioh_event_init(&flushed_event, close_event_cb, &can_exit);
    ioh_event_init(&snapshot_event, close_event_cb, &snapshot_requested);

    struct sigaction sig;
    sig.sa_handler = signal_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;
    for (int i = 1; i < 31; ++i) {
        switch (i) {
            case SIGHUP:
            case SIGINT:
            case SIGUSR1:
            case SIGCHLD:
                sigaction(i, &sig, NULL);
                break;
            default:
                /* some versions of linux will disconnect nbd
                 * if getting signalled, so ignore as many as we can. */
                signal(i, SIG_IGN);
                break;
        }
    }


    shell(script, needs_format ? "create" : "open", NULL);

    while (!can_exit) {
        aio_wait();
        if (should_close) {
            shell(script, "close", NULL);
            should_close = 0;
        }
        if (should_exit) {
            swap_flush(&bs, nbd_final_flush_done, &flushed_event);
            should_exit = 0;
        }
        if (snapshot_requested) {
            struct snapshot_info *si = malloc(sizeof(struct snapshot_info));
            si->bs = &bs;
            si->script = script;
            si->sock = ci->sock;

            aio_suspend_wait_object(ci->sock);
            swap_flush(&bs, nbd_snapshot_flush_done, si);
            snapshot_requested = 0;
        }
    }
    ioctl(device, NBD_DISCONNECT);
    ioctl(device, NBD_CLEAR_SOCK);
    int wstatus;
    waitpid(child, &wstatus, 0);

    dump_swapstat();
    swap_close(&bs);
    return 0;
}
