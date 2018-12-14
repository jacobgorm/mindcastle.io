
#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "block.h"
#include "block-swap.h"
#include "aio.h"
#include "ioh.h"

#if defined(_WIN32)
#include <windows.h>
DECLARE_PROGNAME;
#endif	/* _WIN32 */

static int fds[2];

static void io_done(void *opaque, int ret) {
    char msg;
    int r = write(fds[1], &msg, sizeof(msg));
    if (r != 1) {
        err(1, "write() failed\n");
    }
}

static void wait(void) {
    char msg;
    int r = read(fds[0], &msg, sizeof(msg));
    if (r != sizeof(msg)) {
        err(1, "pipe read failed");
    }
}

static void *disk_swap_thread(void *bs)
{
    for (;;) {
        aio_wait();
    }
    return NULL;
}

int main(int argc, char **argv)
{
#ifdef _WIN32
    setprogname(argv[0]);
#endif
    int r = pipe2(fds, O_DIRECT);
    if (r < 0) {
        errx(1, "pipe2 failed");
    }

    BlockDriverState bs;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <dst.swap> <trace>\n",
                argv[0]);
        exit(-1);
    }

    ioh_init();
    aio_init();

    const char *dst = argv[1];
    const char *trace = argv[2];
    FILE *tracefile = fopen(trace, "r");

    swap_open(&bs, dst, 0);
    pthread_t tid;
    pthread_create(&tid, NULL, disk_swap_thread, &bs);

    uint64_t sector;
    uint32_t len;
    uint64_t total = 0;

    for (;;) {
        if (fscanf(tracefile, "%lx %x\n", &sector, &len) == 2) {

            uint8_t *buf = malloc(512 * len);
            swap_aio_read(&bs, sector, buf, len, io_done, NULL);
            wait();
            swap_aio_write(&bs, sector, buf, len, io_done, NULL);
            wait();
            free(buf);
            total += len;
        } else {
            break;
        }
    }
    swap_flush(&bs);
    swap_close(&bs);
    printf("primed %lu MiB\n", total / 2);
    return 0;
}
