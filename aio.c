#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "ioh.h"

typedef struct AioEntry {
    int fd;
    void (*cb) (void *opaque);
    void *opaque;
} AioEntry;

static AioEntry aios[1024];

void aio_init(void)
{
    for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        memset(e, 0, sizeof(*e));
        e->fd = -1;
    }
}

void aio_add_wait_object(int fd, void (*cb) (void *opaque), void *opaque) {
    for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        if (e->fd == -1 && __sync_bool_compare_and_swap(&e->fd, -1, fd)) {
            e->cb = cb;
            e->opaque = opaque;
            return;
        }
    }
    assert(0);
}

int aio_wait(void)
{
    fd_set fds;
    FD_ZERO(&fds);
    int max = ioh_fd();
    FD_SET(ioh_fd(), &fds);
    for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        int fd = e->fd;
        if (fd >= 0) {
            max = fd > max ? fd : max;
            FD_SET(fd, &fds);
        }
    }

    struct timeval tv = {5, 0};
    int r = select(max + 1, &fds, NULL, NULL, &tv);
    if (r > 0) {
        if (FD_ISSET(ioh_fd(), &fds)) {
            for (;;) {
                ioh_event *event;
                int r = read(ioh_fd(), &event, sizeof(event));
                if (r < 0 && errno == EWOULDBLOCK) {
                    break;
                }
                if (r != sizeof(event)) {
                    assert(0);
                }
                ioh_event_reset(event);
                if (event->cb) {
                    void (*cb) (void *opaque) = event->cb;
                    void *opaque = event->opaque;
                    event->cb = NULL;
                    event->opaque = NULL;
                    /* event may no longer be valid after callback */
                    cb(opaque);
                }
            }
        }
        for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
            AioEntry *e = &aios[i];
            int fd = e->fd;
            if (fd >= 0 && FD_ISSET(fd, &fds)) {
                __sync_bool_compare_and_swap(&e->fd, fd, -1);
                e->cb(e->opaque);
            }
        }
    }
    return r;
}
