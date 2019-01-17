#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>

#include "ioh.h"

static int event_fds[2];

int ioh_init(void) {
    int r = pipe2(event_fds, O_DIRECT | O_NONBLOCK);
    assert(!r);
    return r;
}

int ioh_fd(void) {
    return event_fds[0];
}

void ioh_event_set(ioh_event *event) {
    assert(event->cb);
    if (__sync_bool_compare_and_swap(&event->state, 0, 1)) {
        uintptr_t e = (uintptr_t) event;
        int r = write(event_fds[1], &e, sizeof(e));
        if (r != sizeof(e)) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                assert(0);
            } else {
                printf("%s:%d r %d %d:%s\n", __FUNCTION__, __LINE__, r, errno, strerror(errno));
                assert(0);
            }
        }
    }
}

void ioh_event_init(ioh_event *event, void (*cb) (void *opaque), void *opaque) {
    event->state = 0;
    event->cb = cb;
    event->opaque = opaque;
    __sync_synchronize();
}

void ioh_event_clear(ioh_event *event) {
    __sync_bool_compare_and_swap(&event->state, 1, 0);
}

void ioh_service(void) {
    for (;;) {
        uintptr_t e;
        int r2 = read(ioh_fd(), &e, sizeof(e));
        if (r2 != sizeof(e)) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return;
            } else {
                printf("r=%d\n", r2);
                assert(0);
            }
        } else {
            ioh_event *event = (ioh_event *) e;
            assert(event->state == 1 || event->state == 0);
            if (__sync_bool_compare_and_swap(&event->state, 1, 0)) {
                event->cb(event->opaque);
            }
        }
    }
}
