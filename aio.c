#include <assert.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "ioh.h"

typedef struct AioEntry {
    ioh_event *event;
    void (*cb) (void *opaque);
    void *opaque;
} AioEntry;

static AioEntry aios[1024];

void aio_add_wait_object(ioh_event *event, void (*cb) (void *opaque), void *opaque) {
    for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        if (!e->event && __sync_bool_compare_and_swap(&e->event, NULL, event)) {
            e->cb = cb;
            e->opaque = opaque;
            return;
        }
    }
}

void aio_wait(void)
{
    fd_set fds;
    FD_ZERO(&fds);
    int max = -1;
    for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        if (e->event) {
            int fd = ioh_handle(e->event);
            max = fd > max ? fd : max;
            FD_SET(fd, &fds);
        }
    }

    if (max != -1) {

        int r = select(max + 1, &fds, NULL, NULL, NULL);
        assert(r >= 0);

        for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
            AioEntry *e = &aios[i];
            if (e->event) {
                if (FD_ISSET(ioh_handle(e->event), &fds)) {
                    ioh_event *event = e->event;
                    ioh_event_reset(event);
                    e->cb(e->opaque);
                    __sync_bool_compare_and_swap(&e->event, event, NULL);
                }
            }
        }
    }
}
