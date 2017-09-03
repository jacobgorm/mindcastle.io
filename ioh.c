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
int ioh_init(void)
{
    int r = pipe2(event_fds, O_DIRECT | O_NONBLOCK);
    return r;
}

int ioh_fd(void)
{
    return event_fds[0];
}

void ioh_event_init(ioh_event *event) {
    memset(event, 0, sizeof(*event));
}

void ioh_event_set(ioh_event *event) {
    if (__sync_bool_compare_and_swap(&event->state, 0, 1)) {
        int r = write(event_fds[1], &event, sizeof(event));
        if (r != sizeof(event)) {
            printf("%s:%d r %d %s\n", __FUNCTION__, __LINE__, r, strerror(errno));
            assert(0);
        }
    }
}

void ioh_event_set_callback(ioh_event *event, void (*cb) (void *opaque), void *opaque)
{
    event->cb = cb;
    event->opaque = opaque;
}

void ioh_event_reset(ioh_event *event) {
    if (__sync_bool_compare_and_swap(&event->state, 1, 0)) {
    }
}
