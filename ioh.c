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

static TAILQ_HEAD(, ioh_event) event_queue;

int ioh_init(void)
{
    TAILQ_INIT(&event_queue);
    int r = pipe2(event_fds, O_DIRECT | O_NONBLOCK);
    assert(!r);
    return r;
}

int ioh_fd(void)
{
    return event_fds[0];
}

void ioh_event_set(ioh_event *event) {
    assert(event->cb);
    if (__sync_bool_compare_and_swap(&event->state, 0, 1)) {
        char byte = 0;
        int r = write(event_fds[1], &byte, sizeof(byte));
        if (r != sizeof(byte)) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
            } else {
                printf("%s:%d r %d %d:%s\n", __FUNCTION__, __LINE__, r, errno, strerror(errno));
                assert(0);
            }
        }
    } else assert(0);
}

void ioh_wakeup(void) {
    char byte = 0;
    int r = write(event_fds[1], &byte, sizeof(byte));
    if (r != sizeof(byte)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            //assert(0);
        } else {
            printf("%s:%d r %d %d:%s\n", __FUNCTION__, __LINE__, r, errno, strerror(errno));
            assert(0);
        }
    }
}

void ioh_event_init(ioh_event *event, void (*cb) (void *opaque), void *opaque)
{
    assert(!event->state);
    __sync_bool_compare_and_swap(&event->state, 0, 0);
    event->cb = cb;
    event->opaque = opaque;
    TAILQ_INSERT_TAIL(&event_queue, event, event_queue_entry);
}

void ioh_event_service_callbacks(void) {
    ioh_event *event, *next;
    TAILQ_FOREACH_SAFE(event, &event_queue, event_queue_entry, next) {
        if (__sync_bool_compare_and_swap(&event->state, 1, 0)) {
            void (*cb) (void *opaque) = event->cb;
            void *opaque = event->opaque;
            event->cb = NULL;
            event->opaque = NULL;
            TAILQ_REMOVE(&event_queue, event, event_queue_entry);
            cb(opaque);
        }
    }
}
