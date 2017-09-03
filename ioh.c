#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <error.h>
#include <errno.h>

#include "ioh.h"

int ioh_event_init(ioh_event *event) {
    assert(event->valid != 0xfedeabe0);
    int r = pipe2(event->fds, O_DIRECT | O_NONBLOCK);
    assert(r >= 0);
    event->state = 0;
    event->valid = 0xfedeabe0;
    return r;
}

int ioh_event_init_fd(ioh_event *event, int fd) {
    assert(event->valid != 0xfedeabe0);
    event->fds[0] = fd;
    event->fds[1] = -1;
    event->state = 0;
    event->valid = 0xfedeabe0;
    return 0;
}

void ioh_event_set(ioh_event *event) {
    assert(event->valid == 0xfedeabe0);
    if (__sync_bool_compare_and_swap(&event->state, 0, 1)) {
        char one = 1;
        int r = write(event->fds[1], &one, sizeof(one));
        if (r != sizeof(one)) {
            printf("%s:%d r %d %s\n", __FUNCTION__, __LINE__, r, strerror(errno));
        }
        assert(r == 1);
    } else printf("%p already set\n", event);
}

void ioh_event_reset(ioh_event *event) {
    if (__sync_bool_compare_and_swap(&event->state, 1, 0)) {
        char one = 0;
        int r = read(event->fds[0], &one, sizeof(one));
        if (r != sizeof(one)) {
            printf("%s:%d r %d %s\n", __FUNCTION__, __LINE__, r, strerror(errno));
        }
        assert(r == 1);
        assert(one == 1);
    }
}

void ioh_event_close(ioh_event *event) {
    close(event->fds[0]);
    close(event->fds[1]);
    event->valid = 0;
}

