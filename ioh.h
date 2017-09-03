#ifndef __IOH_H__
#define __IOH_H__

#include <stdint.h>

typedef struct ioh_event {
    volatile uint32_t state;
    int valid;
    int fds[2];
} ioh_event;

static inline int ioh_event_valid(ioh_event *event) {
    return event->valid;
}

static inline int ioh_handle(ioh_event *event) {
    return event->fds[0];
}

int ioh_event_init(ioh_event *event);
int ioh_event_init_fd(ioh_event *event, int fd);
void ioh_event_set(ioh_event *event);
void ioh_event_reset(ioh_event *event);
void ioh_event_wait(ioh_event *event);
void ioh_event_close(ioh_event *event);

#endif /* __IOH_H__ */
