#ifndef __IOH_H__
#define __IOH_H__

#include <stdint.h>

#include "queue.h"

typedef struct ioh_event {
    TAILQ_ENTRY(ioh_event) event_queue_entry;
    volatile uint32_t state;
    void (*cb) (void *opaque);
    void *opaque;
} ioh_event;

int ioh_init(void);
int ioh_fd(void);
void ioh_event_set(ioh_event *event);
void ioh_event_init(ioh_event *event, void (*cb) (void *opaque), void *opaque);
void ioh_event_service_callbacks(void);
void ioh_event_dump(void);

#endif /* __IOH_H__ */
