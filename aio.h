struct ioh_event;

void aio_add_wait_object(struct ioh_event *event, void (*cb) (void *opaque), void *opaque);
void aio_wait(void);
