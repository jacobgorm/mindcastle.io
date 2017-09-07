struct ioh_event;

void aio_init(void);
void aio_add_wait_object(int fd, void (*cb) (void *opaque), void *opaque);
int aio_wait(void);
