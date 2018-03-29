#ifndef __AIO_H__
#define __AIO_H__

struct ioh_event;
struct CURL;

void swap_aio_init(void);
void swap_aio_close(void);
int swap_aio_add_curl_handle(struct CURL *ch);
void swap_aio_add_wait_object(int fd, void (*cb) (void *opaque), void *opaque);
int swap_aio_wait(void);

#endif /* __AIO_H__ */
