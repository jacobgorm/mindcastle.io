#ifndef __AIO_H__
#define __AIO_H__

struct ioh_event;
struct CURL;

void aio_global_init(void);
int aio_add_curl_handle(struct CURL *ch);
void aio_add_wait_object(int fd, void (*cb) (void *opaque), void *opaque);
void aio_suspend_wait_object(int fd);
void aio_resume_wait_object(int fd);
void aio_wait(void);

#endif /* __AIO_H__ */
