#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "ioh.h"

/* These must go last or they will mess with e.g. asprintf() */
#include <curl/curl.h>
#include <curl/easy.h>

struct CURLM *cmh;

typedef struct AioEntry {
    int fd;
    void (*cb) (void *opaque);
    void *opaque;
} AioEntry;

static AioEntry aios[1024];

void aio_init(void)
{
    for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        memset(e, 0, sizeof(*e));
        e->fd = -1;
    }
    curl_global_init(CURL_GLOBAL_ALL);
    cmh = curl_multi_init();
}

void aio_close(void)
{
    curl_multi_cleanup(cmh);
}

void aio_add_wait_object(int fd, void (*cb) (void *opaque), void *opaque) {
    for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        if (e->fd == -1 && __sync_bool_compare_and_swap(&e->fd, -1, fd)) {
            e->cb = cb;
            e->opaque = opaque;
            return;
        }
    }
    assert(0);
}

extern void dump_swapstat(void);

int aio_wait(void)
{
    int max = -1;
    fd_set readset, writeset, errset;
    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    FD_ZERO(&errset);

    CURLMcode mode;
    int running;
    int num_msgs;
    struct timeval tv = {};
    long curl_timeout;
    do {
        mode = curl_multi_perform(cmh, &running);
    } while (mode == CURLM_CALL_MULTI_PERFORM);

    do {
        CURLMsg *msg = curl_multi_info_read(cmh, &num_msgs);
        if (msg) {
            int response;
            curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE,
                    &response);
            if (response != 200 && response != 206) {
                printf("got response %u\n", response);
            }
            curl_multi_remove_handle(cmh, msg->easy_handle);
            curl_easy_cleanup(msg->easy_handle);
        }
    } while (num_msgs);

    if (curl_multi_fdset(cmh, &readset, &writeset, &errset, &max) != CURLM_OK) {
        printf("curl_multi_fdset failed!\n");
    }

    max = max > ioh_fd() ? max : ioh_fd();
    FD_SET(ioh_fd(), &readset);
    for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        int fd = e->fd;
        if (fd >= 0) {
            max = fd > max ? fd : max;
            FD_SET(fd, &readset);
        }
    }

    curl_multi_timeout(cmh, &curl_timeout);
    if(curl_timeout >= 0) {
        tv.tv_sec = curl_timeout / 1000;
        if(tv.tv_sec > 1) {
            tv.tv_sec = 1;
        } else {
            tv.tv_usec = (curl_timeout % 1000) * 1000;
        }
    } else {
        tv.tv_sec = 5;
        tv.tv_usec = 0;
    }

    int r = select(max + 1, &readset, &writeset, &errset, &tv);
    if (r > 0) {
        if (FD_ISSET(ioh_fd(), &readset)) {
            for (;;) {
                ioh_event *event;
                int r = read(ioh_fd(), &event, sizeof(event));
                if (r < 0 && errno == EWOULDBLOCK) {
                    break;
                }
                if (r != sizeof(event)) {
                    assert(0);
                }
                ioh_event_reset(event);
                if (event->cb) {
                    void (*cb) (void *opaque) = event->cb;
                    void *opaque = event->opaque;
                    event->cb = NULL;
                    event->opaque = NULL;
                    cb(opaque);
                }
            }
        }
        for (int i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
            AioEntry *e = &aios[i];
            int fd = e->fd;
            if (fd >= 0 && FD_ISSET(fd, &readset)) {
                __sync_bool_compare_and_swap(&e->fd, fd, -1);
                e->cb(e->opaque);
            }
        }
    } else {
        //dump_swapstat();
    }
    if (r == 0 && curl_timeout < 0) {
        return 1;
    } else {
        return 0;
    }
}
