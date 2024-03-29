#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "config.h"
#include "ioh.h"

/* These must go last or they will mess with e.g. asprintf() */
#include <curl/curl.h>
#include <curl/easy.h>

typedef struct AioEntry {
    int fd;
    void (*cb) (void *opaque);
    void *opaque;
    int suspended;
} AioEntry;

static AioEntry aios[16];

static int curl_timer_callback(CURLM *cmd, long timeout_ms, void *userp);
static int curl_socket_cb(CURL *ch, curl_socket_t s, int what, void *cbp, void *sockp);

struct curl_state {
    critical_section lock;
    struct CURLM *cmh;
    long timeout;
    ioh_event curl_wakeup;
    fd_set readset, writeset, errset;
    int max;
    int running;
} curl_global;

static inline struct curl_state *cs_get(void *opaque) {
    struct curl_state *cs = opaque;
    critical_section_enter(&cs->lock);
    return cs;
}

static inline void cs_put(struct curl_state **pcs) {
    struct curl_state *cs = *pcs;
    critical_section_leave(&cs->lock);
    *pcs = NULL;
}

static void curl_wakeup_cb(void *opaque) {
    struct curl_state *cs = cs_get(opaque);
    ioh_event_clear(&cs->curl_wakeup);
    curl_multi_socket_action(cs->cmh, CURL_SOCKET_TIMEOUT, 0, &cs->running);
    cs_put(&cs);
}

static void aio_init_curl(struct curl_state *cs) {

    critical_section_init(&cs->lock);

    ioh_event_init(&cs->curl_wakeup, curl_wakeup_cb, cs);
    cs->cmh = curl_multi_init();
    curl_multi_setopt(cs->cmh, CURLMOPT_TIMERFUNCTION, curl_timer_callback);
    curl_multi_setopt(cs->cmh, CURLMOPT_TIMERDATA, &cs->timeout);
    curl_multi_setopt(cs->cmh, CURLMOPT_SOCKETFUNCTION, curl_socket_cb);
    curl_multi_setopt(cs->cmh, CURLMOPT_SOCKETDATA, &curl_global);
    FD_ZERO(&cs->readset);
    FD_ZERO(&cs->writeset);
    FD_ZERO(&cs->errset);
    cs->max = -1;
}

void aio_global_init(void) {
    for (size_t i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        memset(e, 0, sizeof(*e));
        e->fd = -1;
    }
    ioh_init();
    curl_global_init(CURL_GLOBAL_DEFAULT);
    aio_init_curl(&curl_global);
}

void aio_add_wait_object(int fd, void (*cb) (void *opaque), void *opaque) {
    for (size_t i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        if (e->fd == -1 && __sync_bool_compare_and_swap(&e->fd, -1, fd)) {
            e->cb = cb;
            e->opaque = opaque;
            e->suspended = 0;
            return;
        }
    }
    assert(0);
}

void aio_suspend_wait_object(int fd) {
    for (size_t i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        if (e->fd == fd) {
            __sync_bool_compare_and_swap(&e->suspended, 0, 1);
            return;
        }
    }
    assert(0);
}

void aio_resume_wait_object(int fd) {
    for (size_t i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        if (e->fd == fd) {
            __sync_bool_compare_and_swap(&e->suspended, 1, 0);
            return;
        }
    }
    assert(0);
}

#define MAX_PENDING_CHS 256
static CURL *pending_chs[MAX_PENDING_CHS] = {};
static int num_pending_chs = 0;

int aio_add_curl_handle(CURL *ch) {
    int r;
    struct curl_state *cs = cs_get(&curl_global);
    CURLMcode cr = curl_multi_add_handle(curl_global.cmh, ch);
    if (cr == CURLM_OK) {
        ioh_event_set(&cs->curl_wakeup);
        r = 0;
#if LIBCURL_VERSION_NUM >= 0x074100
    } else if (cr == CURLM_RECURSIVE_API_CALL) {
        if (num_pending_chs >= MAX_PENDING_CHS) {
            errx(1, "too many pending curl handles");
        }
        pending_chs[num_pending_chs++] = ch;
#endif
    } else {
        errx(1, "%s %p\n", curl_multi_strerror(cr), cs->cmh);
        r = -1;
    }
    cs_put(&cs);
    return r;
}

extern void dump_swapstat(void);
void dubtree_cleanup_curl_handle(CURL *ch);

static int curl_timer_callback(CURLM *cmd, long timeout_ms, void *userp) {
    (void) cmd;
    *((long *) userp) = timeout_ms;
    return 0;
}

static int curl_socket_cb(CURL *ch, curl_socket_t s, int what, void *opaque, void *sockp)
{
    (void) ch;
    (void) sockp;
    assert(s < FD_SETSIZE);
    struct curl_state *cs = opaque;
    if (what == CURL_POLL_REMOVE) {
        FD_CLR(s, &cs->readset);
        FD_CLR(s, &cs->writeset);
        FD_CLR(s, &cs->errset);
    } else {
        FD_SET(s, &cs->readset);
        FD_SET(s, &cs->writeset);
        FD_SET(s, &cs->errset);
        cs->max = cs->max > (s + 1) ? cs->max : (s + 1);
    }
    return 0;
}

void aio_wait(void) {
    long timeout = -1;
    int max = -1;
    fd_set readset, writeset, errset;

    struct curl_state *cs = cs_get(&curl_global);
    if (cs->running) {
        memcpy(&readset, &cs->readset, sizeof(readset));
        memcpy(&writeset, &cs->writeset, sizeof(writeset));
        memcpy(&errset, &cs->errset, sizeof(errset));
        timeout = cs->timeout;
        max = cs->max;
    } else {
        FD_ZERO(&readset);
        FD_ZERO(&writeset);
        FD_ZERO(&errset);
    }
    cs_put(&cs);

    max = max > ioh_fd() ? max : ioh_fd();
    FD_SET(ioh_fd(), &readset);
    for (size_t i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
        AioEntry *e = &aios[i];
        int fd = e->fd;
        if (fd >= 0 && !e->suspended) {
            max = fd > max ? fd : max;
            FD_SET(fd, &readset);
        }
    }

    struct timeval tv = {1, 0};
    if (timeout >= 0) {
        tv.tv_sec = timeout / 1000;
        if(tv.tv_sec > 1) {
            tv.tv_sec = 1;
        } else {
            tv.tv_usec = (timeout % 1000) * 1000;
        }
    }
    int r;
    do {
        r = select(max + 1, &readset, &writeset, &errset, &tv);
        if (r < 0 && errno != EINTR) {
            warn("select failed");
        }
    } while (r < 0 && errno == EINTR);
    if (r < 0) {
        err(1, "select failed");
    }

    if (r == 0) {
        cs = cs_get(&curl_global);
        curl_multi_socket_action(cs->cmh, CURL_SOCKET_TIMEOUT, 0, &cs->running);
        cs_put(&cs);
    } else if (r > 0) {
        cs = cs_get(&curl_global);
        for (int i = 0; i < max; ++i) {
            if (FD_ISSET(i, &cs->readset)) {
                int evmask = 0;
                evmask |= FD_ISSET(i, &readset) ? CURL_CSELECT_IN : 0;
                evmask |= FD_ISSET(i, &writeset) ? CURL_CSELECT_OUT : 0;
                evmask |= FD_ISSET(i, &errset) ? CURL_CSELECT_ERR : 0;
                if (evmask) {
                    curl_multi_socket_action(cs->cmh, i, 0, &cs->running);
                }
            }
        }
        cs_put(&cs);

        if (FD_ISSET(ioh_fd(), &readset)) {
            ioh_service();
        }
        for (size_t i = 0; i < sizeof(aios) / sizeof(aios[0]); ++i) {
            AioEntry *e = &aios[i];
            int fd = e->fd;
            if (fd >= 0 && FD_ISSET(fd, &readset)) {
                e->cb(e->opaque);
            }
        }
    }

    cs = cs_get(&curl_global);
    int num_msgs;
    CURLMsg *msg;
    while ((msg = curl_multi_info_read(cs->cmh, &num_msgs))) {
        if (msg->msg == CURLMSG_DONE) {
            int response;
            curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE,
                    &response);
            if (response != 200 && response != 206) {
                errx(1, "got bad HTTP response %u\n", response);
            }
            dubtree_cleanup_curl_handle(msg->easy_handle);
            curl_multi_remove_handle(cs->cmh, msg->easy_handle);
            curl_easy_cleanup(msg->easy_handle);
        }
    }
    for (int i = 0; i < num_pending_chs; ++i) {
        aio_add_curl_handle(pending_chs[i]);
        pending_chs[i] = NULL;
    }
    num_pending_chs = 0;
    cs_put(&cs);
}
