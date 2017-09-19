#ifndef __CONFIG_H__
#define __CONFIG_H__

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ALIGN_PAGE_ALIGN 0x1000
#define UXEN_PAGE_MASK (~0xfff)
#define BDRV_SECTOR_BITS 9


#define debug_printf printf
#define Werr err
#define Wwarn warn

typedef pthread_t uxen_thread;
#define wait_thread(_a) pthread_join(_a, NULL)
#define create_thread(_a, _b, _c) pthread_create(_a, NULL, _b, (void *) _c)
#define elevate_thread(_t)
#define close_thread_handle(thread) do { } while(0)

typedef pthread_mutex_t critical_section;

static inline int file_exists(const char *path)
{
    struct stat st;

    if (stat(path, &st) >= 0)
        return 1;
    else
        return 0;
}

static inline void
critical_section_init(critical_section *cs)
{
    static pthread_mutexattr_t mta_recursive;
    static int initialized = 0;
    int ret;

    if (!initialized) {
        assert(!pthread_mutexattr_init(&mta_recursive));
        assert(!pthread_mutexattr_settype(&mta_recursive,
                    PTHREAD_MUTEX_RECURSIVE));
    }

    ret = pthread_mutex_init(cs, &mta_recursive);
    if (ret) {
        errno = ret;
        err(1, "%s: pthread_mutex_init failed", __FUNCTION__);
    }
}

static inline void
critical_section_free(critical_section *cs)
{
    int ret;

    ret = pthread_mutex_destroy(cs);
    if (ret) {
        errno = ret;
        err(1, "%s: pthread_mutex_destroy failed", __FUNCTION__);
    }
}

static inline void
critical_section_enter(critical_section *cs)
{
    int ret;

    ret = pthread_mutex_lock(cs);
    if (ret) {
        errno = ret;
        err(1, "%s: pthread_mutex_lock failed", __FUNCTION__);
    }
}

static inline void
critical_section_leave(critical_section *cs)
{
    int ret;

    ret = pthread_mutex_unlock(cs);
    if (ret) {
        errno = ret;
        err(1, "%s: pthread_mutex_unlock failed", __FUNCTION__);
    }
}

#include <sys/time.h>
static inline uint64_t os_get_clock(void)
{
    struct timeval time;
    gettimeofday(&time,0);
    return (1000000 * time.tv_sec + time.tv_usec);
}

#define page_align_alloc malloc
#define page_align_free free
#define align_alloc malloc
#define align_free free

#endif /* __CONFIG_H__ */
