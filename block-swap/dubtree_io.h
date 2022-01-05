#ifndef __DUBTREE_IO_H__
#define __DUBTREE_IO_H__

#ifndef _WIN32
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>

#endif


typedef struct {
#ifdef _WIN32
    HANDLE h;
#else
    int fd;
#endif
    void *opaque;
} * dubtree_handle_t;

static inline int valid_handle(dubtree_handle_t f) {
    return (f != NULL);
}

static inline int invalid_handle(dubtree_handle_t f) {
    return (f == NULL);
}

#define DUBTREE_INVALID_HANDLE NULL

/* Expand path using fullpath/realpath. Caller must
 * free returned result. */
static inline char *dubtree_realpath(const char *in)
{
#ifdef _WIN32
    return _fullpath(NULL, in, 0);
#else
    return realpath(in, NULL);
#endif
}

static inline dubtree_handle_t make_handle(int fd)
{
    if (fd >= 0) {
        dubtree_handle_t r = calloc(1, sizeof(*r));
        r->fd = fd;
        return r;
    } else {
        return NULL;
    }
}

static inline dubtree_handle_t
dubtree_open_existing(const char *fn)
{
#ifdef _WIN32
    return CreateFile(fn, GENERIC_READ | GENERIC_WRITE | DELETE,
            0, NULL,
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
#else
    return make_handle(open(fn, O_RDWR));
#endif
}

static inline dubtree_handle_t
dubtree_open_existing_readonly(const char *fn)
{
#ifdef _WIN32
    return CreateFile(fn, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED |
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            NULL);
#else
    return make_handle(open(fn, O_RDONLY));
#endif
}

static inline dubtree_handle_t
dubtree_open_new(const char *fn, int temp)
{
#ifdef _WIN32
    DWORD flags = FILE_FLAG_OVERLAPPED;
    if (temp) {
        flags |= FILE_ATTRIBUTE_TEMPORARY;
    }
    return CreateFile(fn, GENERIC_READ | GENERIC_WRITE | DELETE,
            0, NULL,
            OPEN_ALWAYS, flags, NULL);
#else
    return make_handle(open(fn, O_RDWR | O_CREAT | O_EXCL, 0644));
#endif
}

static inline dubtree_handle_t
dubtree_open_tmp(const char *dn)
{
#ifdef _WIN32
    assert(0);
#else
    return make_handle(open(dn, O_RDWR | O_TMPFILE, 0644));
#endif
}

static inline void dubtree_set_file_size(dubtree_handle_t f, size_t sz)
{
#ifdef _WIN32
    SetFilePointer(f->handle, (DWORD)sz, 0, FILE_BEGIN);
    SetEndOfFile(f->handle);
#else
    if (ftruncate(f->fd, sz)) {
        perror("truncate");
        exit(-1);
    }
#endif
}

static inline int64_t dubtree_get_file_size(dubtree_handle_t f)
{
#ifdef _WIN32
    return GetFileSize(f, NULL); // XXX on 32b
#else
    struct stat st;
    if (fstat(f->fd, &st) < 0) {
        //warn("unable to stat %s", s->filename);
        assert(0);
        return -1;
    }
    return st.st_size;
#endif
}

static inline void dubtree_close_file(dubtree_handle_t f)
{
#ifdef _WIN32
    CloseHandle(f->handle);
#else
    close(f->fd);
#endif
    free(f);
}

static inline
ssize_t dubtree_pread(dubtree_handle_t f, void *buf, size_t sz, uint64_t offset)
{
#ifdef _WIN32
    OVERLAPPED o = {};
    DWORD got = 0;
    o.OffsetHigh = offset >>32ULL;
    o.Offset = offset & 0xffffffff;

    if (!ReadFile(f, buf, (DWORD)sz, NULL, &o)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            printf("%s: ReadFile fails with error %u\n",
                    __FUNCTION__, (uint32_t)GetLastError());
            return -1;
        }
    }
    if (!GetOverlappedResult(f->handle, &o, &got, TRUE)) {
        printf("GetOverlappedResult fails on line %d with error %u\n",
                __LINE__, (uint32_t)GetLastError());
        got = -1;
    }
    return (int) got;
#else

    uint8_t *b = buf;
    size_t left = sz;
    ssize_t got = 0;
    while (left) {
        ssize_t r;
        do {
            r = pread(f->fd, b, left, offset);
        } while (r < 0 && errno == EINTR);
        if (r <= 0) {
            err(1, "pread %p+%" PRIx64 " failed", b, offset);
        }
        left -= r;
        b += r;
        offset += r;
        got += r;
    }
    return sz;
#endif
}

static inline ssize_t
dubtree_pwrite(dubtree_handle_t f, const void *buf, size_t sz, uint64_t offset)
{
#ifdef _WIN32
    DWORD wrote = 0;
    OVERLAPPED o = {};
    o.OffsetHigh = offset >>32ULL;
    o.Offset = offset & 0xffffffff;

    if (!WriteFile(f->handle, buf, sz, NULL, &o)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            printf("%s: WriteFile fails with error %u\n",
                    __FUNCTION__, (uint32_t)GetLastError());
            return -1;
        }
    }
    if (!GetOverlappedResult(f->handle, &o, &wrote, TRUE)) {
        printf("GetOverlappedResult fails on line %d with error %u\n",
                __LINE__, (uint32_t)GetLastError());
        wrote = -1;
    }
    return (int) wrote;
#else

    const uint8_t *b = buf;
    size_t left = sz;
    ssize_t wrote = 0;
    while (left) {
        ssize_t r;
        do {
            r = pwrite(f->fd, b + offset, left, offset);
        } while (r < 0 && errno == EINTR);
        if (r <= 0) {
            return r;
        }
        left -= r;
        offset += r;
        wrote += r;
    }
    return wrote;
#endif
}

static inline int dubtree_mkdir(const char *dn)
{
#ifdef _WIN32
    return CreateDirectory(dn, NULL) ? 0 : -1;
#else
    return mkdir(dn, 0755);
#endif

}

#endif /* __DUBTREE_IO_H__ */
