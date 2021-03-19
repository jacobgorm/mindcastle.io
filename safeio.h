#ifndef __SAFEIO_H__
#define __SAFEIO_H__

static inline int safe_read(int fd, void *buf, size_t sz)
{
    uint8_t *b = buf;
    size_t left = sz;
    while (left) {
        ssize_t r;
        do {
            r = read(fd, b, left);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            return r;
        } else if (r == 0) {
            break;
        }
        left -= r;
        b += r;
    }
    return sz - left;
}

static inline int safe_write(int fd, const void *buf, size_t sz)
{
    const uint8_t *b = buf;
    size_t left = sz;
    while (left) {
        ssize_t r;
        do {
            r = write(fd, b, left);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            return r;
        } else if (r == 0) {
            break;
        }
        left -= r;
        b += r;
    }
    return sz - left;
}


static inline ssize_t safe_pread(int fd, void *buf, size_t sz, off_t offset)
{
    uint8_t *b = buf;
    size_t left = sz;
    while (left) {
        ssize_t r;
        do {
            r = pread(fd, b, left, offset);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            return r;
        } else if (r == 0) {
            break;
        }
        left -= r;
        offset += r;
        b += r;
    }
    return sz - left;
}

static inline ssize_t safe_pwrite(int fd, const void *buf, size_t sz, off_t offset)
{
    const uint8_t *b = buf;
    size_t left = sz;
    while (left) {
        ssize_t r;
        do {
            r = pwrite(fd, b, left, offset);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            return r;
        } else if (r == 0) {
            break;
        }
        left -= r;
        offset += r;
        b += r;
    }
    return sz - left;
}

#endif /* __SAFEIO_H__ */
