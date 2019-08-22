#define _GNU_SOURCE

#include <assert.h>
#include <err.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <unistd.h>

#include "block-swap/crypto.h"
#include "block-swap/dubtree.h"
#include "block-swap/hex.h"
#include "block-swap/rtc.h"

#include "ioh.h"
#include "aio.h"
#include "kv.h"

static const int MAX_PENDING = 64; // times 8GiB

static void *kv_malloc(void *_s, size_t sz) {
    return malloc(sz);
}

static void kv_free(void *_s, void *b) {
    free(b);
}

static void io_done(void *opaque, int ret) {
    char msg;
    struct kv *kv = opaque;
    int r = write(kv->fds[1], &msg, sizeof(msg));
    if (r != 1) {
        err(1, "write() failed\n");
    }
}

static void wait(struct kv *kv) {
    char msg;
    int r = read(kv->fds[0], &msg, sizeof(msg));
    if (r != sizeof(msg)) {
        err(1, "pipe read failed");
    }
}

static void *kv_aio_thread(void *bs)
{
    for (;;) {
        aio_wait();
    }
    return NULL;
}

static void *kv_insert_thread(void *opaque)
{
    struct kv *kv = opaque;
    struct kv_buffered_insert *kbi;

    for (;;) {
        pthread_mutex_lock(&kv->insert_mutex);
        while (!(kbi = TAILQ_FIRST(&kv->insert_queue))) {
            if (kv->shutdown) {
                return NULL;
            }
            pthread_cond_wait(&kv->insert_cond, &kv->insert_mutex);
        }
        TAILQ_REMOVE(&kv->insert_queue, kbi, queue_entry);
        pthread_mutex_unlock(&kv->insert_mutex);

        dubtree_insert(kv->t, kbi->n, kbi->keys, kbi->buffer, kbi->sizes, 0);
        pthread_mutex_lock(&kv->ready_mutex);
        if (--(kv->num_pending) < MAX_PENDING) {
            pthread_cond_signal(&kv->ready_cond);
        }
        pthread_mutex_unlock(&kv->ready_mutex);

        free(kbi->buffer);
        free(kbi);
    }
    return NULL;
}

int kv_global_init(void) {
    aio_global_init();
    pthread_t tid;
    pthread_create(&tid, NULL, kv_aio_thread, NULL);
    return 0;
}

#define BUFFER_MAX (32<<20)

int kv_init(struct kv *kv, const char *kvinfo, int delete_on_close) {
    memset(kv, 0, sizeof(*kv));
    pthread_mutex_init(&kv->insert_mutex, NULL);
    pthread_cond_init(&kv->insert_cond, NULL);
    pthread_mutex_init(&kv->ready_mutex, NULL);
    pthread_cond_init(&kv->ready_cond, NULL);
    TAILQ_INIT(&kv->insert_queue);
    pthread_create(&kv->insert_tid, NULL, kv_insert_thread, kv);

    chunk_id_t top_id = {};
    hash_t top_hash = {};
    int have_key = 0;
    kv->crypto_key = malloc(CRYPTO_KEY_SIZE);

    char *cache = NULL;
    char *fallbacks[16] = {};
    int num_fallbacks = 1; // first is kvdata
    if (kvinfo) {
        char *dup = strdup(kvinfo);
        char *next = dup;
        char *line;
        while ((line = strsep(&next, "\r\n"))) {
            if (!strncmp(line, "snapshot=", 9)) {
                unhex(top_id.id.bytes, line + 9, sizeof(top_id.id.bytes));
                top_id.size = atoi(line + 9 + 2 * sizeof(top_id.id.bytes) + 1);
            } else if (!strncmp(line, "snaphash=", 9)) {
                unhex(top_hash.bytes, line + 9, sizeof(top_hash.bytes));
            } else if (!strncmp(line, "key=", 4)) {
                unhex(kv->crypto_key, line + 4, CRYPTO_KEY_SIZE);
                have_key = 1;
            } else if (!strncmp(line, "kvdata=", 7)) {
                char *c;
                for (c = line + 8; *c != '\0' && *c != '\n'; ++c);
                *c = '\0';
                kv->kvdata = strdup(line + 7);
                if (!delete_on_close) {
                    kv->saved = 1;
                }
            } else if (!strncmp(line, "fallback=", 9)) {
                fallbacks[num_fallbacks++] = strdup(line + 9);
            } else if (!strncmp(line, "cache=", 6)) {
                cache = strdup(line + 6);
            }
        }
        free(dup);
    }
    if (!have_key) {
        RAND_bytes(kv->crypto_key, CRYPTO_KEY_SIZE);
    }

    int r;
    r = pipe2(kv->fds, O_DIRECT);
    if (r < 0) {
        errx(1, "pipe2 failed");
    }

    char kvdata[256];
    if (!kv->kvdata) {
        uint8_t kvdata_random[16];
        strcpy(kvdata, "kvdata-");
        RAND_bytes(kvdata_random, sizeof(kvdata_random));
        hex(kvdata + strlen(kvdata), kvdata_random, sizeof(kvdata_random));
        kv->kvdata = strdup(kvdata);
    } else {
        strcpy(kvdata, kv->kvdata);
    }
    fallbacks[0] = kvdata;
    kv->t = malloc(sizeof(DubTree));
    if (dubtree_init(kv->t, kv->crypto_key, top_id, top_hash, fallbacks, cache,
                kv_malloc, kv_free, NULL) != 0) {
        assert(0);
        return -1;
    }
    kv->find_context = dubtree_prepare_find(kv->t);
    kv->b = kv->buffer = malloc(BUFFER_MAX);
    kv->base = ~0ULL;
    return 0;
}

struct entry {
    uint64_t key;
    int offset;
    int size;
};

static int list_cmp(const void *va, const void *vb) {

    const struct entry *a = va;
    const struct entry *b = vb;
    if (a->key < b->key) {
        return -1;
    } else if (b->key < a->key) {
        return 1;
    } else {
        return 0;
    }
}

static inline void kv_wait_pending(struct kv *kv, int howmany, int increment) {
    pthread_mutex_lock(&kv->ready_mutex);
    while (kv->num_pending > howmany) {
        pthread_cond_wait(&kv->ready_cond, &kv->ready_mutex);
    }
    kv->num_pending += increment;
    pthread_mutex_unlock(&kv->ready_mutex);
}

int kv_flush(struct kv *kv) {
    int n = kv->n;
    if (n) {
        kv_wait_pending(kv, MAX_PENDING - 1, 1);
        struct kv_buffered_insert *kbi = malloc(sizeof(struct kv_buffered_insert));
        struct entry *list = malloc(sizeof(struct entry) * n);
        size_t total = 0;
        for (int i = 0; i < n; ++i) {
            list[i].key = kv->keys[i];
            list[i].offset = kv->offsets[i];
            list[i].size = kv->sizes[i];
            total += kv->sizes[i];
        }
        qsort(list, n, sizeof(list[0]), list_cmp);
        uint8_t *t;
        t = kbi->buffer = malloc(total);
        for (int i = 0; i < n; ++i) {
            memcpy(t, kv->buffer + list[i].offset, list[i].size);
            kbi->keys[i] = list[i].key;
            kbi->offsets[i] = list[i].offset;
            kbi->sizes[i] = list[i].size;
            t += list[i].size;
        }
        kbi->n = n;

        pthread_mutex_lock(&kv->insert_mutex);
        TAILQ_INSERT_TAIL(&kv->insert_queue, kbi, queue_entry);
        pthread_cond_signal(&kv->insert_cond);
        pthread_mutex_unlock(&kv->insert_mutex);

        free(list);
        kv->n = 0;
        kv->b = kv->buffer;
    }
    return 0;
}

int kv_insert(struct kv *kv, uint64_t key, const uint8_t *value, size_t size) {

    kv->base = ~0ULL;

    if (kv->b - kv->buffer + size > (BUFFER_MAX) || kv->n == KV_MAX_KEYS) {
        kv_flush(kv);
    }

    int n = kv->n;
    memcpy(kv->b, value, size);
    kv->sizes[n] = size;
    kv->offsets[n] = n ? kv->offsets[n - 1] + kv->sizes[n - 1] : 0;
    kv->keys[n] = key;
    ++(kv->n);
    kv->b += size;

    return 0;
}

int kv_find(struct kv *kv, uint8_t **rptr, size_t *rsize, uint64_t key) {
    int r;

    kv_flush(kv);
    kv_wait_pending(kv, 0, 0);

    uint64_t range = 0x100;
    uint64_t base = key & ~(range - 1ULL);
    if (kv->base != base) {
        kv->base = base;
        kv->last_found = ~0ULL;
        do {
            r = dubtree_find(kv->t, base, range, kv->buffer, BUFFER_MAX,
                    NULL, kv->sizes,
                    io_done, kv, kv->find_context);
        } while (r == -EAGAIN);
        wait(kv);
        int offset = 0;
        for (int i = 0; i < range; ++i) {
            kv->offsets[i] = offset;
            offset += kv->sizes[i];
        }
    }

    int idx = key - base;
    *rptr = kv->buffer + kv->offsets[idx];
    *rsize = kv->sizes[idx];
    return 0;
}

int kv_save(struct kv *kv, char *buffer, size_t size) {
    kv_flush(kv);
    kv_wait_pending(kv, 0, 0);

    chunk_id_t top_id = {};
    hash_t top_hash = {};
    dubtree_checkpoint(kv->t, &top_id, &top_hash);

    char tmp[128 + 1];
    hex(tmp, kv->crypto_key, CRYPTO_KEY_SIZE);
    char *b = buffer;
    b += sprintf(b, "key=%s\n", tmp);
    hex(tmp, top_id.id.bytes, sizeof(top_id.id.bytes));
    b += sprintf(b, "snapshot=%s:%u\n", tmp, top_id.size);
    hex(tmp, top_hash.bytes, sizeof(top_hash.bytes));
    b += sprintf(b, "snaphash=%s\n", tmp);
    b += sprintf(b, "kvdata=%s\n", kv->kvdata);
    kv->saved = 1;
    assert(b - buffer <= size);
    return b - buffer;
}

int kv_close(struct kv *kv) {
    kv_flush(kv);
    kv->shutdown = 1;
    pthread_cond_signal(&kv->insert_cond);
    kv_wait_pending(kv, 0, 0);
    pthread_join(kv->insert_tid, NULL);

    if (!kv->saved) {
        dubtree_delete(kv->t);
    } else {
        dubtree_close(kv->t);
    }
    dubtree_end_find(kv->t, kv->find_context);
    free(kv->buffer);
    free(kv->t);
    free(kv->crypto_key);
    free(kv->kvdata);
    close(kv->fds[0]);
    close(kv->fds[1]);
    return 0;
}
