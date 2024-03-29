/*
 * Block driver for swap dubtree databases
 *
 * Copyright (c) 2012-2016 Bromium Inc.
 * Copyright (c) 2017-2018 Jacob Gorm Hansen.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

//#include "config.h"

#define _GNU_SOURCE

#include <assert.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <openssl/rand.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#define RAND_priv_bytes RAND_bytes
#endif

#include "aio.h"
#include "ioh.h"
//#include "block-int.h"
//#include "block.h"
//#include "clock.h"
//#include "os.h"
//#include "qemu_bswap.h"
#include "thread-event.h"
//#include "timer.h"
#include "queue.h"
#include "tinyuuid.h"

#ifndef _WIN32
#include <sys/mman.h>
#include <errno.h>
#endif

#include "block-swap.h"
#include "block-swap/dubtree_io.h"
#include "block-swap/dubtree.h"
#include "block-swap/crypto.h"
#include "block-swap/hashtable.h"
#include "block-swap/lrucache.h"
#include "block-swap/hex.h"

#include <lz4.h>

#define LIBIMG

//#include "uuidgen.h"

#define WRITE_RATELIMIT_THR_BYTES (32 << 20)
#define WRITE_BLOCK_THR_BYTES (WRITE_RATELIMIT_THR_BYTES * 2)
#define WRITE_RATELIMIT_GAP_MS 10

#define SWAP_SIZE_SHIFT (51ULL)
#define SWAP_SIZE_MASK (((1ULL<<(64-SWAP_SIZE_SHIFT))-1) << SWAP_SIZE_SHIFT)

uint64_t log_swap_fills = 0;
static int swap_backend_active = 0;

//#if !defined(LIBIMG) && defined(CONFIG_DUMP_SWAP_STAT)
  #define SWAP_STATS
//#endif
#define SCALE_MS 1000

#define SWAP_SECTOR_SIZE DUBTREE_BLOCK_SIZE
#ifdef LIBIMG
  #define SWAP_LOG_BLOCK_CACHE_LINES 10
#else
  #define SWAP_LOG_BLOCK_CACHE_LINES 8
#endif

struct heap_elem {
    uint64_t key, value;
    uint32_t timestamp;
}__attribute__((__packed__));

static inline int less_than(struct heap_elem *a,
        struct heap_elem *b)
{
    if (a->key != b->key) {
        return a->key < b->key;
    } else {
        return a->timestamp < b->timestamp;
    }
}

static inline void sift_up(struct heap_elem *hp, size_t child)
{
    size_t parent;
    for (; child; child = parent) {
        parent = (child - 1) / 2;

        if (less_than(&hp[child], &hp[parent])) {
            struct heap_elem tmp = hp[parent];
            hp[parent] = hp[child];
            hp[child] = tmp;
        } else {
            break;
        }
    }
}

static inline void sift_down(struct heap_elem *hp, size_t end)
{
    size_t parent = 0;
    size_t child;
    struct heap_elem tmp;
    for (;; parent = child) {
        child = 2 * parent + 1;

        if (child >= end)
            break;

        /* point to the min child */
        if (child + 1 < end &&
                less_than(&hp[child + 1], &hp[child])) {
            ++child;
        }

        /* heap condition restored? */
        if (less_than(&hp[parent], &hp[child])) {
            break;
        }

        /* else swap and continue. */
        tmp = hp[parent];
        hp[parent] = hp[child];
        hp[child] = tmp;
    }
}

struct pq {
    struct heap_elem *heap;
    int max_heap;
    int n_heap;
    uint32_t timestamp;
};

static void pq_init(struct pq *pq)
{
    pq->heap = NULL;
    pq->max_heap = pq->n_heap = 0;
    pq->timestamp = 0;
}

static void pq_push(struct pq *pq, uint64_t key, uint64_t value)
{
    struct heap_elem *he;

    if (pq->n_heap == pq->max_heap) {
        pq->max_heap = pq->max_heap ? 2 * pq->max_heap : 1;
        pq->heap = realloc(pq->heap, sizeof(pq->heap[0]) * pq->max_heap);
    }

    he = pq->heap + pq->n_heap;
    he->key = key;
    he->value = value;
    he->timestamp = pq->timestamp++;
    sift_up(pq->heap, pq->n_heap++);
}

static inline int pq_len(struct pq *pq)
{
    return pq->n_heap;
}

static inline int pq_empty(struct pq *pq)
{
    return (pq_len(pq) == 0);
}

static inline struct heap_elem *pq_min(struct pq *pq)
{
    return pq->n_heap ? &pq->heap[0] : NULL;
}

static void pq_pop(struct pq *pq)
{
    pq->heap[0] = pq->heap[--(pq->n_heap)];
    sift_down(pq->heap, pq->n_heap);

    if (pq->n_heap == pq->max_heap / 2) {
        pq->max_heap = pq->n_heap;
        pq->heap = realloc(pq->heap, sizeof(pq->heap[0]) * pq->max_heap);
    }
    if (pq->n_heap == 0) {
        pq->timestamp = 0;
    }
}

typedef struct SwapMappedFile {
    void *mapping;
    uint64_t modulo;
    uint64_t size;
} SwapMappedFile;

typedef struct BDRVSwapState {

    /** Image name. */
    char *filename;
    char *swapdata;
    int num_fallbacks;
    char *fallbacks[DUBTREE_MAX_FALLBACKS + 1];
    char *cache;
    uint8_t crypto_key[CRYPTO_KEY_SIZE];
    /* Where the CoW kernel module places files. */
    char *cow_backup;
    uuid_t uuid;
    chunk_id_t top_id;
    hash_t top_hash;
    uint64_t size;

    HashTable cached_blocks;
    HashTable busy_blocks;
    LruCache bc;
    struct pq pqs[2];
    int pq_switch;
    uint64_t pq_cutoff;
    critical_section mutex;
    volatile int flush;
    volatile int quit;
    volatile int alloced;
    BlockDriverCompletionFunc *flush_complete_cb;
    void *flush_opaque;
    void *insert_context;

    thread_event write_event;
    thread_event can_write_event;
    uxen_thread write_thread;

    thread_event insert_event;
    thread_event can_insert_event;
    uxen_thread insert_thread;

    DubTree t;
    void *find_context;

    TAILQ_HEAD(, SwapAIOCB) rlimit_write_queue;

    int log_swap_fills;
    int store_uncompressed;

#ifdef _WIN32
    HANDLE heap;
#endif

} BDRVSwapState;


#ifdef SWAP_STATS
struct {
    uint64_t blocked_time;
    uint64_t compressed, decompressed, shallowed;
    uint64_t shallow_miss, shallow_read, dubtree_read, pre_proc_wait, post_proc_wait;
} swap_stats = {0,};
#endif

typedef struct SwapAIOCB {
    BlockDriverAIOCB common; /* must go first. */
    struct SwapAIOCB *next;
    TAILQ_ENTRY(SwapAIOCB) rlimit_write_entry;
    BlockDriverState *bs;
    uint64_t block;
    uint32_t size;
    uint8_t *buffer;
    uint8_t *tmp;
    uint32_t modulo;
    uint8_t *decomp;
    uint32_t *sizes;
    uint8_t *map;
    size_t orig_size;
    ioh_event event;
    int result;
    volatile int splits;
#ifndef LIBIMG
    Timer *ratelimit_complete_timer;
#endif

#ifdef _WIN32
    OVERLAPPED ovl;
#endif

#ifdef SWAP_STATS
    uint64_t t0, t1;
#endif

} SwapAIOCB;

/* Wrappers for compress and expand functions. */

static inline
size_t swap_set_key(void *out, const void *in)
{
    /* Caller has allocated ample space for compression overhead, so we don't
     * worry about about running out of space. However, there is no point in
     * storing more than DUBTREE_BLOCK_SIZE bytes, so if we exceed that we
     * revert to a straight memcpy(). When uncompressing we treat DUBTREE_BLOCK_SIZE'd
     * keys as special, and use memcpy() there as well. */

#ifdef SWAP_STATS
    swap_stats.compressed += DUBTREE_BLOCK_SIZE;
#endif

    size_t size = LZ4_compress_default((const char*)in, (char*) out, DUBTREE_BLOCK_SIZE, DUBTREE_BLOCK_SIZE * 2);
    if (size >= DUBTREE_BLOCK_SIZE) {
        memcpy(out, in, DUBTREE_BLOCK_SIZE);
        size = DUBTREE_BLOCK_SIZE;
    }
    return size;
}

static inline int swap_get_key(void *out, const void *in, int size)
{
#ifdef SWAP_STATS
    swap_stats.decompressed += DUBTREE_BLOCK_SIZE;
#endif

    if (size == DUBTREE_BLOCK_SIZE) {
        memcpy(out, in, DUBTREE_BLOCK_SIZE);
    } else {
        int unsize = LZ4_decompress_safe((const char*)in, (char*)out,
                size, DUBTREE_BLOCK_SIZE);
        if (unsize != DUBTREE_BLOCK_SIZE) {
#ifndef __APPLE__
            /* On OSX we don't like unclean exists, but on Windows our guest
             * will BSOD if we throw a read error. */
            errx(1, "swap: bad block size %d", unsize);
#else
            warnx("swap: bad block size %d", unsize);
#endif
            return -1;
        }
    }
    return 0;
}

static inline void swap_lock(BDRVSwapState *s)
{
    critical_section_enter(&s->mutex);
}

static inline void swap_unlock(BDRVSwapState *s)
{
    critical_section_leave(&s->mutex);
}

static inline void swap_signal_write(BDRVSwapState *s)
{
    thread_event_set(&s->write_event);
}

static inline void swap_signal_can_write(BDRVSwapState *s)
{
    thread_event_set(&s->can_write_event);
}

static inline void swap_signal_insert(BDRVSwapState *s)
{
    thread_event_set(&s->insert_event);
}

static inline void swap_signal_can_insert(BDRVSwapState *s)
{
    thread_event_set(&s->can_insert_event);
}

static inline void swap_wait_write(BDRVSwapState *s)
{
    thread_event_wait(&s->write_event);
}

#ifdef LIBIMG
static inline void swap_wait_can_write(BDRVSwapState *s)
{
    thread_event_wait(&s->can_write_event);
}
#endif

static inline void swap_wait_insert(BDRVSwapState *s)
{
    thread_event_wait(&s->insert_event);
}

static inline void swap_wait_can_insert(BDRVSwapState *s)
{
    thread_event_wait(&s->can_insert_event);
}

static void *swap_malloc(void *_s, size_t sz)
{
    BDRVSwapState *s = _s;
    __sync_fetch_and_add(&s->alloced, 1);
#ifdef _WIN32
    return HeapAlloc(s->heap, 0, sz);
#else
    return malloc(sz);
#endif
}

static void swap_free(void *_s, void *b)
{
    BDRVSwapState *s = _s;
    if (b) {
        __sync_fetch_and_sub(&s->alloced, 1);
#ifdef _WIN32
        HeapFree(s->heap, 0, b);
#else
        free(b);
#endif
    }
}

struct insert_context {
    int n;
    BDRVSwapState *s;
    uint8_t *cbuf;
    uint64_t *keys;
    uint32_t *sizes;
    size_t total_size;
};

static int swap_write_header(BDRVSwapState *s, uuid_t uuid, const char *fn);

static int swap_commit(void *opaque) {
    BDRVSwapState *s = (BDRVSwapState *) opaque;
    dubtree_checkpoint(&s->t, &s->top_id, &s->top_hash);
    swap_write_header(s, s->uuid, s->filename);
    return 0;
}

#ifdef _WIN32
static DWORD WINAPI
#else
static void *
#endif
swap_insert_thread(void * _s)
{
    BDRVSwapState *s = _s;
    struct insert_context *c;
    int quit;
    int r;

    for (;;) {

        swap_signal_can_insert(s);
        swap_wait_insert(s);

        swap_lock(s);
        c = s->insert_context;
        s->insert_context = NULL;
        quit = s->quit;
        swap_unlock(s);
        if (!c) {
            if (quit) {
                break;
            }
            continue;
        }

        uint64_t *keys = c->keys;
        uint8_t *cbuf = c->cbuf;
        int n = c->n;
        int i;
        uint32_t load;

        r = dubtree_insert(&s->t, n, keys, cbuf, c->sizes, 0, swap_commit, s);
        free(c->sizes);

        swap_lock(s);
        for (i = 0; i < n; ++i) {
            HashEntry *e;
            e = hashtable_find_entry(&s->busy_blocks, keys[i]);
            assert(e);
            uint8_t *ptr = (uint8_t *) (uintptr_t) (e->value & ~SWAP_SIZE_MASK);

            if (cbuf <= ptr && ptr < cbuf + c->total_size) {
                hashtable_delete_entry(&s->busy_blocks, e);
            }
        }

        free(keys);
        swap_free(c->s, c->cbuf);
        free(c);
        load = s->busy_blocks.load;
        BlockDriverCompletionFunc *cb = s->flush_complete_cb;
        void *opaque = s->flush_opaque;
        if (load == 0) {
            s->flush_complete_cb = NULL;
            s->flush_opaque = NULL;
        }
        swap_unlock(s);

        if (load == 0 && cb) {
            cb(opaque, r);
        }
        if (r < 0) {
            err(1, "dubtree_insert failed, r=%d!", r);
        }
    }
    debug_printf("%s exiting cleanly\n", __FUNCTION__);
    return 0;
}
static inline uint32_t buffered_size(BDRVSwapState *s)
{
    struct pq *pq1 = &s->pqs[s->pq_switch];
    struct pq *pq2 = &s->pqs[s->pq_switch ^ 1];;
    return SWAP_SECTOR_SIZE * (pq_len(pq1) + pq_len(pq2));
}

static inline int is_ratelimited_hard(BDRVSwapState *s)
{
    return (buffered_size(s) > WRITE_BLOCK_THR_BYTES);
}

static inline int is_ratelimited_soft(BDRVSwapState *s)
{
    return (buffered_size(s) > WRITE_RATELIMIT_THR_BYTES);
}

#ifdef _WIN32
static DWORD WINAPI
#else
static void *
#endif
swap_write_thread(void *_s)
{
    BDRVSwapState *s = (BDRVSwapState*) _s;
    size_t max_sz = 4<<20;
    uint8_t *cbuf = NULL;
    uint64_t *keys = NULL;
    uint32_t *sizes = NULL;
    uint32_t total_size = 0;
    size_t n = 0;

    swap_signal_can_write(s);

    for (;;) {
        /* Wait for more work? */
        uint64_t key;
        int flush = 0;
        HashEntry *e;
        uint64_t value;
        struct pq *pq1 = &s->pqs[s->pq_switch];
        struct pq *pq2 = &s->pqs[s->pq_switch ^ 1];;
        void *ptr = NULL;
        int quit;
        uint32_t size;

        swap_lock(s);
        if (n == 0 && pq_empty(pq1) && pq_empty(pq2)) {
wait:
            quit = s->quit;
            swap_unlock(s);

            swap_signal_can_write(s);
            if (quit) {
                break;
            }
            swap_wait_write(s);
            continue;
        }

        struct heap_elem *min = pq_min(pq1);
        if (min) {

            key = s->pq_cutoff = min->key;
            for (;;) {
                value = min->value;
                pq_pop(pq1);
                ptr = (void *) (uintptr_t) value;

                min = pq_min(pq1);
                if (!min || min->key != key) {
                    break;
                } else {
                    swap_free(s, ptr);
                }
            }

        } else {
            if (s->flush || is_ratelimited_soft(s)) {
                s->pq_switch ^= 1;
                s->pq_cutoff = ~0ULL;
                flush = 1;
            } else {
                goto wait;
            }
        }

        swap_unlock(s);

        if (flush || total_size + 2 * SWAP_SECTOR_SIZE > max_sz) {

            struct insert_context *c = malloc(sizeof(*c));
            c->n = n;
            c->s = s;
            c->cbuf = cbuf;
            c->keys = keys;
            c->sizes = sizes;
            c->total_size = total_size;

            swap_wait_can_insert(s);
            s->insert_context = c;
            swap_signal_insert(s);

            cbuf = NULL;
            keys = NULL;
            sizes = NULL;
            n = 0;
            total_size = 0;
        }

        if (!ptr) {
            continue;
        }

        if (!cbuf) {
            cbuf = swap_malloc(s, max_sz);
        }

        /* The skip check above only works for duplicates already queued,
         * not ones that could arrive when not holding lock. So we have to
         * re-check here. */
        if (n && keys[n - 1] == key) {
            --n;
            total_size -= sizes[n];
        }

        if (!((n - 1) & n)) {
            size_t max = (n ? 2 * n : 1);
            keys = realloc(keys, sizeof(keys[0]) * max);
            sizes = realloc(sizes, sizeof(sizes[0]) * max);
        }

        keys[n] = key;
        if (s->store_uncompressed) {
            memcpy(cbuf + total_size, ptr, DUBTREE_BLOCK_SIZE);
            size = DUBTREE_BLOCK_SIZE;
        } else {
            size = swap_set_key(cbuf + total_size, ptr);
        }

        /* This is nasty. We are doing it to be able to free ptr below, and instead set the
         * HT to point to the compressed version. */

        swap_lock(s);
        e = hashtable_find_entry(&s->busy_blocks, key);
        if (e && e->value == value) {
            e->value = (((uint64_t ) size) << SWAP_SIZE_SHIFT) |
                (uintptr_t) (cbuf + total_size);
        }
        swap_unlock(s);

        swap_free(s, ptr);

        sizes[n] = size;
        total_size += size;
        ++n;
    }

    assert(!cbuf);

    debug_printf("%s exiting cleanly\n", __FUNCTION__);
    return 0;
}

#ifdef _WIN32
static char *strsep(char **stringp, const char *delim)
{
    char *begin, *end;

    begin = *stringp;
    if (!begin)
        return NULL;

    if (!delim[0] || !delim[1]) {
        char ch = delim[0];

        if (ch == '\0')
            end = NULL;
        else {
            if (*begin == ch)
                end = begin;
            else if (*begin == '\0')
                end = NULL;
            else
                end = strchr(begin + 1, ch);
        }
    } else
        end = strpbrk(begin, delim);

    if (end) {
        *end++ = '\0';
        *stringp = end;
    } else
        *stringp = NULL;

    return begin;
}
#endif

static int swap_read_header(BDRVSwapState *s)
{
    FILE *file;
    char *buff;
    size_t len;
    char *next;
    char *line;
    struct stat st;

    file = fopen(s->filename, "r");
    if (!file) {
        warn("swap: unable to open %s", s->filename);
        return -1;
    }

    if (fstat(fileno(file), &st) < 0) {
        warn("swap: unable to stat %s", s->filename);
        fclose(file);
        return -1;
    }
    len = st.st_size;

    buff = calloc(1, len + 1);
    if (!buff) {
        warn("swap: no memory or file empty");
        fclose(file);
        return -1;
    }

    size_t got = fread(buff, 1, len, file);
    if (got != len) {
        warn("swap: unable to read %s", s->filename);
        fclose(file);
        free(buff);
        return -1;
    }
    fclose(file);
    buff[len] = '\0';

    next = buff;

    while ((line = strsep(&next, "\r\n"))) {
        if (!strncmp(line, "size=", 5)) {
            s->size = strtoll(line + 5, NULL, 0);
        } else if (!strncmp(line, "uuid=", 5)) {
            tiny_uuid_parse(line + 5 + (line[5]=='{'), s->uuid);
        } else if (!strncmp(line, "swapdata=", 9)) {
            s->swapdata = strdup(line + 9);
            if (!s->swapdata) {
                errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
            }
        } else if (!strncmp(line, "fallback=", 9)) {
            s->fallbacks[s->num_fallbacks++] = strdup(line + 9);
        } else if (!strncmp(line, "cache=", 6)) {
            s->cache = strdup(line + 6);
        } else if (!strncmp(line, "snapshot=", 9)) {
            unhex(s->top_id.id.bytes, line + 9, sizeof(s->top_id.id.bytes));
            s->top_id.size = atoi(line + 9 + 2 * sizeof(s->top_id.id.bytes) + 1);
        } else if (!strncmp(line, "snaphash=", 9)) {
            unhex(s->top_hash.bytes, line + 9, sizeof(s->top_hash.bytes));
        } else if (!strncmp(line, "key=", 4)) {
            unhex(s->crypto_key, line + 4, CRYPTO_KEY_SIZE);
        }
    }
    /* repair strsep damage */
    for (size_t i = 0; i < len; ++i) {
        if (buff[i] == '\0') {
            buff[i] = '\n';
        }
    }
    free(buff);
    return 0;
}

static int swap_write_header(BDRVSwapState *s, uuid_t uuid, const char *fn)
{
    int r = -1;
    char *tmpfn = NULL;
    if (asprintf(&tmpfn, "%s.tmp", fn) < 0) {
        goto out;
    }
    FILE *f = fopen(tmpfn, "w");
    if (!f) {
        warn("swap: unable to open %s", tmpfn);
        goto out;
    }

    char uuid_str[37];
    tiny_uuid_unparse(uuid, uuid_str);
    fprintf(f, "uuid=%s\n", uuid_str);
    fprintf(f, "size=%" PRIu64 "\n", s->size);

    if (s->swapdata) {
        fprintf(f, "swapdata=%s\n", s->swapdata);
    }
    if (s->cache) {
        fprintf(f, "cache=%s\n", s->cache);
    }
    for (int i = 1; i < s->num_fallbacks; ++i) {
        fprintf(f, "fallback=%s\n", s->fallbacks[i]);
    }
    char tmp[128 + 1];

    hex(tmp, s->crypto_key, CRYPTO_KEY_SIZE);
    fprintf(f, "key=%s\n", tmp);

    hex(tmp, s->top_id.id.bytes, sizeof(s->top_id.id.bytes));
    fprintf(f, "snapshot=%s:%u\n", tmp, s->top_id.size);

    hex(tmp, s->top_hash.bytes, sizeof(s->top_hash.bytes));
    fprintf(f, "snaphash=%s\n", tmp);

    fclose(f);
    r = rename(tmpfn, fn);
    if (r < 0) {
        err(1, "renaming %s -> %s failed", tmpfn, fn);
    }
out:
    free(tmpfn);
    return r;
}

static inline
char *swap_resolve_via_fallback(BDRVSwapState *s, const char *fn)
{
    char **fb;
    char *check = NULL;
    for (fb = s->fallbacks; *fb; ++fb) {
        asprintf(&check, "%s/%s", *fb, fn);
        if (!check) {
            break;
        }
        if (file_exists(check)) {
            break;
        } else {
            free(check);
            check = NULL;
        }
    }
    return check;
}

int swap_open(BlockDriverState *bs, const char *filename, int flags)
{
    (void) flags;
    memset(bs, 0 , sizeof(*bs));
    BDRVSwapState *s = calloc(1, sizeof(BDRVSwapState));
    bs->opaque = s;
    int r = 0;
    char *path, *real_path;
    char *swapdata = NULL;
    char *c, *last;
    int i;
    /* Start out with well-defined state. */
    memset(s, 0, sizeof(*s));
    TAILQ_INIT(&s->rlimit_write_queue);

    s->log_swap_fills = log_swap_fills;

#ifdef _WIN32
    s->heap = HeapCreate(0, 0, 0);
#endif

    /* Strip swap: prefix from path if given. */
    if (strncmp(filename, "swap:", 5) == 0) {
        s->filename = strdup(filename + 5);
    } else {
        s->filename = strdup(filename);
    }
    if (!s->filename) {
        errx(1, "OOM out %s line %d", __FUNCTION__, __LINE__);
    }

    s->num_fallbacks = 1;

    /* Read the .swap header file from disk, there is no data there,
     * just some pointers into the shared swapdata structure. */
    r = swap_read_header(s);
    if (r != 0) {
        r = -1;
        warn("unable to parse header %s", s->filename);
        goto out;
    }

    uint8_t zero_key[CRYPTO_KEY_SIZE] = {};
    if (!memcmp(zero_key, s->crypto_key, CRYPTO_KEY_SIZE)) {
        if (RAND_priv_bytes(s->crypto_key, sizeof(s->crypto_key)) != 1) {
            errx(1, "RAND_bytes failed!");
        }
    }

    /* Chop off filename to reveal dir. */
    path = strdup(s->filename);
    if (!path) {
        errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
    }
    for (c = last = path; *c; ++c) {
#ifdef _WIN32
        if (*c == '/' || *c == '\\') {
#else
        if (*c == '/') {
#endif
            last = c;
        }
    }
    *last = '\0';
    real_path = dubtree_realpath(path[0] ? path : ".");

    /* Generate swapdata path, taking into account user override
     * of "swapdata" component. */
    char *default_swapdata;
    char uuid_str[37];
    tiny_uuid_unparse(s->uuid, uuid_str);
    asprintf(&default_swapdata, "swapdata-%s", uuid_str);
    asprintf(&swapdata, "%s/%s",
            real_path, s->swapdata ? s->swapdata : default_swapdata);
    free(default_swapdata);
    free(real_path);
    free(path);

    if (!swapdata) {
        errx(1, "OOM out %s line %d", __FUNCTION__, __LINE__);
    }

    /* Setting the head of the fallbacks list last, the tail was possibly
     * filled out by swap_read_header(). */
    s->fallbacks[0] = swapdata;

    debug_printf("swap: swapdata at %s\n", swapdata);
    for (i = 1; i < s->num_fallbacks; ++i) {
        const char *fb = s->fallbacks[i];
        debug_printf("swap: fallback %d %s\n", i, fb);
        if (!file_exists(fb) &&
                memcmp("http://", fb, 7) &&
                memcmp("https://", fb, 8)) {
            warn("swap: fallback %s does not exist!", fb);
        }
    }

    if (dubtree_init(&s->t, s->crypto_key, s->top_id, s->top_hash, s->fallbacks, s->cache,
                0) != 0) {
        warn("swap: failed to init dubtree");
        r = -1;
        goto out;
    }

    /* A small write-back block cache, this is mainly to keep hot blocks such
     * as FS superblocks from getting inserted into the dubtree over and over.
     * This has large impact on the performance the libimg tools, and also
     * helps with e.g. USN journaling from a Windows guest. We cache only
     * blocks we write, on the assumption that the host OS takes care of normal
     * read caching and that decompression with LZ4 is cheap. */
    if (hashtable_init(&s->cached_blocks, NULL, NULL) < 0) {
        warn("swap: unable to create hashtable for block cache");
        return -1;
    }
    if (hashtable_init(&s->busy_blocks, NULL, NULL) < 0) {
        warn("swap: unable to create hashtable for busy blocks index");
        return -1;
    }
    if (lru_cache_init(&s->bc, SWAP_LOG_BLOCK_CACHE_LINES) < 0) {
        warn("swap: unable to create lrucache for blocks");
        return -1;
    }

    for (i = 0; i < 2; ++i) {
        pq_init(&s->pqs[i]);
    }
    s->pq_switch = 0;
    s->pq_cutoff = ~0ULL;

    s->quit = 0;
    s->flush = 0;
#if 0
    printf("checking...\n");
    assert(dubtree_sanity_check(&s->t) == 0);
    printf("checking done\n");
#endif

    critical_section_init(&s->mutex); /* big lock. */

    thread_event *events[] = {
        &s->write_event,
        &s->can_write_event,
        &s->insert_event,
        &s->can_insert_event,
    };

    for (size_t i = 0; i < sizeof(events) / sizeof(events[0]); ++i) {
        thread_event *ev = events[i];
        if (thread_event_init(ev) < 0) {
            Werr(1, "swap: unable to create event!");
        }
    }

    if (create_thread(&s->write_thread, swap_write_thread, (void*) s) < 0) {
        Werr(1, "swap: unable to create thread!");
    }

    if (create_thread(&s->insert_thread, swap_insert_thread, (void*) s) < 0) {
        Werr(1, "swap: unable to create thread!");
    }

    bs->total_sectors = s->size >> BDRV_SECTOR_BITS;

    debug_printf("%s: done\n", __FUNCTION__);
out:
    if (r < 0) {
        warnx("swap: failed to open %s", filename);
    }

    swap_backend_active = 1; /* activates stats logging. */
    return r;
}

int swap_remove(BlockDriverState *bs)
{
    int r;
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    dubtree_delete(&s->t);
    r = unlink(s->filename);
    if (r < 0) {
        debug_printf("swap: unable to unlink %s\n", s->filename);
        return r;
    }
    return 0;
}

void dump_swapstat(void)
{
#ifdef SWAP_STATS
    if (swap_backend_active) {
        debug_printf("SWAP blocked=%"PRId64"ms "
                "sh_open=%"PRId64"ms "
                "sh_read=%"PRId64"ms "
                "read=%"PRId64"ms "
                "sched_pre=%"PRId64"ms "
                "sched_post=%"PRId64"ms "
                "(out=%"PRId64"MiB,in=%"PRId64"MiB,sh_in=%"PRId64"MiB)\n",
                swap_stats.blocked_time / SCALE_MS,
                swap_stats.shallow_miss / SCALE_MS,
                swap_stats.shallow_read / SCALE_MS,
                swap_stats.dubtree_read / SCALE_MS,
                swap_stats.pre_proc_wait / SCALE_MS,
                swap_stats.post_proc_wait / SCALE_MS,
                swap_stats.compressed >> 20ULL,
                swap_stats.decompressed >> 20ULL,
                swap_stats.shallowed >> 20ULL);
    }
#endif
}

static inline void swap_common_cb(SwapAIOCB *acb)
{
    BDRVSwapState *s = (BDRVSwapState*) acb->bs->opaque;
#ifdef SWAP_STATS
    int64_t dt = os_get_clock() - acb->t0;
    if (dt / SCALE_MS > 1000) {
        debug_printf("%s: aio waited %"PRId64"ms\n", __FUNCTION__,
                dt / SCALE_MS);
    }
    swap_stats.blocked_time += dt;
#endif
    if (TAILQ_ACTIVE(acb, rlimit_write_entry)) {
        TAILQ_REMOVE(&s->rlimit_write_queue, acb,
                     rlimit_write_entry);
    }
    //aio_del_wait_object(&acb->event);
    free(acb->sizes);
    free(acb->map);
    free(acb);
}

#if 0
static void bdrv_swap_aio_cancel(BlockDriverAIOCB *_acb)
{
    SwapAIOCB *acb = (SwapAIOCB *)_acb;
    swap_common_cb(acb);
}

static AIOPool swap_aio_pool = {
    .aiocb_size = sizeof(SwapAIOCB),
    .cancel = bdrv_swap_aio_cancel,
};
#endif


static inline void complete_read_acb(SwapAIOCB *acb)
{
    if (__sync_fetch_and_sub(&acb->splits, 1) == 1) {
        ioh_event_set(&acb->event);
    }
}

static SwapAIOCB *swap_aio_get(BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    //BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    SwapAIOCB *acb;
    //acb = aio_get(&swap_aio_pool, bs, cb, opaque);
    acb = calloc(1, sizeof(*acb));
    acb->common.cb = cb;
    acb->common.opaque = opaque;
    acb->bs = bs;
    acb->result = -1;
    acb->map = NULL;
    acb->splits = 0;
    memset(&acb->rlimit_write_entry, 0, sizeof(acb->rlimit_write_entry));

#ifdef SWAP_STATS
    acb->t0 = os_get_clock();
    acb->t1 = 0;
#endif
    return acb;
}

static void swap_read_cb(void *opaque)
{
    SwapAIOCB *acb = opaque;

#ifdef SWAP_STATS
    swap_stats.post_proc_wait += os_get_clock() - acb->t1;
#endif

    if (acb->tmp) {
        memcpy(acb->buffer, acb->tmp + acb->modulo, acb->size - acb->modulo);
        free(acb->tmp);
    }
    acb->common.cb(acb->common.opaque, 0);
    swap_common_cb(acb);
}
static int __swap_nonblocking_write(BDRVSwapState *s, const uint8_t *buf,
                                    uint64_t block, size_t size, int dirty);

static void swap_rmw_cb(void *opaque)
{
    SwapAIOCB *acb = opaque;
    BlockDriverState *bs = acb->bs;
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    int n;

    memcpy(acb->tmp + acb->modulo, acb->buffer, acb->orig_size);
    swap_lock(s);
    n = __swap_nonblocking_write(s, acb->tmp, acb->block, acb->size, 1);
    swap_unlock(s);
    if (n) {
        swap_signal_write(s);
    }
    free(acb->tmp);
    acb->common.cb(acb->common.opaque, 0);
    swap_common_cb(acb);
}

#ifndef LIBIMG
static void swap_write_cb(void *opaque)
{
    printf("%s\n", __FUNCTION__);
    SwapAIOCB *acb = opaque;

    acb->common.cb(acb->common.opaque, 0);
    swap_common_cb(acb);
}
#endif

static void dubtree_read_complete_cb(void *opaque, int result)
{
    SwapAIOCB *acb = opaque;
    uint8_t *o = acb->tmp ? acb->tmp : acb->buffer;
    uint8_t *t = acb->decomp;
    int64_t count = acb->size;
    uint32_t *sizes = acb->sizes;
    uint8_t tmp[SWAP_SECTOR_SIZE];
    uint64_t key = acb->block;
    int r = 0;

    if (result >= 0) {

        while (count > 0) {
            size_t sz = *sizes++;

            if (sz != 0) {
#ifdef SWAP_STATS
                swap_stats.decompressed += DUBTREE_BLOCK_SIZE;
#endif
                uint8_t *dst = (count < (int64_t) SWAP_SECTOR_SIZE) ? tmp : o;
                r = swap_get_key(dst, t, sz);
                if (r < 0) {
                    errx(1, "block decompression failed");
                }

                if (dst == tmp) {
                    memcpy(o, tmp, count);
                }
                t += sz;
            }

            o += SWAP_SECTOR_SIZE;
            count -= SWAP_SECTOR_SIZE;
            ++key;
        }
    } else {
        debug_printf("%s: got negative result\n", __FUNCTION__);
        return;
    }

#ifdef SWAP_STATS
    acb->t1 = os_get_clock();
    swap_stats.dubtree_read += acb->t1 - acb->t0;
#endif

    free(acb->decomp);
    complete_read_acb(acb);
}

static int __swap_dubtree_read(BDRVSwapState *s, SwapAIOCB *acb)
{
    int r = 0;
    uint64_t offset = acb->block * SWAP_SECTOR_SIZE;
    uint64_t count = acb->size;
    uint8_t *map = acb->map;
    uint64_t start = offset / SWAP_SECTOR_SIZE;
    uint64_t end = (offset + count + SWAP_SECTOR_SIZE - 1) / SWAP_SECTOR_SIZE;
    uint32_t *sizes;
    void *decomp;

    /* Returns number of unresolved blocks, or negative on
     * error. */

    /* 'sizes' array must be initialized with zeroes. */
    sizes = calloc(end - start, sizeof(sizes[0]));
    if (!sizes) {
        errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
    }
    acb->sizes = sizes;

    size_t decomp_size = (DUBTREE_BLOCK_SIZE + CRYPTO_IV_SIZE) * (end - start);
    decomp = malloc(decomp_size);

    if (!decomp) {
        errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
    }
    acb->decomp = decomp;

    if (!s->find_context) {
        s->find_context = dubtree_prepare_find(&s->t);
        if (!s->find_context) {
            errx(1, "swap: failed to create find context");
        }
    }

    int retries = 0;
    do {
        r = dubtree_find(&s->t, start, end - start,
                decomp, &decomp_size,
                map, sizes,
                dubtree_read_complete_cb, acb, s->find_context);
        if (r == -ENOSPC) {
            errx(1, "%s: dubtree_find() buffer exceeded!?", __FUNCTION__);
        }
    } while (r == -EAGAIN && ++retries < 10);
    assert(r >= 0);

    /* dubtree_find returns 0 for success, <0 for error, >0 if some blocks
     * were unresolved. */
    if (r < 0) {
        errx(1, "swap: dubtree read failed!!");
    }
    return r;
}

static inline void __swap_queue_read_acb(BlockDriverState *bs, SwapAIOCB *acb)
{
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;

    acb->next = NULL;
    int r;

    __sync_fetch_and_add(&acb->splits, 2);
    r = __swap_dubtree_read(s, acb);
#if 0 /* we used to have this to trigger fill-in reads from shallow backing */
    if (r > 0) {
        __sync_fetch_and_add(&acb->splits, 1);
        swap_signal_read(s);
    }
#else
    (void) r;
#endif
    complete_read_acb(acb);
}

static int __swap_nonblocking_read(BDRVSwapState *s, uint8_t *buf,
                                   uint64_t block, size_t size,
                                   uint8_t **ret_map)
{
    int i;
    uint64_t found = 0;
    uint8_t *map;
    size_t take;

    /* We need a map array to keep track of which blocks have been resolved
     * or not, and to which snapshot versions. */
    map = calloc(((size + SWAP_SECTOR_SIZE-1) / SWAP_SECTOR_SIZE),
                 sizeof(uint64_t));
    if (!map) {
        errx(1, "swap: OOM error in %s", __FUNCTION__);
        return -1;
    }

    for (i = 0; size > 0; ++i, size -= take, buf += SWAP_SECTOR_SIZE) {
        take = size < SWAP_SECTOR_SIZE ? size : SWAP_SECTOR_SIZE;
        uint8_t *b;
        uint64_t line;
        uint64_t value;
        uint64_t key = block + i;
        uint8_t tmp[SWAP_SECTOR_SIZE];

        if (hashtable_find(&s->cached_blocks, key, &line)) {
            b = (void*) lru_cache_touch_line(&s->bc, line)->value;
            memcpy(buf, b, take);
            map[i] = 1;
            found += take;
        } else if (hashtable_find(&s->busy_blocks, key, &value)) {
            uint8_t *dst;
            if (value & SWAP_SIZE_MASK) {
                dst = take < SWAP_SECTOR_SIZE ? tmp : buf;
                b = (void *) (uintptr_t) (value & ~SWAP_SIZE_MASK);
                int sz = value >> SWAP_SIZE_SHIFT;
                swap_get_key(dst, b, sz);
                if (dst == tmp) {
                    memcpy(buf, tmp, take);
                }
            } else {
                b = (void *) (uintptr_t) value;
                dst = b;
                memcpy(buf, b, take);
            }
            __swap_nonblocking_write(s, dst, key, SWAP_SECTOR_SIZE, 0);

            map[i] = 1;
            found += take;
        }
    }
    *ret_map = map;
    return found;
}

SwapAIOCB dummy_acb;

BlockDriverAIOCB *swap_aio_read(BlockDriverState *bs,
        int64_t sector_num, uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    //debug_printf("%s %"PRIx64" %d\n", __FUNCTION__, sector_num, nb_sectors);
    //fprintf(stderr, "%s %"PRIx64" %x\n", __FUNCTION__, sector_num, nb_sectors);
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    SwapAIOCB *acb = NULL;
    const uint64_t mask = SWAP_SECTOR_SIZE - 1;
    uint64_t offset = sector_num << BDRV_SECTOR_BITS;
    uint64_t block = offset / SWAP_SECTOR_SIZE;
    uint32_t modulo = offset & mask;
    uint32_t size = (nb_sectors << BDRV_SECTOR_BITS) + modulo;
    uint8_t *tmp = NULL;
    uint8_t *map = NULL;
    ssize_t found;

    /* XXX we should use the map to do this more precisely. */
    memset(buf, 0, nb_sectors << BDRV_SECTOR_BITS);

    if (modulo) {
        tmp = malloc(size);
        if (!tmp) {
            debug_printf("swap: unable to allocate tmp on line %d\n", __LINE__);
            return NULL;
        }
    }

    swap_lock(s);
    found = __swap_nonblocking_read(s, tmp ? tmp : buf, block, size, &map);
    if (found < 0) {
        assert(0);
        swap_unlock(s);
        free(tmp);
        return NULL;
    } else if (found == size) {
        swap_unlock(s);
        if (tmp) {
            memcpy(buf, tmp + modulo, size - modulo);
            free(tmp);
        }
        free(map);
        cb(opaque, 0);
        acb = &dummy_acb;
    } else {
        acb = swap_aio_get(bs, cb, opaque);
        if (!acb) {
            debug_printf("swap: unable to allocate acb on line %d\n", __LINE__);
            free(tmp);
            swap_unlock(s);
            return NULL;
        }
        acb->block = block;
        acb->modulo = modulo;
        acb->size = size;
        acb->buffer = buf;
        acb->tmp = tmp;
        acb->map = map;
        ioh_event_init(&acb->event, swap_read_cb, acb);

        __swap_queue_read_acb(bs, acb);
        swap_unlock(s);
    }

    return (BlockDriverAIOCB *)acb;
}

#if 0
static void
swap_complete_write_acb(SwapAIOCB *acb)
{
#ifndef LIBIMG
    if (acb->ratelimit_complete_timer) {
        free_timer(acb->ratelimit_complete_timer);
        acb->ratelimit_complete_timer = NULL;
    }
#endif
    ioh_event_set(&acb->event);
}
#endif

#ifndef LIBIMG
static void
swap_ratelimit_complete_timer_notify(void *opaque)
{
    SwapAIOCB *acb = (SwapAIOCB*)opaque;
    BDRVSwapState *s = (BDRVSwapState*) acb->bs->opaque;
    int ratelimited;

    swap_signal_write(s);

    swap_lock(s);
    ratelimited = is_ratelimited_hard(s);
    swap_unlock(s);

    if (ratelimited) {
        /* we're over block threshold of buffered data, hold writes off */
        mod_timer(acb->ratelimit_complete_timer,
                  get_clock_ms(rt_clock) + WRITE_RATELIMIT_GAP_MS);
    } else {
        swap_complete_write_acb(acb);
    }
}
#endif

static int queue_write(BDRVSwapState *s, uint64_t key, uint64_t value)
{
    HashEntry *e;

    e = hashtable_find_entry(&s->busy_blocks, key);
    if (e) {
        e->value = value;
    } else {
        hashtable_insert(&s->busy_blocks, key, value);
    }

    struct pq *pq1 = &s->pqs[s->pq_switch];
    struct pq *pq2 = &s->pqs[s->pq_switch ^ 1];;
    pq_push((s->pq_cutoff == ~0ULL || s->pq_cutoff <= key) ? pq1 : pq2, key, value); 

    return 0;
}

static int __swap_nonblocking_write(BDRVSwapState *s, const uint8_t *buf,
                                        uint64_t block, size_t size, int dirty)
{
    LruCache *bc = &s->bc;
    int n = 0;

    for (size_t i = 0; i < size / SWAP_SECTOR_SIZE; ++i) {

        uint8_t *b;
        uint64_t line;
        LruCacheLine *cl;

        if (hashtable_find(&s->cached_blocks, block + i, &line)) {
            cl = lru_cache_touch_line(bc, line);
            /* Do not overwrite previously cached entry on read. */
            if (dirty) {
                cl->dirty = dirty;
                b = (void *) cl->value;
                memcpy(b, buf + SWAP_SECTOR_SIZE * i, SWAP_SECTOR_SIZE);
            }
            continue;
        }

        if (!(b = swap_malloc(s, SWAP_SECTOR_SIZE))) {
            warn("swap: OOM error in %s", __FUNCTION__);
            return -ENOMEM;
        }

        line = lru_cache_evict_line(bc);
        cl = lru_cache_touch_line(bc, line);

        if (cl->value) {
            hashtable_delete(&s->cached_blocks, cl->key);
            if (cl->dirty) {
                queue_write(s, cl->key, cl->value);
                ++n;
            } else {
                swap_free(s, (void *) (uintptr_t) cl->value);
            }
        }

        memcpy(b, buf + SWAP_SECTOR_SIZE * i, SWAP_SECTOR_SIZE);
        cl->key = (uintptr_t) block + i;
        cl->value = (uintptr_t) b;
        cl->dirty = dirty;
        hashtable_insert(&s->cached_blocks, block + i, line);
    }
    return n;
}

/*static*/ BlockDriverAIOCB *swap_aio_write(BlockDriverState *bs,
        int64_t sector_num, const uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    //fprintf(stderr, "%s %"PRIx64" %x\n", __FUNCTION__, sector_num, nb_sectors);
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    SwapAIOCB *acb = NULL;

    if ((sector_num & 7) || (nb_sectors & 7)) {
        const uint64_t mask = SWAP_SECTOR_SIZE - 1;
        uint64_t offset = sector_num << BDRV_SECTOR_BITS;
        uint64_t count = nb_sectors << BDRV_SECTOR_BITS;
        uint64_t aligned_offset = offset & ~mask;
        uint64_t aligned_end = (offset + count + mask) & ~mask;
        uint64_t aligned_count = aligned_end - aligned_offset;
        ssize_t found;

        acb = swap_aio_get(bs, cb, opaque);
        if (!acb) {
            debug_printf("swap: unable to allocate acb on line %d\n", __LINE__);
            return NULL;
        }

        acb->block = aligned_offset / SWAP_SECTOR_SIZE;
        acb->modulo = offset & mask;
        acb->size = aligned_count;
        acb->orig_size = nb_sectors << BDRV_SECTOR_BITS;
        acb->buffer = (void*) buf;
        acb->tmp = malloc(acb->size);
        if (!acb->tmp) {
            /* XXX potential DoS here if VM does a lot of big unaligned writes.
             * Could be solved by only reading head and tail of affected
             * section and thus not needing a variable sized tmp buffer. */
            errx(1, "swap: OOM on line %d", __LINE__);
        }

        swap_lock(s);
        found = __swap_nonblocking_read(s, acb->tmp ? acb->tmp : acb->buffer,
                                        acb->block, acb->size, &acb->map);
        if (found < 0) {
            free(acb->tmp);
            free(acb);
            acb = NULL;
        } else if (found == acb->size) {
            swap_rmw_cb(acb);
            acb = NULL;
            //ioh_event_set(&acb->event);
        } else {
            ioh_event_init(&acb->event, swap_rmw_cb, acb);
            __swap_queue_read_acb(bs, acb);
        }
        swap_unlock(s);
    } else {
        /* Already done. */

        int ratelimited;
        int n;
        swap_lock(s);
        n = __swap_nonblocking_write(s, buf, sector_num / 8,
                                     nb_sectors << BDRV_SECTOR_BITS, 1);
        ratelimited = is_ratelimited_hard(s);
        swap_unlock(s);
        if (n) {
            swap_signal_write(s);
        }

        if (ratelimited) {
#ifdef LIBIMG
            swap_wait_can_write(s);
            cb(opaque, 0);
            acb = &dummy_acb;
#else
            /* late completion in order to rate limit writes */

            acb = swap_aio_get(bs, cb, opaque);
            if (!acb) {
                debug_printf("swap: unable to allocate acb on line %d\n",
                             __LINE__);
                return NULL;
            }

            ioh_event_init(&acb->event, swap_write_cb, acb);
            acb->ratelimit_complete_timer = new_timer_ms(
                    rt_clock, swap_ratelimit_complete_timer_notify, acb);
            mod_timer(acb->ratelimit_complete_timer,
                    get_clock_ms(rt_clock) + WRITE_RATELIMIT_GAP_MS);
            TAILQ_INSERT_TAIL(&s->rlimit_write_queue, acb, rlimit_write_entry);
#endif
        } else {
            /* immediate completion */
            cb(opaque, 0);
            acb = &dummy_acb;
        }

#ifdef SWAP_STATS
        acb->t1 = os_get_clock();
#endif
    }
    return (BlockDriverAIOCB *) acb;
}

int swap_flush(BlockDriverState *bs, BlockDriverCompletionFunc *cb,
        void *opaque)
{
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    LruCache *bc = &s->bc;
    //SwapAIOCB *acb, *next;
    int i;

    /* Complete ratelimited writes */

#if 0
    /* Wait for all outstanding ios completing. */
    //aio_wait_start();
    //aio_poll();
    while (s->outstanding_writes) {
        TAILQ_FOREACH_SAFE(acb, &s->rlimit_write_queue, rlimit_write_entry,
                           next)
            swap_complete_write_acb(acb);
        swap_aio_wait();
    }
    //aio_wait_end();
#endif

    swap_lock(s);
    s->flush = 1;
    s->flush_complete_cb = cb;
    s->flush_opaque = opaque;
    int n = 0;
    for (i = 0; i < (1 << bc->log_lines); ++i) {
        LruCacheLine *cl = &bc->lines[i];
        if (cl->value) {
            hashtable_delete(&s->cached_blocks, (uint64_t) cl->key);
            if (cl->dirty) {
                queue_write(s, cl->key, cl->value);
                ++n;
            } else {
                swap_free(s, (void *) (uintptr_t) cl->value);
            }
        }
        cl->key = 0;
        cl->value = 0;
        cl->dirty = 0;
    }
    swap_unlock(s);
    if (n) {
        debug_printf("swap: emptying %d cache lines\n", n);
        swap_signal_write(s);
    } else {
        if (cb) {
            cb(opaque, 0);
        }
    }
    return 0;
}

void swap_close(BlockDriverState *bs)
{
    debug_printf("%s\n", __FUNCTION__);
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;

#if 0
    printf("checking...\n");
    dubtree_sanity_check(&s->t);
    printf("checking done\n");
#endif

    /* Signal write thread to quit and wait for it. */
    s->quit = 1;

    swap_signal_write(s);
    wait_thread(s->write_thread);

    swap_signal_insert(s);
    wait_thread(s->insert_thread);

    assert(s->pqs[0].n_heap == 0);
    assert(s->pqs[1].n_heap == 0);
    assert(s->busy_blocks.load == 0);

    swap_lock(s);
    if (s->find_context) {
        dubtree_end_find(&s->t, s->find_context);
        s->find_context = NULL;
    }
    s->flush = 0;
    dubtree_checkpoint(&s->t, &s->top_id, &s->top_hash);
    swap_write_header(s, s->uuid, s->filename);
    swap_unlock(s);

    if (s->find_context) {
        dubtree_end_find(&s->t, s->find_context);
        s->find_context = NULL;
    }
    dubtree_close(&s->t);

    thread_event_close(&s->write_event);
    thread_event_close(&s->can_write_event);

    critical_section_free(&s->mutex);

    lru_cache_close(&s->bc);
    hashtable_clear(&s->cached_blocks);
    free(s->filename);
    for (int i = 0; i < s->num_fallbacks; ++i) {
        free(s->fallbacks[i]);
    }
    free(s->cache);
    free(s);
}

int swap_create(const char *filename, int64_t size, int flags)
{
    printf("%s\n", __FUNCTION__);
    (void) flags;
    FILE *file;
    uuid_t uuid;
    char uuid_str[37];
    int ret;

    if (!strncmp(filename, "swap:", 5))
        filename = &filename[5];

    file = fopen(filename, "wb");
    if (file == NULL) {
        warn("%s: unable to create %s", __FUNCTION__, filename);
        return -errno;
    }

    //uuid_generate_truly_random(uuid);
    tiny_uuid_generate_random(uuid);
    tiny_uuid_unparse(uuid, uuid_str);

    ret = fprintf(file, "uuid=%s\n", uuid_str);
    if (ret < 0) {
        warn("%s: fprintf failed", __FUNCTION__);
        ret = -errno;
        goto out;
    }

    ret = fprintf(file, "size=%"PRId64"\n", size);
    if (ret < 0) {
        warn("%s: fprintf failed", __FUNCTION__);
        ret = -errno;
        goto out;
    }

    ret = 0;
  out:
    if (file)
        fclose(file);
    return ret;
}

int swap_snapshot(BlockDriverState *bs, uuid_t uuid)
{
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    char uuid_str[37];
    char *dn, *fn;
    int r;

    tiny_uuid_generate_random(uuid);
    tiny_uuid_unparse(uuid, uuid_str);

    r = dubtree_mkdir("snapshots");
    if (r < 0 && errno != EEXIST) {
        warn("unable to create snapshots directory");
        return -1;
    }

    r = asprintf(&dn, "snapshots/swapdata-%s", uuid_str);
    if (r < 0) {
        errx(1, "%s:%d asprintf failed", __FUNCTION__, __LINE__);
    }

    r = dubtree_snapshot(&s->t, dn);
    if (r < 0) {
        warnx("snapshot %s failed", uuid_str);
        return r;
    }
    r = asprintf(&fn, "snapshots/%s.swap", uuid_str);
    if (r < 0) {
        errx(1, "%s: asprintf failed", __FUNCTION__);
    }
    if (s->swapdata) {
        warnx("WARNING: snapshotting disk with swapdata at %s!", s->swapdata);
    }
    r = swap_write_header(s, uuid, fn);
    if (r < 0) {
        warnx("failed to write header %s", fn);
    }
    free(fn);
    free(dn);
    return r;
}

int swap_getsize(BlockDriverState *bs, uint64_t *result) {
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    if (result) {
        *result = s->size;
        return 0;
    } else {
        return -1;
    }
}

int swap_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    if (req == 0) {
        if (!buf) {
            return -EINVAL;
        }
        memcpy(buf, s->uuid, sizeof(uuid_t));
        return sizeof(uuid_t);
    } else if (req == 1) {
        if (!buf) {
            return -EINVAL;
        }
        int sl = *((int *) buf);
        return dubtree_insert(&s->t, 0, NULL, NULL, NULL, sl, NULL, NULL);
    } else if (req == 2) {
        return dubtree_sanity_check(&s->t);
    } else if (req == 3) {
        s->store_uncompressed = 1;
        return 0;
    }
    return -ENOTSUP;
}

#if 0
BlockDriver bdrv_swap = {
    .format_name = "swap",
    .instance_size = sizeof(BDRVSwapState),
    .bdrv_probe = NULL, /* no probe for protocols */
    .bdrv_open = swap_open,
    .bdrv_close = swap_close,
    .bdrv_create = swap_create,
    .bdrv_flush = swap_flush,
    .bdrv_remove = swap_remove,

    .bdrv_aio_read = swap_aio_read,
    .bdrv_aio_write = swap_aio_write,

    .bdrv_ioctl = swap_ioctl,

    .protocol_name = "swap",
};
#endif
