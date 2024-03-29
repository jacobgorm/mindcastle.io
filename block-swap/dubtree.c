#include "dubtree_sys.h"
#include "dubtree_io.h"

#include "aio.h"
#include "crypto.h"
#include "dubtree.h"
#include "lrucache.h"
#include "simpletree.h"
#include "lz4.h"
#include "hex.h"
#include "rtc.h"
#include "safeio.h"

/* These must go last or they will mess with e.g. asprintf() */
#include <curl/curl.h>
#include <curl/easy.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifndef _WIN32
//#include <aio.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <errno.h>
#include <sys/uio.h>
#include <limits.h>
#include <fcntl.h>
#else
#endif

#ifndef CURL_MAX_READ_SIZE
#define CURL_MAX_READ_SIZE (1<<19)
#endif

static dubtree_handle_t prepare_http_get(DubTree *t,
        int synchronous, const char *url, chunk_id_t chunk_id);

static void __put_chunk(DubTree *t, int line);
static void put_chunk(DubTree *t, int line);
static dubtree_handle_t __get_chunk(DubTree *t, chunk_id_t chunk_id,
                                       int dirty, int local, int *l);
static dubtree_handle_t get_chunk(DubTree *t, chunk_id_t chunk_id,
                                     int dirty, int local, int *l);
static int __get_chunk_fd(DubTree *t, chunk_id_t chunk_id);
static int get_chunk_fd(DubTree *t, chunk_id_t chunk_id);
static chunk_id_t content_id(const uint8_t *in, int size);

typedef struct CacheLineUserData {
    dubtree_handle_t f;
    chunk_id_t chunk_id;
} CacheLineUserData;

typedef struct UserData {
    uint32_t level;
    struct level_ptr next;
    uint32_t fragments;
    uint64_t garbage;
    uint64_t size;        /* How many bytes are addressed by this tree. */
    uint32_t num_chunks;
    chunk_id_t chunk_ids[0];
} UserData;

static inline size_t ud_size(const UserData *cud, size_t n)
{
    return sizeof(*cud) + sizeof(cud->chunk_ids[0]) * n;
}

static inline int chunk_deref(DubTree *t, chunk_id_t chunk_id)
{
    HashEntry *e = hashtable_find_entry(&t->refcounts_ht, chunk_id.id.first64);
    if (e) {
        return --(e->value);
    }
    errx(1, "trying to deref chunk not in hashtable");
    return -1;
}

static inline void chunk_ref(DubTree *t, chunk_id_t chunk_id)
{
    HashEntry *e = hashtable_find_entry(&t->refcounts_ht, chunk_id.id.first64);
    if (e) {
        e->value++;
    } else {
        hashtable_insert(&t->refcounts_ht, chunk_id.id.first64, 1);
    }
}

int dubtree_init(DubTree *t, const uint8_t *key,
        chunk_id_t top_id, hash_t top_hash,
        char **fallbacks, char *cache,
        int use_large_values)
{
    char *fn;
    char **fb;

    memset(t, 0, sizeof(DubTree));
    t->crypto_key = key;
    t->use_large_values = use_large_values;

    t->head_ch = curl_easy_init();
    t->shared_ch = curl_easy_init();

    critical_section_init(&t->cache_lock);
    critical_section_init(&t->write_lock);

    critical_section_enter(&t->cache_lock);
    hashtable_init(&t->ht, NULL, NULL);
    const int log_cache_lines = 4;
    lru_cache_init(&t->lru, log_cache_lines);
    t->cache_infos = calloc(1 << log_cache_lines, sizeof(CacheLineUserData));
    hashtable_init(&t->refcounts_ht, NULL, NULL);

    fb = t->fallbacks;
    for (size_t i = 0; i < sizeof(t->fallbacks) / sizeof(t->fallbacks[0]); ++i) {
        char *in;
        if (cache && i == 1) {
            in = cache;
            dubtree_mkdir(cache);
            t->cache = dubtree_realpath(cache);
        } else {
            in = *fallbacks++;
        }
        if (!in) {
            break;
        }
        if (!(*fb = dubtree_realpath(in))) {
            *fb = strdup(in);
        }
        ++fb;
    }
    *fb = NULL;

    fn = t->fallbacks[0];
    dubtree_mkdir(fn);

    t->first.level = -1;

    if (valid_chunk_id(&top_id)) {
        SimpleTree st;
        Crypto crypto;
        crypto_init(&crypto, t->crypto_key);
        simpletree_open(&st, &crypto, __get_chunk_fd(t, top_id), top_hash);
        const UserData *cud = simpletree_get_user(&st);
        t->first.level = cud->level;

        struct level_ptr next = { cud->level, top_id, top_hash };
        t->first = next;

        simpletree_close(&st);

        while (next.level >= 0) {
            SimpleTree st;
            simpletree_open(&st, &crypto, __get_chunk_fd(t, next.level_id),
                    next.level_hash);
            const UserData *cud = simpletree_get_user(&st);
            for (size_t j = 0; j < cud->num_chunks; ++j) {
                chunk_ref(t, cud->chunk_ids[j]);
            }
            next = cud->next;
            simpletree_close(&st);
        }
        crypto_close(&crypto);
    }

    critical_section_leave(&t->cache_lock);
    return 0;
}

int dubtree_checkpoint(DubTree *t, chunk_id_t *top_id, hash_t *top_hash)
{
    *top_id = t->first.level_id;
    *top_hash = t->first.level_hash;
    return 0;
}

typedef struct Read {
    uint32_t src_offset;
    uint32_t dst_offset;
    uint32_t size;
} Read;

typedef struct ChunkReads {
    chunk_id_t chunk_id;
    int num_reads;
    Read *reads;
} ChunkReads;

typedef struct Chunk {
    HashTable ht;
    int n_crs;
    ChunkReads *crs;
} Chunk;

void clear_chunk(Chunk *c) {
    hashtable_clear(&c->ht);
    free(c->crs);
    c->n_crs = 0;
    c->crs = NULL;
}

static inline void read_chunk(DubTree *t, Chunk *d, chunk_id_t chunk_id,
        uint32_t dst_offset, uint32_t src_offset,
        uint32_t size)
{
    (void) t;
    ChunkReads *cr;
    Read *rd;
    uint64_t v;

    if (hashtable_find(&d->ht, chunk_id.id.first64, &v)) {
        cr = &d->crs[v];
    } else {
        int n = d->n_crs++;
        if (!((n - 1) & n)) {
            /* XXX we do this once per find(). */
            d->crs = realloc(d->crs, sizeof(d->crs[0]) * (n ? 2 * n : 1));
            if (!d->crs) {
                errx(1, "%s: malloc failed line %d", __FUNCTION__, __LINE__);
            }
        }

        cr = &d->crs[n];
        memset(cr, 0, sizeof(*cr));
        cr->chunk_id = chunk_id;
        hashtable_insert(&d->ht, chunk_id.id.first64, n);
    }

    int n = cr->num_reads++;
    if (!((n - 1) & n)) {
        /* XXX we do this once per find(). */
        cr->reads = realloc(cr->reads, sizeof(cr->reads[0]) * (n ? 2 * n: 1));
        if (!cr->reads) {
            errx(1, "%s: realloc failed line %d", __FUNCTION__, __LINE__);
        }
    }

    rd = &cr->reads[n];
    rd->src_offset = src_offset;
    rd->dst_offset = dst_offset;
    rd->size = size;
}

static void set_event_cb(void *opaque, int result)
{
    (void) result;
#ifdef _WIN32
    SetEvent(opaque);
#else
    if (opaque) {
        int fd = (int) (intptr_t) opaque;
        char msg = 1;
        int r = write(fd, &msg, sizeof(msg));
        if (r != sizeof(msg)) {
            fprintf(stderr, "r=%d write err %s\n", r, strerror(errno));
        }
        if (r != sizeof(msg)) {
            err(1, "pipe read failed");
        }
        close(fd);
    }
#endif
}

typedef struct CallbackState {
    read_callback cb;
    void *opaque;
    volatile uint32_t counter;
    int result;
} CallbackState;

typedef struct DecryptState {
    read_callback cb;
    void *opaque;
    uint8_t *buffer;
    int num_keys;
    uint32_t *sizes;
    Crypto *crypto;
    uint8_t *hashes;
} DecryptState;

static inline
void increment_counter(CallbackState *cs)
{
    __sync_fetch_and_add(&cs->counter, 1);
}

static inline
void decrement_counter(CallbackState *cs)
{
    if (__sync_fetch_and_sub(&cs->counter, 1) == 1) {
        if (cs->cb) {
            cs->cb(cs->opaque, cs->result);
        }
        free(cs);
    }
}

static void decrypt_read(void *opaque, int result)
{
    DecryptState *ds = opaque;
    if (result >= 0) {
        const uint8_t *hash = ds->hashes;
        uint8_t *dst = ds->buffer;
        const uint8_t *src = ds->buffer;

        uint8_t inline_tmp[0x10000];
        size_t max_size = 0;
        for (int i = 0; i < ds->num_keys; ++i) {
            if (ds->sizes[i] > CRYPTO_IV_SIZE) {
                uint32_t size = ds->sizes[i] - CRYPTO_IV_SIZE;
                max_size = size > max_size ? size : max_size;
            }
        }
        uint8_t *tmp = max_size > sizeof(inline_tmp) ? malloc(max_size) : inline_tmp;

        for (int i = 0; i < ds->num_keys; ++i, hash += CRYPTO_TAG_SIZE) {
            uint32_t size = ds->sizes[i];
            if (size > CRYPTO_IV_SIZE) {
                int dsize = decrypt256(ds->crypto, tmp, src + CRYPTO_IV_SIZE, size - CRYPTO_IV_SIZE, hash, src);
                if (dsize <= 0) {
                    warnx("failed decrypting read, size=%u, dsize=%d", size, dsize);
                } else {
                    memcpy(dst, tmp, dsize);
                }
                src += size;
                dst += dsize;
                ds->sizes[i] = dsize > 0 ? dsize : 0;
            }
        }
        if (tmp != inline_tmp) {
            free(tmp);
        }
    }
    ds->cb(ds->opaque, result);
    free(ds->hashes);
    free(ds);
}

#ifdef _WIN32
typedef struct {
    OVERLAPPED o; // first
    DubTree *t;
    Read *first;
    int n;
    uint8_t *dst;
    uint8_t *buf;
    int size;
    CallbackState *cs;
} ReadContext;

static void CALLBACK read_complete_scatter(DWORD rc, DWORD got, OVERLAPPED *o)
{
    int i;
    Read *rd;
    ReadContext *ctx = (ReadContext *) o;
    DubTree *t = ctx->t;
    CallbackState *cs = ctx->cs;

    if (ctx->buf) {
        uint8_t *in = ctx->buf;
        int size = 0;

        for (i = 0, rd = ctx->first; i < ctx->n; ++i, ++rd) {
            size += rd->size;
            assert(size <= ctx->size);
            memcpy(ctx->dst + rd->dst_offset, in, rd->size);
            in += rd->size;
        }

        t->free_cb(t->opaque, ctx->buf);
    }
    free(ctx->first);
    free(ctx);
    decrement_counter(cs);
}
#endif

#define MAX_BLOCKED_READS 256

typedef struct {
    chunk_id_t chunk_id;
    int refcount;
    double t0;
    DubTree *t;
    char *url;
    int active;
    int synchronous;
    uint32_t size;
    int fd;
    uint32_t split;
    uint32_t offset;
    critical_section lock; /* protects members below */
    int is_buffering;
    int num_blocked;
    int num_unblocked;
    struct {
        CallbackState *cs;
        uint8_t *dst;
        Read *first;
        int n; } *blocked_reads;
} HttpGetState;

static inline HttpGetState *hgs_ref(HttpGetState *hgs) {
    ++(hgs->refcount);
    return hgs;
}

static inline void hgs_deref(HttpGetState *hgs) {
    if (--(hgs->refcount) == 0) {
        critical_section_free(&hgs->lock);
        free(hgs->url);
        free(hgs->blocked_reads);
        free(hgs);
    }
}

static inline int reads_inside_buffer(const HttpGetState *hgs, const Read *first, int n)
{
    uint32_t begin = first->src_offset;
    uint32_t end = first[n - 1].src_offset + first[n - 1].size;
    if (hgs->offset > hgs->split) { // right side fetch
        return hgs->split <= begin && end <= hgs->offset;
    } else if (hgs->offset < hgs->split) { // left side fetch
        return end <= hgs->offset || begin >= hgs->split;
    } else {
        return 0;
    }
}

int curl_sockopt_cb(void *clientp, curl_socket_t curlfd, curlsocktype purpose);
static size_t curl_data_cb(void *ptr, size_t size, size_t nmemb, void *opaque);

static void prep_curl_handle(CURL *ch, const char *url, const char *ranges,
        void *opaque)
{
    curl_easy_setopt(ch, CURLOPT_URL, url);
    curl_easy_setopt(ch, CURLOPT_BUFFERSIZE, CURL_MAX_READ_SIZE);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, opaque);
    curl_easy_setopt(ch, CURLOPT_PRIVATE, opaque);
    curl_easy_setopt(ch, CURLOPT_SOCKOPTFUNCTION, curl_sockopt_cb);
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_data_cb);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 60L);

    if (ranges) {
        curl_easy_setopt(ch, CURLOPT_RANGE, ranges);
    }
}

void dubtree_cleanup_curl_handle(CURL *ch)
{
    HttpGetState *hgs;
    curl_easy_getinfo(ch, CURLINFO_PRIVATE, &hgs);
    hgs_deref(hgs);
}

static int execute_reads(DubTree *t,
        uint8_t *dst,
        dubtree_handle_t f,
        Read *first, int n,
        CallbackState *cs)
{
    (void) t;
    int i;
    Read *rd;

    HttpGetState *hgs = f->opaque;
    if (hgs) {
        int resolved = 0;
        critical_section_enter(&hgs->lock);
        if (hgs->is_buffering) {
            if (hgs->active && reads_inside_buffer(hgs, first, n)) {
                for (i = 0, rd = first; i < n; ++i, ++rd) {
                    ssize_t got = safe_pread(hgs->fd, dst + rd->dst_offset,
                            rd->size, rd->src_offset);
                    if (got != rd->size) {
                        err(1, "%s: pread() failed", __FUNCTION__);
                    }

                }
                free(first);
            } else {
                if (!hgs->active) {
                    CURL *ch = curl_easy_init();
                    char ranges[32];
                    sprintf(ranges, "%u-%u", first->src_offset, hgs->chunk_id.size - 1);
                    prep_curl_handle(ch, hgs->url, ranges, hgs_ref(hgs));
                    aio_add_curl_handle(ch);
                    hgs->split = hgs->offset = first->src_offset;
                    hgs->active = 1;
                }
                increment_counter(cs);
                int nb = hgs->num_blocked++;
                if (!((nb - 1) & nb)) {
                    hgs->blocked_reads = realloc(hgs->blocked_reads, sizeof(hgs->blocked_reads[0]) * (nb ? 2 * nb: 1));
                    if (!hgs->blocked_reads) {
                        errx(1, "%s: realloc failed line %d", __FUNCTION__, __LINE__);
                    }
                }
                hgs->blocked_reads[nb].cs = cs;
                hgs->blocked_reads[nb].dst = dst;
                hgs->blocked_reads[nb].first = first;
                hgs->blocked_reads[nb].n = n;
            }
            resolved = 1;
        }
        critical_section_leave(&hgs->lock);
        if (resolved) {
            return 0;
        }
    }

#ifdef _WIN32
    uint32_t size;
    int contig = 1;
    for (i = size = 0, rd = first; i < n; ++i, ++rd) {
        if (first->dst_offset + size != rd->dst_offset) {
            contig = 0;
        }
        size += rd->size;
    }
    ReadContext *ctx = calloc(1, sizeof(*ctx));
    ctx->t = t;
    ctx->first = first;
    ctx->n = n;
    ctx->dst = dst;
    if (contig) {
        ctx->buf = NULL;
    } else {
        ctx->buf = t->malloc_cb(t->opaque, size);
        if (!ctx->buf) {
            errx(1, "%s: malloc failed", __FUNCTION__);
            return -1;
        }
    }
    ctx->size = size;
    ctx->cs = cs;
    increment_counter(cs);

    ctx->o.Offset = first->src_offset;
    if (!ReadFileEx(f, ctx->buf ? ctx->buf : dst + first->dst_offset, size,
                &ctx->o, read_complete_scatter)) {
        Werr(1, "ReadFileEx failed");
        return -1;
    }
#else

#ifdef __APPLE__

    int r;

    if (n > 1) {
        struct radvisory ra = {first->src_offset,
            first[n - 1].src_offset + first[n - 1].size - first->src_offset};
        r = fcntl(f, F_RDADVISE, &ra);
        assert(r >= 0);
    }

    for (i = 0, rd = first; i < n; ++i, ++rd) {
        do {
            r = pread(f, dst + rd->dst_offset, rd->size, rd->src_offset);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            err(1, "pread failed f=%d r %d", f, r);
        }
    }

#else

    int take;
    int r;
    for (i = 0, rd = first; i < n; i += take) {
        int j;
        uint32_t offset;
        struct iovec v[IOV_MAX];
        take = (n - i) < IOV_MAX ? (n - i): IOV_MAX;

        for (j = 0, offset = rd->src_offset; j < take; ++j, ++rd) {
            v[j].iov_base = dst + rd->dst_offset;
            v[j].iov_len = rd->size;
        }
        do {
            r = preadv(f->fd, v, take, offset);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            err(1, "preadv failed f=%d r %d", f->fd, r);
        }
        assert(r >= 0);
    }
#endif
    free(first);

#endif

    return 0;
}

static int flush_chunk(DubTree *t, uint8_t *dst, dubtree_handle_t f,
        ChunkReads *cr, CallbackState *cs)
{
    int i, j;
    int n = cr->num_reads;
    Read *reads = cr->reads;
    Read *first = reads;
    Read *rd, *prev;
    int r = 0;

    for (i = 1, j = 0; i < n + 1; ++i) {
        rd = &reads[i];
        prev = &reads[i - 1];

        if (i == n || rd->src_offset != prev->src_offset + prev->size) {
            if (j > 0 || i < n) {
                first = malloc((i - j) * sizeof(*first));
                memcpy(first, reads + j, (i - j) * sizeof(*first));
            }
            r = execute_reads(t, dst, f, first, i - j, cs);
            if (r < 0) {
                printf("execute_reads failed, r=%d\n", r);
                break;
            }
            j = i;
        }
    }

    if (first != reads) {
        free(reads);
    }
    return r;
}

static int flush_reads(DubTree *t, const Chunk *c, void *buf,
        const uint8_t *chunk0, int local, CallbackState *cs)
{
    int i, j;
    int r = 0;

    for (i = 0; i < c->n_crs; ++i) {
        ChunkReads *cr = &c->crs[i];
        if (!valid_chunk_id(&cr->chunk_id)) {

            Read *first = cr->reads;
            Read *rd;
            for (j = 0, rd = first; j < cr->num_reads; ++j, ++rd) {
                memcpy(buf + rd->dst_offset, chunk0 + rd->src_offset,
                       rd->size);
            }
            free(first);
            r = 0;

        } else {
            dubtree_handle_t f;
            int l;

            f = get_chunk(t, cr->chunk_id, 0, local, &l);
            if (valid_handle(f)) {
                r = flush_chunk(t, buf, f, cr, cs);
                put_chunk(t, l);
            } else {
                free(cr->reads);
                r = -1;
            }
            if (r < 0) {
                break;
            }
        }
    }
    return r;
}

static int __get_chunk_fd(DubTree *t, chunk_id_t chunk_id)
{
    int line = -1;
    dubtree_handle_t f = __get_chunk(t, chunk_id, 0, 1, &line);
    if (invalid_handle(f)) {
        assert(0);
        return -1;
    }
    int r = dup(f->fd);
    __put_chunk(t, line);
    return r;
}

static int get_chunk_fd(DubTree *t, chunk_id_t chunk_id)
{
    critical_section_enter(&t->cache_lock);
    int r = __get_chunk_fd(t, chunk_id);
    critical_section_leave(&t->cache_lock);
    return r;
}

static inline int add_chunk_id(UserData **pud)
{
    UserData *ud = *pud;
    int n = ud->num_chunks++;
    if (!((n - 1) & n)) {
        *pud = ud = realloc(ud, sizeof(UserData) +
                sizeof(chunk_id_t) * (n ? 2 * n: 1));
        if (!ud) {
            errx(1, "%s: malloc failed", __FUNCTION__);
            return -1;
        }
    }
    return n;
}

typedef struct CachedTree {
    struct SimpleTree st;
    chunk_id_t chunk;
} CachedTree;

typedef struct FindContext {
    CachedTree cached_trees[DUBTREE_MAX_LEVELS];
#ifdef _WIN32
    HANDLE event;
#endif
    Crypto crypto;
} FindContext;

void *dubtree_prepare_find(DubTree *t)
{
    (void) t;
    FindContext *fx = calloc(1, sizeof(FindContext));
#ifdef _WIN32
    fx->event = CreateEvent(NULL, FALSE, FALSE, NULL);
#endif
    crypto_init(&fx->crypto, t->crypto_key);
    return fx;
}

void dubtree_end_find(DubTree *t, void *ctx)
{
    (void) t;
    FindContext *fx = ctx;
    int i;

    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        CachedTree *ct = &fx->cached_trees[i];
        if (valid_chunk_id(&ct->chunk)) {
            clear_chunk_id(&ct->chunk);
            simpletree_close(&ct->st);
        }
    }
#ifdef _WIN32
    CloseHandle(fx->event);
#endif
    crypto_close(&fx->crypto);
    free(fx);
}

int dubtree_find(DubTree *t, uint64_t start, int num_keys,
        uint8_t *buffer, size_t *buffer_size,
        uint8_t *map, uint32_t *sizes,
        read_callback cb, void *opaque, void *ctx)
{
    int i, r;
    struct source {
        chunk_id_t chunk_id;
        uint32_t offset;
        uint32_t size;
        hash_t hash;
    };
    const int max_inline_keys = 8;
    struct source inline_sources[max_inline_keys];
    uint8_t inline_versions[max_inline_keys];
    struct source *sources = NULL;
    uint8_t *versions = NULL;
    int succeeded;
    int missing;
    uint8_t *hashes = malloc(num_keys * sizeof(hash_t));

    FindContext *fx = ctx;

    if (num_keys > max_inline_keys) {
        sources = calloc(num_keys, sizeof(sources[0]));
        if (!sources) {
            printf("%s: OOM line %d\n", __FUNCTION__, __LINE__);
            r = -1;
            goto out;
        }

        versions = calloc(num_keys, sizeof(versions[0]));
        if (!versions) {
            printf("%s: OOM line %d\n", __FUNCTION__, __LINE__);
            r = -1;
            goto out;
        }
    } else {
        memset(inline_sources, 0, sizeof(inline_sources));
        sources = inline_sources;
        memset(inline_versions, 0, sizeof(inline_versions));
        versions = inline_versions;
    }

    DecryptState *ds = calloc(1, sizeof(DecryptState));
    CallbackState *cs = calloc(1, sizeof(CallbackState));
    assert(cb);
    ds->cb = cb;
    ds->opaque = opaque;
    ds->sizes = sizes;
    ds->buffer = buffer;
    ds->num_keys = num_keys;
    ds->crypto = &fx->crypto;
    ds->hashes = hashes;

    cs->cb = decrypt_read;
    cs->opaque = ds;
    increment_counter(cs);

    succeeded = 1; // so far so good.

    /* Initialize result vectors. */
    if (map) {
        memcpy(versions, map, sizeof(versions[0]) * num_keys);
    } else {
        memset(versions, 0, sizeof(versions[0]) * num_keys);
    }
    memset(sizes, 0, sizeof(sizes[0]) * num_keys);

    /* How many keys do we actually need to get? Some may have been
     * filled out already by the caller so do not count those. */

    for (i = missing = 0; i < num_keys; ++i) {
        if (!map || map[i] == 0) ++missing;
    }

    /* Open all the trees. */
    critical_section_enter(&t->cache_lock);

    struct level_ptr next = t->first;

    for (i = 0; i < DUBTREE_MAX_LEVELS && next.level >= 0; ++i) {
        CachedTree *ct = &fx->cached_trees[i];
        SimpleTree *st = NULL;
        if (valid_chunk_id(&ct->chunk)) {
            st = &ct->st;
            if (next.level != i || !equal_chunk_ids(&ct->chunk, &next.level_id)) {
                simpletree_close(st);
                st = NULL;
                clear_chunk_id(&ct->chunk);
            }
        }
        if (next.level == i && !st) {
            st = &ct->st;
            simpletree_open(st, &fx->crypto, __get_chunk_fd(t, next.level_id),
                    next.level_hash);
            ct->chunk = next.level_id;
        }

        if (st) {
            const UserData *cud = simpletree_get_user(st);
            next = cud->next;
        }
    }
    critical_section_leave(&t->cache_lock);

    /* Check for relevant keys in all cached trees. */
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        CachedTree *ct = &fx->cached_trees[i];
        if (valid_chunk_id(&ct->chunk)) {
            SimpleTree *st = &ct->st;
            SimpleTreeIterator it;
            SimpleTreeResult k;
            if (simpletree_find(st, start, &it)) {
                const UserData *cud = simpletree_get_user(st);
                while (missing && !simpletree_at_end(st, &it)) {

                    uint64_t block;
                    int idx;

                    k = simpletree_read(st, &it);
                    block = k.key;
                    idx = block - start;

                    if (block >= start + num_keys) {
                        break;
                    }

                    /* The youngest data is always at the top of the tree,
                     * so only include a key into the returned result if we
                     * did not have one already. */
                    if (!versions[idx]) {
                        versions[idx] = 1;
                        sources[idx].chunk_id = cud->chunk_ids[k.value.chunk];
                        sources[idx].offset = k.value.offset;
                        sources[idx].size = k.value.size;
                        sources[idx].hash = k.value.hash;
                        --missing;
                    }
                    simpletree_next(st, &it);
                }
            }
        }
    }


    /* Copy out the values we found. */
    Chunk c = {};
    hashtable_init(&c.ht, NULL, NULL);

    int dst;
    uint32_t read_total = 0;
    for (i = dst = 0; i < num_keys; ++i) {
        int size = sources[i].size;
        if (size) {
            read_chunk(t, &c, sources[i].chunk_id, dst, sources[i].offset,
                       size);
        }
        sizes[i] = size;
        read_total += size;
        memcpy(hashes + CRYPTO_TAG_SIZE * i, sources[i].hash.bytes,
                CRYPTO_TAG_SIZE);
        dst += size;
    }

    if (read_total <= *buffer_size) {
        r = flush_reads(t, &c, buffer, NULL, 0, cs);
        clear_chunk(&c);
    } else {
        *buffer_size = read_total;
        r = -ENOSPC;
    }
    if (r < 0) {
        succeeded = 0;
    }

    /* Return 0 or positive value indicating number of unresolved blocks on
     * succes. Negative return means error. */

    r = succeeded ? missing : -EAGAIN;
    /* Since versions array started out as a copy of map, it is safe to
     * copy it back wholesale. */
    if (succeeded && map) {
        memcpy(map, versions, sizeof(map[0]) * num_keys);
    }

    cs->result = r;
    decrement_counter(cs);
    cs = NULL;

#ifdef _WIN32
    if (!cb) {
        for (;;) {
            int r = WaitForSingleObjectEx(fx->event, INFINITE, TRUE);
            if (r == WAIT_OBJECT_0) {
                break;
            } else if (r == WAIT_IO_COMPLETION) {
                continue;
            } else {
                Werr(1, "r %x");
            }
        }
    }
#endif

out:
    if (num_keys > max_inline_keys) {
        free(sources);
        free(versions);
    }
    return r; /* negative for error, positive if unresolved blocks. */
}


/* Heap helper functions. */

typedef struct {
    SimpleTree *st;
    SimpleTreeIterator it;
    int level;
    uint64_t key;
    uint32_t chunk;
    uint32_t offset;
    uint32_t size;
    hash_t hash;
    chunk_id_t chunk_id;
} HeapElem;

static inline int heap_less_than(DubTree *t, HeapElem *a,
        HeapElem *b)
{
    (void) t;
    if (a->key != b->key) {
        return (a->key < b->key);
    } else {
        return (a->level < b->level);
    }
}

static inline void sift_up(DubTree *t, HeapElem **hp, size_t child)
{
    (void) t;
    size_t parent;
    for (; child; child = parent) {
        parent = (child - 1) / 2;

        if (heap_less_than(t, hp[child], hp[parent])) {

            HeapElem *tmp = hp[parent];
            hp[parent] = hp[child];
            hp[child] = tmp;

        } else {
            break;
        }
    }
}

static inline void sift_down(DubTree *t, HeapElem **hp, size_t end)
{
    size_t parent = 0;
    size_t child;
    HeapElem *tmp;
    for (;; parent = child) {
        child = 2 * parent + 1;

        if (child >= end)
            break;

        /* point to the min child */
        if (child + 1 < end &&
                heap_less_than(t, hp[child + 1], hp[child])) {
            ++child;
        }

        /* heap condition restored? */
        if (heap_less_than(t, hp[parent], hp[child])) {
            break;
        }

        /* else swap and continue. */
        tmp = hp[parent];
        hp[parent] = hp[child];
        hp[child] = tmp;
    }
}

static inline char *name_chunk(const char *prefix, chunk_id_t chunk_id)
{
    char *fn;
    char h[65];
    hex(h, chunk_id.id.bytes, 32);
    h[64] = '\0';
    asprintf(&fn, "%s/%s.lvl", prefix, h);
    return fn;
}

int curl_sockopt_cb(void *clientp, curl_socket_t curlfd, curlsocktype purpose)
{
    (void) clientp;
    (void) purpose;
    int size;
    int r;
    for (size = 1 << 22; size != 0; size >>= 1) {
        r = setsockopt(curlfd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
        if (r == 0) {
            break;
        }
    }
    for (size = 1 << 22; size != 0; size >>= 1) {
        r = setsockopt(curlfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
        if (r == 0) {
            break;
        }
    }
    return r;
}

static void close_chunk_file(dubtree_handle_t f)
{
    assert(f);
    if (f->opaque) {
        hgs_deref(f->opaque);
    }
    dubtree_close_file(f);
}

static chunk_id_t content_id(const uint8_t *in, int size)
{
    chunk_id_t chunk_id;
    chunk_id.size = size;

#if 1
    uint8_t tmp[512 / 8];
    SHA512(in, size, tmp);
    memcpy(chunk_id.id.bytes, tmp, sizeof(chunk_id.id.bytes));
#else
    unsigned int len;

    EVP_MD_CTX *mdctx;

    if((mdctx = EVP_MD_CTX_create()) == NULL) {
        errx(1, "EVP_MD_CTX_create failed");
    }

    if(1 != EVP_DigestInit_ex(mdctx, EVP_blake2b512(), NULL)) {
        errx(1, "EVP_DigestInit_ex failed");
    }

    if(1 != EVP_DigestUpdate(mdctx, in, size)) {
        errx(1, "EVP_DigestUpdate failed");
    }

    if(1 != EVP_DigestFinal_ex(mdctx, chunk_id.id.bytes, &len)) {
        errx(1, "EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_destroy(mdctx);
#endif
    return chunk_id;
}

static chunk_id_t file_content_id(int fd, size_t size)
{
    uint8_t tmp[512 / 8];
    chunk_id_t result;
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    off_t offset = 0;
    for (;;) {
        uint8_t buffer[0x10000];
        size_t left = size - offset;
        size_t take = left < sizeof(buffer) ? left : sizeof(buffer);
        ssize_t got = safe_pread(fd, buffer, take, offset);
        if (got > 0) {
            SHA512_Update(&ctx, buffer, got);
            offset += got;
        } else if (got < 0) {
            err(1, "%s: pread() failed", __FUNCTION__);
        } else if ((size_t) got < sizeof(buffer)) {
            break;
        }
    }
    SHA512_Final(tmp, &ctx);
    memcpy(result.id.bytes, tmp, sizeof(result.id.bytes));
    result.size = size;
    return result;
}

static size_t curl_data_cb(void *ptr, size_t size, size_t nmemb, void *opaque)
{
    //printf("%s %zu\n", __FUNCTION__, size * nmemb);
    int done = 0;
    int r;
    HttpGetState *hgs = opaque;
    critical_section_enter(&hgs->lock);

    size_t wrote = safe_pwrite(hgs->fd, ptr, size * nmemb, hgs->offset);
    if (wrote != size * nmemb) {
        err(1, "%s: pwrite failed", __FUNCTION__);
    }
    hgs->offset += size * nmemb;

    if ((hgs->offset == hgs->size) || (hgs->offset == hgs->split)) {
        if (hgs->split > 0 && hgs->offset > hgs->split) {
            CURL *ch = curl_easy_init();
            hgs->offset = 0;
            char ranges[32];
            sprintf(ranges, "0-%u", hgs->split - 1);
            prep_curl_handle(ch, hgs->url, ranges, hgs_ref(hgs));
            aio_add_curl_handle(ch);
        } else {
            fprintf(stderr, "%s %.2fMiB/s\n", hgs->url, (double) (hgs->size) / (1024.0 * 1024.0 * (rtc() - hgs->t0)));
            DubTree *t = hgs->t;
            if (t->cache) {
                char procfn[32];
                sprintf(procfn, "/proc/self/fd/%d", hgs->fd);
                chunk_id_t real_id = file_content_id(hgs->fd, hgs->chunk_id.size);

                if (equal_chunk_ids(&real_id, &hgs->chunk_id)) {
                    char *fn = name_chunk(t->cache, hgs->chunk_id);
                    r = linkat(AT_FDCWD, procfn, AT_FDCWD, fn, AT_SYMLINK_FOLLOW);
                    if (r < 0 && errno != EEXIST) {
                        warn("linkat failed for %d -> %s", hgs->fd, fn);
                    }
                    free(fn);
                } else {
                    fprintf(stderr, "chunk damaged in transit, not caching!!\n");
                }
            }
            hgs->active = 0;
            done = 1;
        }
    }

    for (int i = 0; i < hgs->num_blocked; ++i) {
        Read *first = hgs->blocked_reads[i].first;
        if (first) {
            int n = hgs->blocked_reads[i].n;
            assert(n >= 1);
            if (done || reads_inside_buffer(hgs, first, n)) {
                Read *rd = first;
                for (int j = 0; j < n; ++j, ++rd) {
                    size_t got = safe_pread(hgs->fd,
                            hgs->blocked_reads[i].dst + rd->dst_offset,
                            rd->size, rd->src_offset);
                    if (got != rd->size) {
                        err(1, "%s: pread failed", __FUNCTION__);
                    }
                }
                hgs->blocked_reads[i].first = NULL;
                decrement_counter(hgs->blocked_reads[i].cs);
                free(first);
                ++(hgs->num_unblocked);
            }
        }
    }

    if (done) {
        hgs->is_buffering = 0;
        close(hgs->fd);
        hgs->fd = -1;
    }
    critical_section_leave(&hgs->lock);

    return size * nmemb;
}

static dubtree_handle_t prepare_http_get(DubTree *t,
        int synchronous, const char *url, chunk_id_t chunk_id)
{
    curl_easy_setopt(t->head_ch, CURLOPT_URL, url);
    curl_easy_setopt(t->head_ch, CURLOPT_NOBODY, 1);
    CURLcode r = curl_easy_perform(t->head_ch);
    if (r != CURLE_OK) {
        warn("unable to HEAD %s, %s!", url, curl_easy_strerror(r));
        return DUBTREE_INVALID_HANDLE;
    }
    long response;
    curl_easy_getinfo(t->head_ch, CURLINFO_RESPONSE_CODE, &response);
    if (response != 200) {
        return DUBTREE_INVALID_HANDLE;
    }

    dubtree_handle_t f = dubtree_open_tmp(t->cache ? t->cache : t->fallbacks[0]);
    if (invalid_handle(f)) {
        err(1, "unable to create tmp file\n");
    }
    HttpGetState *hgs = calloc(1, sizeof(*hgs));
    critical_section_init(&hgs->lock);
    fprintf(stderr, "fetching %s sz=%u s=%d...\n", url, chunk_id.size, synchronous);
    hgs->t0 = rtc();
    hgs->chunk_id = chunk_id;
    hgs->size = chunk_id.size;
    hgs->synchronous = synchronous;
    hgs->t = t;
    hgs->url = strdup(url);
    dubtree_set_file_size(f, hgs->size);
    hgs->is_buffering = 1;
    hgs->fd = dup(f->fd);
    f->opaque = hgs_ref(hgs);

    if (synchronous) {
        prep_curl_handle(t->shared_ch, hgs->url, NULL, hgs_ref(hgs));
        r = curl_easy_perform(t->shared_ch);
        if (r != CURLE_OK) {
            errx(1, "unable to fetch %s, %s!", url, curl_easy_strerror(r));
        }
    }
    return f;
}

static inline dubtree_handle_t __get_chunk(DubTree *t, chunk_id_t chunk_id, int dirty, int local, int *l)
{
    dubtree_handle_t f = DUBTREE_INVALID_HANDLE;
    uint64_t line;
    LruCacheLine *cl;

    if (hashtable_find(&t->ht, chunk_id.id.first64, &line)) {
        cl = lru_cache_touch_line(&t->lru, line);
        if (dirty && !cl->dirty) {
            printf("%"PRIx64":%u was previously opened non-dirty!\n",
                    be64toh(chunk_id.id.first64), chunk_id.size);
            errno = EEXIST;
            return DUBTREE_INVALID_HANDLE;
        }
        ++(cl->users);
        CacheLineUserData *ud = &t->cache_infos[line];
        f = ud->f;
        *l = line; // XXX
    } else {
        char *fn = NULL;
        char **fb = t->fallbacks;
        while (invalid_handle(f) && *fb) {
            free(fn);
            fn = name_chunk(*fb, chunk_id);
            if (fb == t->fallbacks) {
                if (dirty) {
                    f = dubtree_open_new(fn, 0);
                    if (invalid_handle(f)) {
                        break;
                    }
                } else {
                    f = dubtree_open_existing_readonly(fn);
                }
            } else {
                if (!memcmp("http://", fn, 7) || !memcmp("https://", fn, 8)) {
                    f = prepare_http_get(t, local, fn, chunk_id);
                } else {
                    f = dubtree_open_existing_readonly(fn);
                }
            }
            ++fb;
        }

        if (valid_handle(f)) {
            for (;;) {
                line = lru_cache_evict_line(&t->lru);
                cl = lru_cache_touch_line(&t->lru, line);
                if (cl->users == 0) {
                    break;
                }
            }
            CacheLineUserData *ud = &t->cache_infos[line];
            if (cl->key) {
                hashtable_delete(&t->ht, cl->key);
                close_chunk_file(ud->f);
                clear_chunk_id(&ud->chunk_id);
                memset(ud, 0, sizeof(*ud));
            } else {
                if (valid_handle(ud->f)) {
                    fprintf(stderr, "warning: dangling file handle %p\n", ud->f);
                }
            }

            assert(valid_chunk_id(&chunk_id));

            cl->key = chunk_id.id.first64;
            assert(cl->key);
            cl->users = 1;
            cl->dirty = dirty;
            ud->chunk_id = chunk_id;
            ud->f = f;
            hashtable_insert(&t->ht, chunk_id.id.first64, line);
            *l = line;
        } else {
            if (errno != EEXIST) {
#ifdef _WIN32
                Wwarn("open chunk=%"PRIx64" dirty=%d failed, fn=%s", be64toh(chunk_id.id.first64), dirty, fn);
#else
                warn("open chunk=%"PRIx64" dirty=%d failed, fn=%s", be64toh(chunk_id.id.first64), dirty, fn);
#endif
            }
            *l = -1; //XXX
        }
        free(fn);
    }

    return f;
}

static dubtree_handle_t get_chunk(DubTree *t, chunk_id_t chunk_id, int dirty, int local, int *l)
{
    dubtree_handle_t f;
    critical_section_enter(&t->cache_lock);
    f = __get_chunk(t, chunk_id, dirty, local, l);
    critical_section_leave(&t->cache_lock);
    return f;
}

static int unlink_chunk(DubTree *t, chunk_id_t chunk_id, dubtree_handle_t f)
{
    char *fn;

    if (valid_handle(f)) {
#ifdef _WIN32
        FILE_DISPOSITION_INFO fdi = {1};
        if (!SetFileInformationByHandle(f, FileDispositionInfo, &fdi,
                                        sizeof(fdi)) &&
                GetLastError() != ERROR_ACCESS_DENIED) {
            Wwarn("err setting delete disposition for chunk=%"PRIx64"",
                  chunk_id);
        }
        close_chunk_file(f);
        return 0;
#endif
    }

    fn = name_chunk(t->fallbacks[0], chunk_id);
    if (unlink(fn) < 0 && errno != ENOENT) {
        printf("unlink %s failed err %s\n", fn, strerror(errno));
    }
    free(fn);

#ifndef _WIN32
    if (valid_handle(f)) {
        close_chunk_file(f);
    }
#endif
    return 0;
}

static inline void __put_chunk(DubTree *t, int line)
{
    LruCacheLine *cl = &t->lru.lines[line];
    assert(cl->users > 0);
    chunk_id_t chunk_id = {};
    int delete = 0;
    dubtree_handle_t f = DUBTREE_INVALID_HANDLE;

    if (cl->users-- == 1) {
        if (cl->delete) {
            CacheLineUserData *ud = &t->cache_infos[line];
            chunk_id = ud->chunk_id;
            f = ud->f;
            ud->f = DUBTREE_INVALID_HANDLE;
            hashtable_delete(&t->ht, cl->key);
            delete = 1;
            memset(cl, 0, sizeof(*cl));
        }
    }

    if (delete) {
        unlink_chunk(t, chunk_id, f);
    }
}

static void put_chunk(DubTree *t, int line)
{
    critical_section_enter(&t->cache_lock);
    __put_chunk(t, line);
    critical_section_leave(&t->cache_lock);
}

static inline void __free_chunk(DubTree *t, chunk_id_t chunk_id)
{
    uint64_t line;
    int delete = 1;
    dubtree_handle_t f = DUBTREE_INVALID_HANDLE;

    if (hashtable_find(&t->ht, chunk_id.id.first64, &line)) {
        LruCacheLine *cl = &t->lru.lines[line];
        if (cl->users > 0) {
            cl->delete = 1;
            delete = 0;
        } else {
            CacheLineUserData *ud = &t->cache_infos[line];
            f = ud->f;
            hashtable_delete(&t->ht, cl->key);
            cl->key = 0;
            memset(ud, 0, sizeof(*ud));
        }
    }

    if (delete) {
        unlink_chunk(t, chunk_id, f);
    }
}

void write_chunk(DubTree *t, chunk_id_t *out_id, const Chunk *c,
        const uint8_t *chunk0, uint32_t size)
{
    /* If copying everything in a chunk, we can just return its id. */
    int i, j;
    uint32_t total = 0;
    int l = -1;
    chunk_id_t *first_chunk_id = &c->crs[0].chunk_id;

    for (i = 0; i < c->n_crs; ++i) {
        ChunkReads *cr = &c->crs[i];
        if (!equal_chunk_ids(&cr->chunk_id, first_chunk_id)) {
            break;
        }
        Read *first = cr->reads;
        Read *rd;
        for (j = 0, rd = first; j < cr->num_reads; ++j, ++rd) {
            total += rd->size;
        }
    }
    //printf("%d vs %d, %u vs %u, %016lx\n", i, c->n_crs, first_chunk_id->size, total,
            //be64toh(first_chunk_id->id.first64));
    if (i == c->n_crs && first_chunk_id->size == total) {
        for (j = 0; j < c->n_crs; ++j) {
            ChunkReads *cr = &c->crs[j];
            Read *first = cr->reads;
            free(first);
        }
        *out_id = *first_chunk_id;
        goto out;
    }

    CallbackState *cs = calloc(1, sizeof(*cs));
    if (!cs) {
        errx(1, "%s: calloc failed", __FUNCTION__);
        goto out;
    }

    increment_counter(cs);

#ifdef _WIN32
    HANDLE h = CreateFileMappingA(f, NULL, PAGE_READWRITE, 0, size, NULL);
    if (!h) {
        Werr(1, "CreateFileMappingA fails");
    }
    void *buf = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, size);
    CloseHandle(h);

    HANDLE event = CreateEvent(NULL, TRUE, FALSE, NULL);
    cs->cb = set_event_cb;
    cs->opaque = (void *) event;
#else
    void *buf = malloc(size);
    if (!buf) {
        errx(1, "%s: malloc failed", __FUNCTION__);
    }
    int fds[2];
    int r = pipe2(fds, O_DIRECT);
    if (r < 0) {
        errx(1, "pipe2 failed");
    }
    cs->cb = set_event_cb;
    cs->opaque = (void *) (intptr_t) fds[1];
#endif

    flush_reads(t, c, buf, chunk0, 1, cs);
    decrement_counter(cs);

#ifdef _WIN32
    for (;;) {
        int r = WaitForSingleObjectEx(event, INFINITE, TRUE);
        if (r == WAIT_OBJECT_0) {
            break;
        } else if (r == WAIT_IO_COMPLETION) {
            continue;
        } else {
            printf("r %x err %u\n", r, (uint32_t) GetLastError());
        }
    }
    CloseHandle(event);
    UnmapViewOfFile(buf);
#else
    char msg;
    r = read(fds[0], &msg, sizeof(msg));
    if (r != sizeof(msg)) {
        err(1, "pipe read failed");
    }
    close(fds[0]);
    *out_id = content_id(buf, size);
    dubtree_handle_t f = get_chunk(t, *out_id, 1, 0, &l);
    if (invalid_handle(f)) {
        if (errno == EEXIST) {
            /* benign. */
        } else {
            err(1, "unable to write chunk %"PRIx64, be64toh(out_id->id.first64));
            goto out;
        }
    } else {
        if (dubtree_pwrite(f, buf, size, 0) != size) {
            err(1, "%s: dubtree_pwrite to chunk %"PRIx64" failed",
                    __FUNCTION__, be64toh(out_id->id.first64));
        }
    }
    free(buf);
#endif

out:
    if (l >= 0) {
        put_chunk(t, l);
    }
}

static inline int chunk_exceeded(uint64_t hash, size_t size)
{
    /* cap .lvl file sizes due to max 24 bit offsets in simpletree! */
    if (size >= 8 << 20) {
        return 1;
    }
    int p = __builtin_clzll((uint64_t) size);
    int q = __builtin_ffsll(hash);
    /* K is a tunable parameter to affect avg chunk sizes,
     * increase to make chunks smaller */
    const int K = 33;
    return p < K + 2 * q;
}

#define HASH_WINDOW 32
#define HASH_B 33
struct hash_state {
    int idx;
    uint64_t base;
    uint64_t hash;
    uint64_t hashes[HASH_WINDOW];
};

static inline void init_hash(struct hash_state *hs)
{
    memset(hs, 0, sizeof(*hs));
    uint64_t base = 1;
    for (int i = 1; i < HASH_WINDOW; ++i) {
        base *= HASH_B;
    }
    hs->base = base;
}

static inline void update_hash(struct hash_state *hs, uint64_t hash)
{
    int i = hs->idx++ % HASH_WINDOW;
    uint64_t prev = hs->hashes[i];
    hs->hashes[i] = hash;
    hs->hash = HASH_B * (hs->hash - hs->base * prev) + hash;
}

static inline void insert_kv(SimpleTree *st,
        uint64_t key, uint32_t chunk, uint32_t offset, uint32_t size, hash_t hash)
{
    SimpleTreeValue v;
    v.chunk = chunk;
    v.offset = offset;
    v.size = size;
    v.hash = hash;
    simpletree_insert(st, key, v);
}

#if 0
static int u64_cmp(const void *pa, const void *pb) {
    uint64_t a = *(uint64_t *) pa;
    uint64_t b = *(uint64_t *) pb;
    if (a < b) {
        return -1;
    } else if (b < a) {
        return 1;
    } else {
        return 0;
    }
}

static uint64_t *u64_lower_bound(uint64_t *first, int len, uint64_t key)
{
    int half;
    uint64_t *middle;
    while (len > 0) {
        half = len >> 1;
        middle = first + half;
        if (*middle < key) {
            first = middle + 1;
            len = len - half - 1;
        } else {
            len = half;
        }
    }
    return first;
}
#endif

int dubtree_insert(DubTree *t, int num_keys, uint64_t* keys,
        uint8_t *values, uint32_t *sizes,
        int force_level, commit_callback commit_cb, void *opaque)
{
    /* Find a free slot at the top level and copy the key there. */
    SimpleTree st;
    int i;
    int j = 0;
    uint64_t last_key = -1;
    uint64_t needed = 0;
    uint32_t fragments = 0;
    uint64_t garbage = 0;
    UserData *ud = NULL;

    HeapElem tuples[1 + DUBTREE_MAX_LEVELS];
    HeapElem *heap[1 + DUBTREE_MAX_LEVELS];
    HeapElem *min;
    SimpleTree trees[DUBTREE_MAX_LEVELS];
    SimpleTree *tree_ptrs[DUBTREE_MAX_LEVELS] = {};
    chunk_id_t tree_chunk_ids[DUBTREE_MAX_LEVELS] = {};
    SimpleTree *existing;
    const UserData *cud;
    const UserData *old_ud;

    uint64_t slot_size = DUBTREE_SLOT_SIZE;

    critical_section_enter(&t->write_lock);

    Crypto crypto;
    crypto_init(&crypto, t->crypto_key);
    int total_size = 0;
    for (i = 0; i < num_keys; ++i) {
        total_size += CRYPTO_IV_SIZE + sizes[i];
    }
    uint8_t *encrypted_values = malloc(total_size);
    uint8_t *enc = encrypted_values;
    uint8_t *hashes = malloc(CRYPTO_TAG_SIZE * num_keys);
    const uint8_t *v = values;
    for (i = 0; i < num_keys; ++i) {
        int size = sizes[i];
        //RAND_bytes(enc, CRYPTO_IV_SIZE);
        //SHA512(v, size, tmp); // XXX use key to make this HMAC
#if 1
        uint8_t tmp[512 / 8];
        SHA512_CTX ctx;
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, crypto.key, CRYPTO_KEY_SIZE);
        SHA512_Update(&ctx, v, size);
        SHA512_Final(tmp, &ctx);
        memcpy(enc, tmp, CRYPTO_IV_SIZE);
#endif
        sizes[i] = CRYPTO_IV_SIZE + encrypt256(&crypto, enc + CRYPTO_IV_SIZE,
                &hashes[CRYPTO_TAG_SIZE * i], v, size, enc);
        assert(t->use_large_values || sizes[i] < (1<<16));
        v += size;
        enc += sizes[i];
    }
 
    if (num_keys > 0) {
        for (i = 0; i < num_keys; ++i) {
            needed += sizes[i];
        }

        min = &tuples[j];
        memset(min, 0, sizeof(*min));
        min->level = -1;
        min->key = keys[0];
        min->size = sizes[0];
        memcpy(&min->hash, hashes, CRYPTO_TAG_SIZE);
        heap[j] = min;
        sift_up(t, heap, j++);
    }

    struct level_ptr next = t->first;
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        /* Figure out how many bytes are in use at this level. */

        uint64_t used = 0;
        if (next.level == i) {
            SimpleTreeResult k;
            existing = &trees[i];
            simpletree_open(existing, &crypto, get_chunk_fd(t, next.level_id),
                    next.level_hash);
            cud = simpletree_get_user(existing);

            tree_ptrs[cud->level] = existing;
            tree_chunk_ids[cud->level] = next.level_id;

            next = cud->next;

            used = cud->size;
            garbage = cud->garbage;
            fragments = cud->fragments;
            if (used > garbage) {
                needed += used - garbage;
            }

            min = &tuples[j];
            min->level = i;
            min->st = existing;
            simpletree_begin(existing, &min->it);
            k = simpletree_read(existing, &min->it);
            min->key = k.key;
            min->chunk = k.value.chunk;
            min->chunk_id = cud->chunk_ids[min->chunk];
            min->offset = k.value.offset;
            min->size = k.value.size;
            min->hash = k.value.hash;
            heap[j] = min;
            sift_up(t, heap, j++);
        } else {
            existing = NULL;
            fragments = 0;
            garbage = used = 0;
            cud = NULL;
        }

        if (slot_size >= needed && fragments < DUBTREE_M && used >= garbage &&
                i >= force_level) {

            ud = calloc(1, sizeof(*ud));

            if (existing) {
                old_ud = simpletree_get_user(existing);
            } else {
                old_ud = NULL;
            }

            break;
        }
        slot_size *= DUBTREE_M;
    }

    if (i == DUBTREE_MAX_LEVELS) {
        printf("all levels full!\n");
        return -1;
    }

    /* Create the new B-tree to index the destination level. */
    // XXX we could know min and max values here and pass to tree to
    // allow it to set its addressed range.
    //
    // or we could (perhaps dynamically) decided to insert a radix node in front of
    // the tree, which would split the address space down to a managable size
    //
    //
    simpletree_create(&st, &crypto, t->use_large_values);

    struct hash_state hash_state;
    init_hash(&hash_state);
    uint64_t total = 0;
    int min_idx = 0;
    uint32_t min_offset = 0;

    int done;
    int *deref = NULL;

    int out_chunk = -1;
    Chunk out = {};
    hashtable_init(&out.ht, NULL, NULL);
    
    if (old_ud) {
        deref = calloc(old_ud->num_chunks, sizeof(int));
        for (uint32_t i = 0; i < old_ud->num_chunks; ++i) {
            deref[i] = -1;
        }
    }
    uint32_t t_buffered = 0;

    for (done = 0;;) {
        /* Loop and copy down until heap empty. */

        min = heap[0];
        int end = 0;

        /* Anything to flush from current chunk before we switch to another one? */
        if (t_buffered && (done || chunk_exceeded(hash_state.hash, t_buffered))) {

            /* Write buffered data with look-aside to incoming encrypted_values values,
             * which will be merged in as needed. */
            write_chunk(t, &ud->chunk_ids[out_chunk], &out, encrypted_values, t_buffered);
            clear_chunk(&out);
            out_chunk = -1;
            t_buffered = 0;
            init_hash(&hash_state);

        }
        if (done) {
            break;
        }

        /* Process min element from incoming and existing trees. */
        /* The same key may be repeated across levels, so ignore
         * duplicates. */

        if (min->key != last_key) {
            last_key = min->key;

            if (min->level == i) {
                int chunk = deref[min->chunk];
                if (chunk < 0) {
                    chunk = add_chunk_id(&ud);
                    deref[min->chunk] = chunk;
                    ud->chunk_ids[chunk] = old_ud->chunk_ids[min->chunk];
                }
                insert_kv(&st, min->key, chunk, min->offset, min->size, min->hash);
            } else {
                if (out_chunk < 0) {
                    out_chunk = add_chunk_id(&ud);
                }
                read_chunk(t, &out, min->chunk_id, t_buffered, min->offset, min->size);
                insert_kv(&st, min->key, out_chunk, t_buffered, min->size, min->hash);
                t_buffered += min->size;
            }
            update_hash(&hash_state, min->hash.first64);
            total += min->size;
        } else {
            garbage += min->size;
        }

        /* Find next min for next round. */
        if (min->st) {
            simpletree_next(min->st, &min->it);
            end = simpletree_at_end(min->st, &min->it);
        } else {
            end = (min_idx == num_keys - 1);
        }
        if (end) {
            if (j == 1) {
                done = 1;
            } else {
                heap[0] = heap[--j];
            }
        } else {
            if (min->st) {
                SimpleTreeResult k;
                cud = simpletree_get_user(min->st);
                k = simpletree_read(min->st, &min->it);
                min->key = k.key;
                min->chunk = k.value.chunk;
                min->chunk_id = cud->chunk_ids[min->chunk];
                min->offset = k.value.offset;
                min->size = k.value.size;
                min->hash = k.value.hash;
            } else {
                min_offset += sizes[min_idx++];
                min->key = keys[min_idx];
                min->offset = min_offset;
                min->size = sizes[min_idx];
                memcpy(&min->hash, &hashes[CRYPTO_TAG_SIZE * min_idx],
                        CRYPTO_TAG_SIZE); // XXX assumes hash and tag sizes match
            }
        }
        sift_down(t, heap, j);
    }

    /* Find the smallest level that this tree can fit in. */
    int dest;
    for (dest = i; ; --dest) {
        slot_size /= DUBTREE_M;
        if (dest == 0 || slot_size < total) {
            break;
        }
    }

    simpletree_finish(&st);

    for (uint32_t k = 0; k < ud->num_chunks; ++k) {
        chunk_ref(t, ud->chunk_ids[k]);
    }

    ud->level = dest;
    ud->next = next;
    ud->size = total;
    ud->fragments = fragments + 1;
    ud->garbage = garbage;
    simpletree_set_user(&st, ud, ud_size(ud, ud->num_chunks));
    free(ud);

    uint32_t tree_size = simpletree_get_nodes_size(&st);
    hash_t tree_hash = simpletree_encrypt(&st);
    chunk_id_t tree_chunk = content_id(st.mem, tree_size);
    int l;
    dubtree_handle_t f = get_chunk(t, tree_chunk, 1, 0, &l);
    if (invalid_handle(f)) {
        err(1, "unable to open tree chunk %"PRIx64" for write", tree_chunk.id.first64);
        return -1;
    }
    if (dubtree_pwrite(f, st.mem, tree_size, 0) != tree_size) {
        err(1, "%s: dubtree_pwrite failed", __FUNCTION__);
    }
    put_chunk(t, l);


    simpletree_close(&st);

    struct level_ptr first = {dest, tree_chunk, tree_hash};
    t->first = first;
    if (commit_cb) {
        commit_cb(opaque);
    }

    critical_section_enter(&t->cache_lock);
    for (j = i; j >= 0; --j) {
        SimpleTree *st = tree_ptrs[j];
        if (st) {
            cud = simpletree_get_user(st);
            for (uint32_t k = 0; k < cud->num_chunks; ++k) {
                chunk_id_t chunk_id = cud->chunk_ids[k];
                if (chunk_deref(t, chunk_id) == 0) {
                    __free_chunk(t, chunk_id);
                }
            }
            simpletree_close(st);
            __free_chunk(t, tree_chunk_ids[j]);
        }
    }
    critical_section_leave(&t->cache_lock);

    critical_section_leave(&t->write_lock);
    free(deref);
    free(hashes);
    free(encrypted_values);
    crypto_close(&crypto);
    return 0;
}

int dubtree_delete(DubTree *t)
{
    Crypto crypto;
    crypto_init(&crypto, t->crypto_key);

    struct level_ptr next = t->first;
    while (next.level >= 0) {

        chunk_id_t chunk_id = next.level_id;
        SimpleTree st;
        simpletree_open(&st, &crypto, get_chunk_fd(t, chunk_id),
                next.level_hash);

        const UserData *cud = simpletree_get_user(&st);
        for (uint32_t i = 0; i < cud->num_chunks; ++i) {
            __free_chunk(t, cud->chunk_ids[i]);
        }

        next = cud->next;
        simpletree_close(&st);
        __free_chunk(t, chunk_id);
    }
    crypto_close(&crypto);
    char *dn;
    dn = strdup(t->fallbacks[0]);

    dubtree_close(t);

    if (rmdir(dn) < 0) {
        warn("unable to rmdir %s", dn);
        return -1;
    }
    free(dn);

    return 0;
}

void dubtree_close(DubTree *t)
{
    char **fb;

    hashtable_clear(&t->ht);
    for (int i = 0; i < (1 << t->lru.log_lines); ++i) {
        CacheLineUserData *ud = &t->cache_infos[i];
        dubtree_handle_t f = ud->f;
        if (f) {
            close_chunk_file(f);
        }
    }
    free(t->cache_infos);
    lru_cache_close(&t->lru);
    hashtable_clear(&t->refcounts_ht);

    free(t->buffered);

    fb = t->fallbacks;
    while (*fb) {
        free(*fb++);
    }
    free(t->cache);
    curl_easy_cleanup(t->shared_ch);
    curl_easy_cleanup(t->head_ch);
}


int dubtree_sanity_check(DubTree *t)
{
    Crypto crypto;
    crypto_init(&crypto, t->crypto_key);
    struct level_ptr next = t->first;
    /* Figure out how many bytes are in use at this level. */
    SimpleTree st;
    while (next.level >= 0) {
        int i = next.level;
        dubtree_handle_t cf;
        SimpleTreeIterator it;
        const UserData *cud;

        printf("get level %d\n", i);
        simpletree_open(&st, &crypto, get_chunk_fd(t, next.level_id), next.level_hash);
        simpletree_begin(&st, &it);
        cud = simpletree_get_user(&st);
        printf("check level %d\n", i);
        printf("level %d has %d chunks, garbage=%" PRIu64 "\n", i, cud->num_chunks, cud->garbage);
        uint32_t idx = ~0U;
        uint64_t decrypted = 0;
        while (!simpletree_at_end(&st, &it)) {
            SimpleTreeResult k;
            chunk_id_t chunk_id;
            int l;

            k = simpletree_read(&st, &it);
            if (idx != k.value.chunk) {
                idx = k.value.chunk;
                chunk_id = cud->chunk_ids[k.value.chunk];
            }
            cf = get_chunk(t, chunk_id, 0, 1, &l);
            if (invalid_handle(cf)) {
                warn("unable to read chunk %"PRIx64, be64toh(chunk_id.id.first64));
                return -1;
            }
            uint8_t *in = malloc(k.value.size);
            ssize_t got = dubtree_pread(cf, in, k.value.size, k.value.offset);
            if ((uint32_t) got != k.value.size) {
                err(1, "dubtree pread failed");
            }
            put_chunk(t, l);

            uint8_t tmp[0x10000];
            int size = k.value.size;
            hash_t hash = k.value.hash;
            int dsize = decrypt256(&crypto, tmp, in + CRYPTO_IV_SIZE, size - CRYPTO_IV_SIZE,
                hash.bytes, in);
            if (dsize <= 0) {
                errx(1, "failed decrypting block %" PRIx64 ", size=%u, dsize=%d",
                    k.key, size, dsize);
            } else {
                ++decrypted;
            }

#if 0
            int sz = k.value.size;
            int unsz = LZ4_decompress_safe((const char*)in, (char*)out,
                    sz, DUBTREE_BLOCK_SIZE);
            if (unsz != DUBTREE_BLOCK_SIZE) {
                printf("%d vs %d, offset=%u size=%u\n", unsz, sz,
                        k.value.offset, sz);
                return -1;
            }
#endif
            free(in);

            simpletree_next(&st, &it);
        }
        next = cud->next;
        simpletree_close(&st);
        printf("%" PRIu64 " key/values decrypted ok\n", decrypted);
    }
    crypto_close(&crypto);
    return 0;
}

static int link_chunk(chunk_id_t chunk_id, const char *from, const char *to)
{
    char *fn = name_chunk(from, chunk_id);
    char *ln = name_chunk(to, chunk_id);
    int r = link(fn, ln);
    if (r < 0) {
        if (errno != EEXIST && errno != ENOENT) {
            warn("unable to link %s -> %s!", fn, ln);
        } else {
            r = 0;
        }
    }
    free(ln);
    free(fn);
    return r;
}

int dubtree_snapshot(DubTree *t, const char *dn)
{
    int r;

    r = dubtree_mkdir(dn);
    if (r < 0) {
        warnx("unable to create snapshot directory %s, aborting snapshot!", dn);
        return -1;
    }

    Crypto crypto;
    crypto_init(&crypto, t->crypto_key);
    struct level_ptr next = t->first;

    while (next.level >= 0 && r >= 0) {
        chunk_id_t chunk_id = next.level_id;

        r = link_chunk(chunk_id, t->fallbacks[0], dn);
        if (r < 0) {
            break;
        }

        SimpleTree st;
        simpletree_open(&st, &crypto, get_chunk_fd(t, chunk_id),
                next.level_hash);

        const UserData *cud = simpletree_get_user(&st);
        for (uint32_t i = 0; i < cud->num_chunks; ++i) {
            chunk_id = cud->chunk_ids[i];
            r = link_chunk(chunk_id, t->fallbacks[0], dn);
            if (r < 0) {
                break;
            }
        }

        next = cud->next;
        simpletree_close(&st);
    }
    crypto_close(&crypto);
    return 0;
}
