#include "dubtree_sys.h"
#include "dubtree_io.h"

#include "aio.h"
#include "cbf.h"
#include "crypto.h"
#include "dubtree.h"
#include "lrucache.h"
#include "simpletree.h"
#include "lz4.h"
#include "hex.h"
#include "rtc.h"

/* These must go last or they will mess with e.g. asprintf() */
#include <curl/curl.h>
#include <curl/easy.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define DUBTREE_FILE_MAGIC_MMAP 0x73776170

#define DUBTREE_FILE_VERSION 15

#define DUBTREE_MMAPPED_NAME "top.lvl"


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

static int populate_cbf(DubTree *t, Crypto *crypto);
static dubtree_handle_t prepare_http_get(DubTree *t,
        int synchronous, const char *url, chunk_id_t chunk_id);

static void __put_chunk(DubTree *t, int line);
static void put_chunk(DubTree *t, int line);
static dubtree_handle_t __get_chunk(DubTree *t, chunk_id_t chunk_id,
                                       int dirty, int local, int *l);
static dubtree_handle_t get_chunk(DubTree *t, chunk_id_t chunk_id,
                                     int dirty, int local, int *l);
static chunk_id_t content_id(const uint8_t *in, int size);

typedef struct CacheLineUserData {
    dubtree_handle_t f;
    chunk_id_t chunk_id;
} CacheLineUserData;

int dubtree_init(DubTree *t, const uint8_t *key, chunk_id_t top_id,
        char **fallbacks, char *cache,
        malloc_callback malloc_cb, free_callback free_cb,
        void *opaque)
{
    int i;
    char *fn;
    char **fb;
    DubTreeHeader *header;

    if (!malloc_cb || !free_cb) {
        return -1;
    }

    memset(t, 0, sizeof(DubTree));
    t->crypto_key = key;
    t->malloc_cb = malloc_cb;
    t->free_cb = free_cb;
    t->opaque = opaque;
    critical_section_init(&t->cache_lock);
    critical_section_init(&t->write_lock);

    critical_section_enter(&t->cache_lock);
    hashtable_init(&t->ht, NULL, NULL);
    const int log_cache_lines = 4;
    lru_cache_init(&t->lru, log_cache_lines);
    t->cache_infos = calloc(1 << log_cache_lines, sizeof(CacheLineUserData));
    critical_section_leave(&t->cache_lock);

    fb = t->fallbacks;
    for (i = 0; i < sizeof(t->fallbacks) / sizeof(t->fallbacks[0]); ++i) {
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

    if (!t->cache) {
        t->cache = strdup(fn);
    }


    header = calloc(1, sizeof(DubTreeHeader));
    t->header = header;
    t->levels = header->levels;
    t->hashes = header->hashes;

    if (valid_chunk_id(&top_id)) {
        int l;
        dubtree_handle_t f = get_chunk(t, top_id, 0, 1, &l);
        if (valid_handle(f)) {
            printf("got top chunk!\n");
            dubtree_pread(f, t->header, sizeof(*(t->header)), 0);
            put_chunk(t, l);
        }
    }

    if (!t->header->magic) {
        fprintf(stderr, "*** creating empty dubtree ****\n");
        /* Magic header and version number. */
        t->header->magic = DUBTREE_FILE_MAGIC_MMAP;
        t->header->version = DUBTREE_FILE_VERSION;
        t->header->dubtree_m = DUBTREE_M;
        t->header->dubtree_slot_size = DUBTREE_SLOT_SIZE;
        t->header->dubtree_max_levels = DUBTREE_MAX_LEVELS;

        __sync_synchronize();
    }

    /* Check that shared data structure matches current version and
     * configuration. */
    if ((t->header->magic == DUBTREE_FILE_MAGIC_MMAP) &&
        (t->header->version == DUBTREE_FILE_VERSION) &&
        (t->header->dubtree_slot_size == DUBTREE_SLOT_SIZE) &&
        (t->header->dubtree_max_levels == DUBTREE_MAX_LEVELS)) {

        t->header->version = DUBTREE_FILE_VERSION;
        cbf_init(&t->cbf);
        return 0;
    } else {
        printf("mismatched dubtree header!\n");
        exit(1);
        return -1;
    }
}

chunk_id_t dubtree_checkpoint(DubTree *t)
{
    chunk_id_t top_id = content_id((const uint8_t *) t->header, sizeof(DubTreeHeader));
    int l;
    dubtree_handle_t f = get_chunk(t, top_id, 1, 1, &l);
    if (valid_handle(f)) {
        dubtree_pwrite(f, t->header, sizeof(*(t->header)), 0);
        put_chunk(t, l);
    }
    return top_id;
}

typedef struct Read {
    int src_offset;
    int dst_offset;
    int size;
} Read;

typedef struct ChunkReads {
    chunk_id_t chunk_id;
    int num_reads;
    Read *reads;
} ChunkReads;

typedef struct Chunk {
    void *buf;
    HashTable ht;
    int n_crs;
    ChunkReads *crs;
} Chunk;

static inline void read_chunk(DubTree *t, Chunk *d, chunk_id_t chunk_id,
        uint32_t dst_offset, uint32_t src_offset,
        uint32_t size)
{
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

    int n = cr->num_reads;
    if (!((n - 1) & n)) {
        /* XXX we do this once per find(). */
        cr->reads = realloc(cr->reads,
                sizeof(cr->reads[0]) * (n ? 2 * n: 1));
        if (!cr->reads) {
            errx(1, "%s: malloc failed line %d", __FUNCTION__, __LINE__);
        }
    }

    rd = &cr->reads[cr->num_reads++];
    rd->src_offset = src_offset;
    rd->dst_offset = dst_offset;
    rd->size = size;
}

static void set_event_cb(void *opaque, int result)
{
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
        for (int i = 0; i < ds->num_keys; ++i, hash += CRYPTO_TAG_SIZE) {
            uint32_t size = ds->sizes[i];
            if (size > 0) {
                uint8_t tmp[DUBTREE_BLOCK_SIZE];
                int dsize = decrypt256(ds->crypto, tmp, src + CRYPTO_IV_SIZE, size - CRYPTO_IV_SIZE, hash, src);
                memcpy(dst, tmp, dsize);
                src += size;
                dst += dsize;
                ds->sizes[i] = dsize;
            }
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
    int size;
    int fd;
    uint32_t split;
    uint32_t offset;
    critical_section lock; /* protects members below */
    uint8_t *buffer;
    int num_blocked;
    int num_unblocked;
    struct {
        CallbackState *cs;
        uint8_t *dst;
        Read *first;
        int n; } blocked_reads[MAX_BLOCKED_READS];
} HttpGetState;

static inline HttpGetState *hgs_ref(HttpGetState *hgs) {
    ++(hgs->refcount);
    return hgs;
}

static inline void hgs_deref(HttpGetState *hgs) {
    if (--(hgs->refcount) == 0) {
        critical_section_free(&hgs->lock);
        free(hgs->url);
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
    int i;
    Read *rd;

    HttpGetState *hgs = f->opaque;
    if (hgs) {
        int resolved = 0;
        critical_section_enter(&hgs->lock);
        if (hgs->buffer) {
            if (hgs->active && reads_inside_buffer(hgs, first, n)) {
                for (i = 0, rd = first; i < n; ++i, ++rd) {
                    memcpy(dst + rd->dst_offset, hgs->buffer + rd->src_offset,
                            rd->size);
                }
                free(first);
            } else {
                if (!hgs->active) {
                    CURL *ch = curl_easy_init();
                    char ranges[32];
                    sprintf(ranges, "%u-%u", first->src_offset, hgs->chunk_id.size - 1);
                    prep_curl_handle(ch, hgs->url, ranges, hgs_ref(hgs));
                    swap_aio_add_curl_handle(ch);
                    hgs->split = hgs->offset = first->src_offset;
                    hgs->active = 1;
                }
                increment_counter(cs);
                int num_blocked = hgs->num_blocked++;
                assert(num_blocked < MAX_BLOCKED_READS); //XXX
                hgs->blocked_reads[num_blocked].cs = cs;
                hgs->blocked_reads[num_blocked].dst = dst;
                hgs->blocked_reads[num_blocked].first = first;
                hgs->blocked_reads[num_blocked].n = n;
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

static int flush_reads(DubTree *t, Chunk *c, const uint8_t *chunk0, int local, CallbackState *cs)
{
    int i, j;
    int r = 0;

    for (i = 0; i < c->n_crs; ++i) {
        ChunkReads *cr = &c->crs[i];
        if (!valid_chunk_id(&cr->chunk_id)) {

            Read *first = cr->reads;
            Read *rd;
            for (j = 0, rd = first; j < cr->num_reads; ++j, ++rd) {
                memcpy(c->buf + rd->dst_offset, chunk0 + rd->src_offset,
                       rd->size);
            }
            free(first);
            r = 0;

        } else {
            dubtree_handle_t f;
            int l;

            f = get_chunk(t, cr->chunk_id, 0, local, &l);
            if (valid_handle(f)) {
                r = flush_chunk(t, c->buf, f, cr, cs);
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

    hashtable_clear(&c->ht);
    free(c->crs);
    c->n_crs = 0;
    c->crs = NULL;
    return r;
}


static inline void *map_file(dubtree_handle_t f, uint32_t sz, int writable)
{
    void *m;

#ifdef _WIN32
    HANDLE h = CreateFileMappingA(f, NULL, writable ? PAGE_READWRITE : PAGE_READONLY, 0, sz, NULL);
    if (!h) {
        Werr(1, "CreateFileMappingA fails");
    }
    m = MapViewOfFile(h, FILE_MAP_READ, 0, 0, sz);
    assert(m);
    CloseHandle(h);
#else
    m = mmap(NULL, sz, PROT_READ | (writable ? PROT_WRITE : 0), writable ? MAP_SHARED : MAP_PRIVATE, f->fd, 0);
    if (m == MAP_FAILED) {
        err(1, "unable to map file fd=%d,sz=%u %s:%d", f->fd, sz,  __FUNCTION__, __LINE__);
    }
#endif
    return m;
}

static inline void unmap_file(void *mem, size_t size)
{
#ifdef _WIN32
    if (!UnmapViewOfFile(mem)) {
        printf("UnmapViewOfFile failed, err=%u\n", (uint32_t) GetLastError());
    }
#else
    int r = munmap(mem, size);
    if (r < 0) {
        err(1, "unmap_file");
    }
#endif
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

typedef struct UserData {
    uint32_t fragments;
    uint64_t garbage;
    uint64_t size;        /* How many bytes are addressed by this tree. */
    uint32_t num_chunks;
    chunk_id_t chunk_ids[0];
} UserData;

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

static inline void set_chunk_id(UserData *ud, int chunk, chunk_id_t chunk_id)
{
    assert(chunk >= 0);
    ud->chunk_ids[chunk] = chunk_id;
}

static inline chunk_id_t get_chunk_id(const UserData *ud, int chunk)
{
    return ud->chunk_ids[chunk];
}

static inline size_t ud_size(const UserData *cud, size_t n)
{
    return sizeof(*cud) + sizeof(cud->chunk_ids[0]) * n;
}

static int populate_cbf(DubTree *t, Crypto *crypto)
{
    int retry = 1;
    do {
        if (retry) {
            cbf_double(&t->cbf);
        }
        retry = 0;
        for (int i = 0; i < DUBTREE_MAX_LEVELS && !retry; ++i) {
            if (valid_chunk_id(&t->levels[i])) {
                SimpleTree st;
                simpletree_open(&st, crypto, get_chunk_fd(t, t->levels[i]),
                        t->hashes[i]);
                const UserData *cud = simpletree_get_user(&st);
                for (int j = 0; j < cud->num_chunks; ++j) {
                    chunk_id_t chunk_id = get_chunk_id(cud, j);
                    if (cbf_add(&t->cbf, chunk_id.id.bytes)) {
                        retry = 1;
                        break;
                    }
                }
                simpletree_close(&st);
            }
        }
    } while (retry);

    return 0;
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
    FindContext *fx = calloc(1, sizeof(FindContext));
#ifdef _WIN32
    fx->event = CreateEvent(NULL, FALSE, FALSE, NULL);
#endif
    crypto_init(&fx->crypto, t->crypto_key);
    return fx;
}

void dubtree_end_find(DubTree *t, void *ctx)
{
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
        uint8_t *buffer, uint8_t *map, uint32_t *sizes,
        read_callback cb, void *opaque, void *ctx)
{
    int i, r;
    struct source {
        chunk_id_t chunk_id;
        int offset;
        int size;
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
    char relevant[DUBTREE_MAX_LEVELS] = {};

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
    memcpy(versions, map, sizeof(versions[0]) * num_keys);
    memset(sizes, 0, sizeof(sizes[0]) * num_keys);

    /* How many keys do we actually need to get? Some may have been
     * filled out already by the caller so do not count those. */

    for (i = missing = 0; i < num_keys; ++i) {
        if (map[i] == 0) ++missing;
    }

    /* Open all the trees. */
    critical_section_enter(&t->cache_lock);
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        CachedTree *ct = &fx->cached_trees[i];
        if (valid_chunk_id(&ct->chunk)) {
            if (!equal_chunk_ids(&ct->chunk, &t->levels[i])) {
                simpletree_close(&ct->st);
                clear_chunk_id(&ct->chunk);
            }
        }
        if (!valid_chunk_id(&ct->chunk) && valid_chunk_id(&t->levels[i])) {
            ct->chunk = t->levels[i];
            simpletree_open(&ct->st, &fx->crypto,
                    __get_chunk_fd(t, ct->chunk), t->hashes[i]);
        }
    }
    critical_section_leave(&t->cache_lock);

    /* Check for relevant keys in all fx->cached_trees. */
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        CachedTree *ct = &fx->cached_trees[i];
        SimpleTree *st = valid_chunk_id(&ct->chunk) ? &ct->st : NULL;
        SimpleTreeIterator it;

        if (st != NULL) {

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
                        sources[idx].chunk_id = get_chunk_id(cud, k.value.chunk);
                        sources[idx].offset = k.value.offset;
                        sources[idx].size = k.value.size;
                        sources[idx].hash = k.value.hash;
                        relevant[i] = 1;
                        --missing;
                    }
                    simpletree_next(st, &it);
                }
            }
        }
    }


    /* Copy out the values we found. */
    Chunk c = {};
    c.buf = buffer;
    hashtable_init(&c.ht, NULL, NULL);

    int dst;
    for (i = dst = 0; i < num_keys; ++i) {
        int size = sources[i].size;
        if (size) {
            read_chunk(t, &c, sources[i].chunk_id, dst, sources[i].offset,
                       size);
        }
        sizes[i] = size;
        memcpy(hashes + CRYPTO_TAG_SIZE * i, sources[i].hash.bytes,
                CRYPTO_TAG_SIZE);
        dst += size;
    }

    r = flush_reads(t, &c, NULL, 0, cs);
    if (r < 0) {
        succeeded = 0;
    }

    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        CachedTree *ct = &fx->cached_trees[i];
        if (valid_chunk_id(&ct->chunk) && !equal_chunk_ids(&ct->chunk, &t->levels[i])) {
            if (relevant[i]) {
                succeeded = 0;
            }
        }
    }

    /* Return 0 or positive value indicating number of unresolved blocks on
     * succes. Negative return means error. */

    r = succeeded ? missing : -EAGAIN;
    /* Since versions array started out as a copy of map, it is safe to
     * copy it back wholesale. */
    if (succeeded) {
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
    int chunk;
    int offset;
    int size;
    hash_t hash;
    chunk_id_t chunk_id;
} HeapElem;

static inline int heap_less_than(DubTree *t, HeapElem *a,
        HeapElem *b)
{
    if (a->key != b->key) {
        return (a->key < b->key);
    } else {
        return (a->level < b->level);
    }
}

static inline void sift_up(DubTree *t, HeapElem **hp, size_t child)
{
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
    char h[33];
    hex(h, chunk_id.id.bytes, 16); // shorten to 128 bits, too painful otherwise
    h[32] = '\0';
    asprintf(&fn, "%s/%s.lvl", prefix, h);
    return fn;
}

int curl_sockopt_cb(void *clientp, curl_socket_t curlfd, curlsocktype purpose)
{
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
    SHA512(in, size, chunk_id.id.bytes);
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

static size_t curl_data_cb(void *ptr, size_t size, size_t nmemb, void *opaque)
{
    int done = 0;
    HttpGetState *hgs = opaque;

    memcpy(hgs->buffer + hgs->offset, ptr, size * nmemb);
    hgs->offset += size * nmemb;

    if ((hgs->offset == hgs->size) || (hgs->offset == hgs->split)) {
        if (hgs->split > 0 && hgs->offset > hgs->split) {
            CURL *ch = curl_easy_init();
            hgs->offset = 0;
            char ranges[32];
            sprintf(ranges, "0-%u", hgs->split - 1);
            prep_curl_handle(ch, hgs->url, ranges, hgs_ref(hgs));
            swap_aio_add_curl_handle(ch);
        } else {
            fprintf(stderr, "%s %.2fMiB/s\n", hgs->url, (double) (hgs->size) / (1024.0 * 1024.0 * (rtc() - hgs->t0)));
            void *b = hgs->buffer;
            char procfn[32];
            sprintf(procfn, "/proc/self/fd/%d", hgs->fd);
            chunk_id_t real_id = content_id(b, hgs->chunk_id.size);

            if (equal_chunk_ids(&real_id, &hgs->chunk_id)) {
                DubTree *t = hgs->t;
                char *fn = name_chunk(t->cache, hgs->chunk_id);
                int r = linkat(AT_FDCWD, procfn, AT_FDCWD, fn, AT_SYMLINK_FOLLOW);
                close(hgs->fd);
                if (r < 0 && errno != EEXIST) {
                    err(1, "linkat failed for %d -> %s", hgs->fd, fn);
                }
                free(fn);
            } else {
                fprintf(stderr, "chunk damaged in transit, not caching!!\n");
            }
            hgs->active = 0;
            done = 1;
        }
    }

    critical_section_enter(&hgs->lock);
    int num_blocked = hgs->num_blocked;
    critical_section_leave(&hgs->lock);

    for (int i = 0; i < num_blocked; ++i) {
        Read *first = hgs->blocked_reads[i].first;
        if (first) {
            int n = hgs->blocked_reads[i].n;
            assert(n >= 1);
            if (done || reads_inside_buffer(hgs, first, n)) {
                Read *rd = first;
                for (int j = 0; j < n; ++j, ++rd) {
                    memcpy(hgs->blocked_reads[i].dst + rd->dst_offset, hgs->buffer + rd->src_offset, rd->size);
                }
                hgs->blocked_reads[i].first = NULL;
                decrement_counter(hgs->blocked_reads[i].cs);
                free(first);
                ++(hgs->num_unblocked);
            }
        }
    }

    if (done) {
        critical_section_enter(&hgs->lock);
        hgs->buffer = NULL;
        unmap_file(hgs->buffer, hgs->size);
        critical_section_leave(&hgs->lock);
    }

    return size * nmemb;
}

static CURL *head_ch = NULL;
static CURL *shared_ch = NULL;

static dubtree_handle_t prepare_http_get(DubTree *t,
        int synchronous, const char *url, chunk_id_t chunk_id)
{
    if (!head_ch) {
        head_ch = curl_easy_init();
    }
    if (!shared_ch) {
        shared_ch = curl_easy_init();
    }

    curl_easy_setopt(head_ch, CURLOPT_URL, url);
    curl_easy_setopt(head_ch, CURLOPT_NOBODY, 1);
    CURLcode r = curl_easy_perform(head_ch);
    if (r != CURLE_OK) {
        errx(1, "unable to HEAD %s, %s!", url, curl_easy_strerror(r));
    }
    int response;
    curl_easy_getinfo(head_ch, CURLINFO_RESPONSE_CODE, &response);
    if (response != 200) {
        return DUBTREE_INVALID_HANDLE;
    }

    dubtree_handle_t f = dubtree_open_tmp(t->cache);
    if (invalid_handle(f)) {
        err(1, "unable to create tmp file\n");
    }
    HttpGetState *hgs = calloc(1, sizeof(*hgs));
    critical_section_init(&hgs->lock);
    fprintf(stderr, "fetching %s s=%d...\n", url, synchronous);
    hgs->t0 = rtc();
    hgs->chunk_id = chunk_id;
    hgs->size = chunk_id.size;
    hgs->synchronous = synchronous;
    hgs->t = t;
    hgs->url = strdup(url);
    dubtree_set_file_size(f, hgs->size);
    hgs->buffer = map_file(f, hgs->size, 1);
    hgs->fd = dup(f->fd);
    f->opaque = hgs_ref(hgs);

    if (synchronous) {
        prep_curl_handle(shared_ch, hgs->url, NULL, hgs_ref(hgs));
        r = curl_easy_perform(shared_ch);
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
                f = dirty ?
                    dubtree_open_new(fn, 0) :
                    dubtree_open_existing(fn);
            } else {
                if (!memcmp("http://", fn, 7) || !memcmp("https://", fn, 8)) {
                    f = prepare_http_get(t, local, fn, chunk_id);
                } else {
                    printf("open %s from fallback\n", fn);
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
            ud->chunk_id = chunk_id;
            ud->f = f;
            hashtable_insert(&t->ht, chunk_id.id.first64, line);
            *l = line;
        } else {
#ifdef _WIN32
            Wwarn("open chunk=%"PRIx64" dirty=%d failed, fn=%s", be64toh(chunk_id.id.first64), dirty, fn);
#else
            warn("open chunk=%"PRIx64" dirty=%d failed, fn=%s", be64toh(chunk_id.id.first64), dirty, fn);
#endif
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

chunk_id_t write_chunk(DubTree *t, Chunk *c, const uint8_t *chunk0,
        uint32_t size)
{
    int l = -1;
    chunk_id_t chunk_id = {};
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
    c->buf = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, size);
    CloseHandle(h);

    HANDLE event = CreateEvent(NULL, TRUE, FALSE, NULL);
    cs->cb = set_event_cb;
    cs->opaque = (void *) event;
#else
    c->buf = t->malloc_cb(t->opaque, size);
    if (!c->buf) {
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

    flush_reads(t, c, chunk0, 1, cs);
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
    UnmapViewOfFile(c->buf);
#else
    char msg;
    r = read(fds[0], &msg, sizeof(msg));
    if (r != sizeof(msg)) {
        err(1, "pipe read failed");
    }
    close(fds[0]);
    chunk_id = content_id(c->buf, size);
    dubtree_handle_t f = get_chunk(t, chunk_id, 1, 0, &l);
    if (invalid_handle(f)) {
        if (errno == EEXIST) {
            printf("not writing pre-existing chunk %"PRIx64"\n", chunk_id.id.first64);
        } else {
            err(1, "unable to write chunk %"PRIx64, chunk_id.id.first64);
            goto out;
        }
    } else {
        dubtree_pwrite(f, c->buf, size, 0);
    }
    t->free_cb(t->opaque, c->buf);
#endif

out:
    free(c);
    if (l >= 0) {
        put_chunk(t, l);
    }
    return chunk_id;
}


static inline int chunk_exceeded(size_t size)
{
    return (size + DUBTREE_BLOCK_SIZE - 1 > (1 << 20));
}

static inline void insert_kv(SimpleTree *st,
        uint64_t key, int chunk, int offset, int size, hash_t hash)
{
    SimpleTreeValue v;
    v.chunk = chunk;
    v.offset = offset;
    v.size = size;
    v.hash = hash;
    simpletree_insert(st, key, v);
}

int dubtree_insert(DubTree *t, int num_keys, uint64_t* keys,
        uint8_t *values, uint32_t *sizes,
        int force_level)
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
    SimpleTree *existing;
    const UserData *cud;
    const UserData *old_ud;

    uint64_t slot_size = DUBTREE_SLOT_SIZE;

    critical_section_enter(&t->write_lock);
    struct buf_elem {uint64_t key; int offset; int size; hash_t hash;};
    struct buf_elem *buffered = t->buffered;

    Crypto crypto;
    crypto_init(&crypto, t->crypto_key);
    int total_size = 0;
    for (i = 0; i < num_keys; ++i) {
        total_size += CRYPTO_IV_SIZE + sizes[i];
    }
    uint8_t *encrypted_values = malloc(total_size);
    uint8_t *enc = encrypted_values;
    uint8_t *hashes = malloc(CRYPTO_TAG_SIZE * num_keys);
    uint8_t *hash = hashes;
    const uint8_t *v = values;
    for (i = 0; i < num_keys; ++i, hash += CRYPTO_TAG_SIZE) {
        int size = sizes[i];
        RAND_bytes(enc, CRYPTO_IV_SIZE);
        sizes[i] = CRYPTO_IV_SIZE + encrypt256(&crypto, enc + CRYPTO_IV_SIZE,
                hash, v, size, enc);
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
        memcpy(&min->hash, &hashes[0], CRYPTO_TAG_SIZE);
        heap[j] = min;
        sift_up(t, heap, j++);
    }

    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        /* Figure out how many bytes are in use at this level. */

        uint64_t used = 0;
        if (valid_chunk_id(&t->levels[i])) {
            SimpleTreeResult k;
            existing = &trees[i];

            simpletree_open(existing, &crypto,
                    get_chunk_fd(t, t->levels[i]), t->hashes[i]);

            cud = simpletree_get_user(existing);
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
            min->chunk_id = get_chunk_id(cud, min->chunk);
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
    simpletree_create(&st, &crypto);

    uint32_t b = 0;
    int n_buffered = 0;
    int t_buffered = 0;
    uint64_t total = 0;
    int min_idx = 0;
    uint32_t min_offset = 0;

    int done;
    chunk_id_t last_chunk_id = {};
    //memset(last_chunk_id.id.full, 0xff, sizeof(last_chunk_id.id.full));
    Chunk *out = NULL;
    chunk_id_t out_id = {};
    int out_chunk = -1;
    struct buf_elem *e;
    int *deref = NULL;
    
    if (old_ud) {
        deref = calloc(old_ud->num_chunks, sizeof(int));
        for (int i = 0; i < old_ud->num_chunks; ++i) {
            deref[i] = -1;
        }
    }

    for (done = 0;;) {
        /* Loop and copy down until heap empty. */

        min = heap[0];
        int end = 0;

        /* Anything to flush before we consume input? */
        if (n_buffered && ((!equal_chunk_ids(&last_chunk_id, &min->chunk_id)) || done ||
                    chunk_exceeded(t_buffered))) {
            int q;

            if (chunk_exceeded(t_buffered) && valid_chunk_id(&last_chunk_id)) {

                /* Handle the case of merging an entire chunk as-is, to avoid
                 * rewriting it. In the case where we filled an entire chunk
                 * from the newly inserted keys, there will be no valid chunk
                 * id set for them, which we check for by requiring a valid
                 * last_chunk_id. */

                int chunk = add_chunk_id(&ud);
                set_chunk_id(ud, chunk, last_chunk_id);
                for (q = 0; q < n_buffered; ++q) {
                    e = &buffered[q];
                    insert_kv(&st, e->key, chunk, e->offset, e->size, e->hash);
                    total += e->size;
                }

            } else {

                uint32_t b0 = b;
                uint32_t offset0 = buffered[0].offset;

                for (q = 0; q < n_buffered; ++q) {

                    if (!out) {
                        out = calloc(1, sizeof(Chunk));
                        if (!out) {
                            warnx("%s: calloc failed on line %d",
                                    __FUNCTION__, __LINE__);
                            return -1;
                        }
                        out_chunk = add_chunk_id(&ud);
                    }

                    e = &buffered[q];
                    insert_kv(&st, e->key, out_chunk, b, e->size, e->hash);
                    total += e->size;
                    b += e->size;

                    if (chunk_exceeded(b)) {
                        read_chunk(t, out, last_chunk_id, b0, offset0, b - b0);
                        offset0 = e->offset + e->size;

                        out_id = write_chunk(t, out, encrypted_values, b);
                        set_chunk_id(ud, out_chunk, out_id);
                        out_chunk = -1;
                        out = NULL;
                        b0 = b = 0;
                    }

                }
                if (out) {
                    read_chunk(t, out, last_chunk_id, b0, offset0, b - b0);
                }
            }
            n_buffered = t_buffered = 0;
        }
        if (done) {
            if (out) {
                out_id = write_chunk(t, out, encrypted_values, b);
                set_chunk_id(ud, out_chunk, out_id);
                out_chunk = -1;
                out = NULL;
            }
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
                    set_chunk_id(ud, chunk, get_chunk_id(old_ud, min->chunk));
                }
                insert_kv(&st, min->key, chunk, min->offset, min->size, min->hash);
                total += min->size;
            } else {

                if (n_buffered >= t->buffer_max) {
                    t->buffer_max = t->buffer_max ? 2 * t->buffer_max : 1;
                    buffered = t->buffered = realloc(t->buffered,
                                                     sizeof(buffered[0]) *
                                                     t->buffer_max);
                    if (!buffered) {
                        errx(1, "%s: malloc failed", __FUNCTION__);
                        return -1;
                    }
                }

                e = &buffered[n_buffered++];
                e->key = min->key;
                e->offset = min->offset;
                e->size = min->size;
                e->hash = min->hash;
                t_buffered += min->size;
            }
        } else {
            garbage += min->size;
        }

        last_chunk_id = min->chunk_id;

        /* Find next min for next round. */
        if (min->st) {
            simpletree_next(min->st, &min->it);
            end = simpletree_at_end(min->st, &min->it);
        } else {
            min_offset += sizes[min_idx++];
            end = (min_idx == num_keys);
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
                min->chunk_id = get_chunk_id(cud, min->chunk);
                min->offset = k.value.offset;
                min->size = k.value.size;
                min->hash = k.value.hash;
            } else {
                min->key = keys[min_idx];
                min->offset = min_offset;
                min->size = sizes[min_idx];
                memcpy(&min->hash, &hashes[CRYPTO_TAG_SIZE * min_idx],
                        CRYPTO_TAG_SIZE);
            }
        }
        sift_down(t, heap, j);
    }

    int retry = 0;
    do {
        retry = 0;
        for (int i = 0; i < ud->num_chunks && !retry; ++i) {
            chunk_id_t chunk_id = get_chunk_id(ud, i);
            retry = cbf_add(&t->cbf, chunk_id.id.bytes);
        }
        if (retry) {
            populate_cbf(t, &crypto);
        }
    } while (retry);

    /* Finish the combined tree and commit the merge by
     * installing a globally visible reference to the merged
     * tree. */

    simpletree_finish(&st);
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
    dubtree_pwrite(f, st.mem, tree_size, 0);
    put_chunk(t, l);
    simpletree_close(&st);

    critical_section_enter(&t->cache_lock);

    /* Find the smallest level that this tree can fit in, and delete
     * the rest of the levels from i and up. */

    int dest;
    for (dest = i; ; --dest) {
        slot_size /= DUBTREE_M;
        if (dest == 0 || slot_size < total) {
            break;
        }
    }

    for (j = i; j >= 0; --j) {
        SimpleTree *st = &trees[j];
        chunk_id_t chunk_id = t->levels[j];

        // XXX XXX no longer atomic!
        if (dest == j) {
            t->levels[j] = tree_chunk;
            t->hashes[j] = tree_hash;
        } else {
            clear_chunk_id(&t->levels[j]);
        }
        __sync_synchronize();

        if (valid_chunk_id(&chunk_id)) {
            int k;
            cud = simpletree_get_user(st);
            for (k = 0; k < cud->num_chunks; ++k) {
                chunk_id_t dead_chunk_id = cud->chunk_ids[k];
                if (cbf_remove(&t->cbf, dead_chunk_id.id.bytes)) {
                    __free_chunk(t, dead_chunk_id);
                }
            }
            simpletree_close(st);
            __free_chunk(t, chunk_id);
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
    int i, j;
    Crypto crypto;
    crypto_init(&crypto, t->crypto_key);

    critical_section_enter(&t->cache_lock);
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        chunk_id_t chunk_id = t->levels[i];
        if (valid_chunk_id(&chunk_id)) {

            SimpleTree st;
            const UserData *cud;
            simpletree_open(&st, &crypto, get_chunk_fd(t, chunk_id),
                    t->hashes[i]);

            cud = simpletree_get_user(&st);
            for (j = 0; j < cud->num_chunks; ++j) {
                __free_chunk(t, cud->chunk_ids[j]);
            }

            simpletree_close(&st);
            __free_chunk(t, chunk_id);
        }
    }
    critical_section_leave(&t->cache_lock);
    crypto_close(&crypto);

    char *mn;
    asprintf(&mn, "%s/"DUBTREE_MMAPPED_NAME, t->fallbacks[0]);

    char *dn;
    dn = strdup(t->fallbacks[0]);

    dubtree_close(t);

    if (unlink(mn) < 0) {
        warn("unable to unlink %s", mn);
        return -1;
    }
    if (rmdir(dn) < 0) {
        warn("unable to rmdir %s", dn);
        return -1;
    }

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
    cbf_close(&t->cbf);

    free(t->buffered);

    fb = t->fallbacks;
    while (*fb) {
        free(*fb++);
    }
    free(t->cache);
}


int dubtree_sanity_check(DubTree *t)
{
    int i;
    Crypto crypto;
    crypto_init(&crypto, t->crypto_key);
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        /* Figure out how many bytes are in use at this level. */

        SimpleTree st;
        if (valid_chunk_id(&t->levels[i])) {
            dubtree_handle_t cf;
            SimpleTreeIterator it;
            const UserData *cud;

            printf("get level %d\n", i);
            simpletree_open(&st, &crypto, get_chunk_fd(t, t->levels[i]), t->hashes[i]);
            simpletree_begin(&st, &it);
            cud = simpletree_get_user(&st);
            printf("check level %d\n", i);
            printf("level %d has %d chunks, garbage=%lu\n", i, cud->num_chunks, cud->garbage);
            int idx = -1;
            while (!simpletree_at_end(&st, &it)) {
                SimpleTreeResult k;
                uint8_t in[2 * DUBTREE_BLOCK_SIZE];
                //uint8_t out[DUBTREE_BLOCK_SIZE];
                chunk_id_t chunk_id;
                int l;
                int got;

                k = simpletree_read(&st, &it);
                if (idx != k.value.chunk) {
                    idx = k.value.chunk;
                    chunk_id = get_chunk_id(cud, k.value.chunk);
                }
                cf = get_chunk(t, chunk_id, 0, 0, &l);
                if (invalid_handle(cf)) {
                    warn("unable to read chunk %"PRIx64, chunk_id.id.first64);
                    return -1;
                }
                got = dubtree_pread(cf, in, k.value.size, k.value.offset);
                if (got != k.value.size) {
                    err(1, "dubtree pread failed");
                }
                put_chunk(t, l);

                int sz = k.value.size;
                if (sz < DUBTREE_BLOCK_SIZE) {
#if 0
                    int unsz = LZ4_decompress_safe((const char*)in, (char*)out,
                                                   sz, DUBTREE_BLOCK_SIZE);
                    if (unsz != DUBTREE_BLOCK_SIZE) {
                        printf("%d vs %d, offset=%u size=%u\n", unsz, sz,
                               k.value.offset, sz);
                        return -1;
                    }
#endif
                }

                simpletree_next(&st, &it);
            }
            simpletree_close(&st);
        }
    }
    crypto_close(&crypto);
    return 0;
}
