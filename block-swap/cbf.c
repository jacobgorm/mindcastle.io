#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbf.h"

void cbf_init(CBF *cbf, int n)
{
    double p = .001f;
    double m = - ((double) n * log(p)) / (pow(log(2), 2));
    double k = - (log(p) / log(2));

    int bits;
    for (bits = 0; (1 << bits) < m; ++bits);
    printf("m=%f, k=%f, M=%d bits=%d\n", m, k, 1 << bits, bits);
    //assert(k * bits <= 128);

    cbf->counters = calloc(1, 1 << bits);
    cbf->bits = bits;
    cbf->k = ceil(k);
    cbf->max = n;
}

void cbf_clear(CBF *cbf)
{
    free(cbf->counters);
    memset(cbf, 0, sizeof(*cbf));
}

static inline int cbf_modify(CBF *cbf, const uint8_t *key, const int direction)
{
    int over_or_underflow = 0;
    const uint32_t *in = (uint32_t *) key;
    uint32_t x = 0;
    int have = 0;
    for (int i = 0; i < cbf->k; ++i) {
        uint32_t h = 0;
        int need = cbf->bits;
        while (need > 0) {
            if (have == 0) {
                x = be32toh(*in++);
                have = 32;
            }
            int take = have < need ? have : need;
            h = (h << take) | ((x >> (have - take)));
            have -= take;
            need -= take;
            x = x & ((1 << have) - 1);
        }
        int c = cbf->counters[h];
        if (direction >= 0) {
            cbf->counters[h] = c < 0xff ? c + 1 : 0xff;
            over_or_underflow = c == 0xff ? 1 : over_or_underflow;
        } else {
            cbf->counters[h] = c > 0 ? c - 1 : 0;
            over_or_underflow = c == 1 ? 1 : over_or_underflow;
        }
    }
    cbf->n += direction;
    return over_or_underflow;
}

int cbf_add(CBF *cbf, const uint8_t *key)
{
    int overflow = cbf_modify(cbf, key, 1);
    if (overflow || cbf->n > cbf->max) {
        printf("OVERFLOWING!\n");
        assert(0);
        return 1;
    }
    return 0;
}

int cbf_remove(CBF *cbf, const uint8_t *key)
{
    return cbf_modify(cbf, key, -1);
}


#if 0
int main(int argc, char **argv)
{
    CBF cbf;
    cbf_init(&cbf, 10000);
    uint8_t key[32] = "hej mor og far og lille ib";
    cbf_add(&cbf, key);
    cbf_add(&cbf, key);
    if (cbf_remove(&cbf, key)) {
        printf("was last\n");
    }
    if (cbf_remove(&cbf, key)) {
        printf("was last2\n");
    }

}
#endif
