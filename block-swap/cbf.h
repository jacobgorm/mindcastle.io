#ifndef __CBF_H__
#define __CBF_H__

#include <stdint.h>

typedef struct CBF {
    uint8_t *counters;
    int k;
    int bits;
    int max;
    int n;
} CBF;

void cbf_init(CBF *cbf, int n);
void cbf_clear(CBF *cbf);
int cbf_add(CBF *cbf, const uint8_t *key);
int cbf_remove(CBF *cbf, const uint8_t *key);

#endif /* __CBF_H__ */
