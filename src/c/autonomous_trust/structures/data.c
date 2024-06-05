#include "data.h"

#define pod_cmp(a, b) ((a) < (b)) ? -1 : (((a) > (b)) ? 1 : 0)

int i_cmp(data_t *a, data_t *b) { return pod_cmp(a->intgr, b->intgr); }
int u_cmp(data_t *a, data_t *b) { return pod_cmp(a->uintr, b->uintr); }
int f_cmp(data_t *a, data_t *b) { return pod_cmp(a->flt_pt, b->flt_pt); }
int b_cmp(data_t *a, data_t *b) { return pod_cmp(a->bl, b->bl); }
int s_cmp(data_t *a, data_t *b) { return strcmp(a->str, b->str); }
int d_cmp(data_t *a, data_t *b) { return memcmp(a->str, b->str, a->size); }
int o_cmp(data_t *a, data_t *b) { return a->obj == b->obj; } // FIXME

bool data_equal(data_t *a, data_t *b)
{
    return a->type == b->type && a->cmp(a, b) == 0;
}