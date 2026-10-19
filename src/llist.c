#include "../include/llist.h"
#include <stdlib.h>
#include <string.h>

void llist_init(void *ll_ptr, __u64 size) {
    if (!ll_ptr)
        return;

    LLIST_OF(int) *ll = ll_ptr;
    memset(ll, 0, sizeof(LLIST_OF(int)));
    ll->sz = size;
    ll->next = ll;
    ll->prev = ll;
}

void *llist_push(_LL_TYPE_ *ll, void *dat) {
    if (!ll)
        return NULL;

    LLIST_SZ(ll->sz) *new = malloc(sizeof(*ll));
    new->sz = ll->sz;
    new->array = malloc(ll->sz);
    memcpy(new->array, dat, ll->sz);

    LLIST_OF(int) *last = ll;
    ll_each(ll, e) last = e;

    LLIST_TWINE(last, new);
    return new;
}
