#include "./types.h"

#ifndef KRACK_LLIST_H
#define KRACK_LLIST_H

#define __CONCAT1__(a, T, counter) a##T##counter
#define __CONCAT__(a, T, counter) __CONCAT1__(a, T, counter)

#define LLIST_OF(T)                                                            \
    struct __CONCAT__(_llist_, at_, __LINE__) {                                \
        struct __CONCAT__(_llist_, at_, __LINE__) * next, *prev;               \
        T *v;                                                                  \
        __u64 sz;                                                              \
        __u8 used;                                                             \
    }

#define LLIST_SZ(size)                                                         \
    struct __CONCAT__(_llist_, sizeof_, __LINE__) {                            \
        struct __CONCAT__(_llist_, sizeof_, __LINE__) * next, *prev;           \
        __u8 *array;                                                           \
        __u64 sz;                                                              \
        __u8 used;                                                             \
    }

typedef LLIST_SZ(8) _LL_TYPE_;

#define ll_each(ll, e)                                                         \
    for (typeof((ll)) e = (ll)->next; !!e && e != (ll); e = e->next)

#define LLIST_TWINE(last, new)                                                 \
    ({                                                                         \
        (new)->next = last->next;                                              \
        (new)->prev = last;                                                    \
        last->next = (new);                                                    \
    })

void llist_init(void *ll_ptr, __u64 size);
void *llist_push(_LL_TYPE_ *ll, void *dat);

#endif
