#include "../../include/rel/rel_yayo.h"
#include "../../include/pe64/pe64.h"

static struct rel_yayo_tic *ins_yayo_tic(struct rel_yayo *r,
                                         enum yayo_ref_t type);

__s8 new_rel_yayo(struct rel_yayo *r) {
    if (!r)
        return -1;
    memset(r, 0, sizeof(struct rel_yayo));

    llist_init(&r->ll_tics, sizeof(struct rel_yayo_tic));
    return 0;
}

struct rel_yayo_tic *new_yayo_pe64(struct rel_yayo *r, pe64_image *pe,
                                   __u64 off, __u64 size) {
    struct rel_yayo_tic *y = ins_yayo_tic(r, YAYO_PTR_PE64);
    if (!y)
        return NULL;

    y->pe.offset = off;
    y->pe.size = size;
    return y;
}

// struct rel_yayo_tic *new_yayo_sc(struct rel_yayo *r) {
// 	return NULL;
// }
// struct rel_yayo_tic *new_yayo_vmmap(struct rel_yayo *r) {
// 	return NULL;
// }
// struct rel_yayo_tic *new_yayo_uc(struct rel_yayo *r) {
// 	return NULL;
// }

static struct rel_yayo_tic *ins_yayo_tic(struct rel_yayo *r,
                                         enum yayo_ref_t type) {
    if (!r)
        return NULL;
    struct rel_yayo_tic y = {.t = type};

    llist_push(&r->ll_tics, &y);
    return r->ll_tics.prev->v;
}