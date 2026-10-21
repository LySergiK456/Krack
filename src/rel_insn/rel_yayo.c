#include "../../include/rel/rel_yayo.h"
#include "../../include/pe64/pe64.h"

static struct rel_yayo_tic *ins_yayo_tic(struct rel_yayo *r, enum yayo_ref_t type);
static __s64 _rel_align(struct rel_yayo *rel, __u64 off);
static __s64 _yayo_px_align(struct rel_yayo_tic *tick, __u64 off);
static void make_rel_yayo(mm_t *mm_out, struct rel_yayo *rel, struct rel_yayo_tic *tick);
static void make_yayo_pe64(mm_t *mm_out, struct rel_yayo *rel, struct rel_yayo_tic *y);

__s8 new_rel_yayo(struct rel_yayo *r) {
    if (!r) return -1;
    memset(r, 0, sizeof(struct rel_yayo));

    llist_init(&r->ll_yayo, sizeof(struct rel_yayo_tic));
    return 0;
}

__s8 YayoRelocate(mm_t *mm, struct rel_yayo *rel) {
    // make_rel_yayo(mm, rel, NULL);
}

struct rel_yayo_tic *new_yayo_pe64(struct rel_yayo *r, pe64_image *pe, __u64 off, __u64 size) {
    struct rel_yayo_tic *y = ins_yayo_tic(r, YAYO_PTR_PE64);
    if (!y) return NULL;

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

static struct rel_yayo_tic *ins_yayo_tic(struct rel_yayo *r, enum yayo_ref_t type) {
    if (!r) return NULL;
    struct rel_yayo_tic y = {.t = type};

    llist_push(&r->ll_yayo, &y);
    return r->ll_yayo.prev->v;
}

static void make_rel_yayo(mm_t *mm_out, struct rel_yayo *rel, struct rel_yayo_tic *tick) {
    ll_each_value(&tick->ll_yayo_px,px) {
        if (!llist_empty(&px->ll_yayo_px))
            make_rel_yayo(mm_out, rel, px);

        switch (px->t) {
            case YAYO_PTR_PE64:     make_yayo_pe64(mm_out, rel, px);    break;
            case YAYO_PTR_SHELLCODE:    break;
            case YAYO_PTR_UC_VMMAP:     break;
            case YAYO_PTR_VMMAP:        break;
            default:
                return -1;
        }
    }
    return 0;
}


static __s64 _rel_align(struct rel_yayo *rel, __u64 off) {
    __s64 r=0;
    ll_each_value(&rel->ll_yayo, px) r += _yayo_px_align(px, off);
    return r;
}

static __s64 _yayo_px_align(struct rel_yayo_tic *tick, __u64 off) {
    __s64 r=0;
    ll_each_value(&tick->ll_yayo_px, y) {
        if (!llist_empty(&y->ll_yayo_px)) r += _rel_align(y, off);
        // if (y->out.off > off) return r;

        if (y->t==YAYO_PX_RELATIVE);
        if (y->t==YAYO_PX_REPLACE) r += y->orig_size - y->dst_size;
        if (y->t==YAYO_PX_ADD)     r += y->orig_size;
        if (y->t==YAYO_PX_REMOVE)  r -= y->orig_size;
    }
    return r;
}

#define x8664_each(in, i, src, size)    \
        foreach_instr_off(X86_64, in, i, (src), (size))

static void make_yayo_pe64(mm_t *mm_out, struct rel_yayo *rel, struct rel_yayo_tic *y) {
    __u8 *out       = mm_out->mem;
    // __u8 *src       = &y->pe.bin->pMem[y->pe.offset];
    __s64 align     = _rel_align(rel, y->out.off);
    // __u64 i=0;
    // x8664_each(in, i, src, y->pe.size) {
    //     __u64 off       = y->out.off + i;
    //     pe64_image *bin = y->pe.bin;
        
    //     // llist_each_value(&y->ll_yayo_px, ypx) {
    //     //     if (ypx->out.off == off) {
    //     //         make_yayo_pe64(mm_out, rel, ypx);
    //     //     }
    //     // }
    // }
}