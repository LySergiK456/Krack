#include "../../x86disass/disass.h"
#include "../llist.h"
#include "../pe64/pe64.h"
#include "../types.h"
#include <unicorn/unicorn.h>

#ifndef KRACK_YAYO_H
#define KRACK_YAYO_H

enum yayo_ref_t {
    YAYO_PTR_PE64 = 1,
    YAYO_PTR_SHELLCODE = 2,
    YAYO_PTR_UC_VMMAP = 4,
    YAYO_PTR_VMMAP = 8,
};
enum yayo_px_t {
    YAYO_PX_RELATIVE = 1,
    YAYO_PX_REPLACE = 2,
    YAYO_PX_ADD = 4,
    YAYO_PX_REMOVE = 8,
};
enum yayo_hook_t {
    YAYO_HOOK_ORIG = 1,
    YAYO_HOOK_DST = 2,
};

struct rel_evmmap {
    __u64 VirtualAddress;
    __u64 VirtualSize;
    __u32 Perm;
    __u64 Characteristics;
};

struct rel_uc_evmmap {
    __u64 virt;
    __u64 size;
    __u32 perm;
};

struct yayo_hook {
    enum yayo_hook_t t;
    __u64 src;
    __u64 v;
};

struct yayo_px {
    enum yayo_px_t  t;
    struct {
        __u64 orig_off, dst_off;
        __u64 orig_size, dst_size;
    };
    LLIST_OF(struct yayo_px) ll_yayo_px;
    LLIST_OF(struct yayo_hook) ll_hooks;
};

struct xtc_px {
    union {
        __u64 orig_off;
        __u64 VirtualAddress;
    };
    instr *tabl_insn;
    __u8 sc[15];
    __u8 size;
};
typedef __u64 (*yayp_imm_hook_t)(struct yayo_px *, __u64 i, instr_dat_t *in, __u64 imm);

struct rel_yayo_tic {
    enum yayo_ref_t     t;
    yayp_imm_hook_t     hook_fn;
    union {
        /* PE64*/
        struct {
            pe64_image *bin;
            __u64 offset;
            __u64 size;
        } pe;
        /* Shellcode */
        struct {
            void *ptr;
            __u64 size;
        } mm;
        /* Virtual Mapping's */
        struct {
            LLIST_OF(struct rel_evmmap) ll_entries;
        } vmmap;
        /* Unicorn VM */
        struct {
            uc_engine *uc;
            LLIST_OF(struct rel_uc_evmmap) ll_entries;
        } uc;
    };
    struct {
        __u64       off;
    } out;
    LLIST_OF(struct xtc_px) ll_xtc_px;
    LLIST_OF(struct yayo_px) ll_yayo_px;
};

struct rel_yayo {
    LLIST_OF(struct rel_yayo_tic) ll_yayo;
};
#endif
