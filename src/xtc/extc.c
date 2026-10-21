#include "../../include/utils.h"
#include "../../include/xtc/xtc.h"

#define XTC_ENTN(x) ((x) * sizeof(xtc_ehdr))

static int pread(FILE *f, void *buf, __u64 size, __u64 off);

int new_x_t_c(x_t_c_dump *x, char *dumpfile) {
    memset(x, 0, sizeof(x_t_c_dump));
    x->f = fopen(dumpfile, "rb");
    if (!x->f)
        return -1;

    pread(x->f, &x->x_fhdr, sizeof(xtc_fheader), 0);

    x->x_entries = xmalloc(XTC_ENTN(x->x_fhdr.e_count));
    pread(x->f, x->x_entries, XTC_ENTN(x->x_fhdr.e_count), sizeof(xtc_fheader));
    return 0;
}

/* wide */
int xtc_make_insn(x_t_c_dump *x, char *mnemonic, struct xtc_oper *ops,
                  __u8 *sc) {
    __u64 s_len = strlen(mnemonic) + 1;

    for (__u32 i = 0; i < x->x_fhdr.e_count; i++) {
        xtc_ehdr *e = &x->x_entries[i];
        instr *i_tabl = &x86_64_tabl[e->tabl_ndx];
        __u64 size = e->count * sizeof(struct xtc_instr);

        if (!!i_tabl->mnemonic && !_memcmp(mnemonic, i_tabl->mnemonic, s_len)) {
            goto target;
        } else
            for (__u8 l = 0; l < i_tabl->ops_count; l++) {
                if (!!i_tabl->ops[l].mnemonic &&
                    !_memcmp(mnemonic, i_tabl->ops[l].mnemonic, s_len)) {
                    goto target;
                }
            }
        continue;

    target:
        do {
            struct xtc_instr *xin_ptr = xmalloc(size);
            if (!xin_ptr) return -1;
            int ret = pread(x->f, xin_ptr, size, e->offset);
            if (ret == -1) return -1;

            for (__u64 l = 0; l < e->count; l++) {
                struct xtc_instr *xin = &xin_ptr[l];

                for (__u8 k = 0; k < xin->op_count; k++)
                    if (ops[k].t != xin->op[k].t ||
                        ops[k].size != xin->op[k].size)
                        goto next;

                __u8 j = 0;
                if (!!xin->pfx.addr)sc[j++] = xin->pfx.addr;
                if (!!xin->pfx.oper)sc[j++] = xin->pfx.oper;
                if (!!xin->pfx.rex) sc[j++] = xin->pfx.rex;
                _build_instr(&x86_64_tabl[e->tabl_ndx], &sc[j]);
                goto retn;

            next:
            }
        retn:
            do {
                free(xin_ptr);
                return 0;
            } while (0);
        } while (0);
    }

    return -1;
}

void x_t_c_fini(x_t_c_dump *x) {
    if (!x)
        return;

    if (!!x->x_entries)
        free(x->x_entries);
    fclose(x->f);
    memset(x, 0, sizeof(x_t_c_dump));
}

static int pread(FILE *f, void *buf, __u64 size, __u64 off) {
    __u64 pos = _ftelli64(f);
    if (pos == -1)
        return -1;

    _fseeki64(f, off, SEEK_SET);
    if (fread(buf, 1, size, f) < 0LL)
        return -1;

    _fseeki64(f, pos, SEEK_SET);
    return 0;
}
