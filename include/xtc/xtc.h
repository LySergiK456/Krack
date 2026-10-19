#include "../types.h"

#ifndef KRACK_XTC_H
#define KRACK_XTC_H
#include "../../x86disass/disass.h"

enum x86_op_type {
    X86_OP_NONE = 0,
    X86_OP_IMM = 1,
    X86_OP_REG = 2,
    X86_OP_FXD = 4,
    X86_OP_PTR = 8,
};

#define X_T_C_X64_STR (char *)"x8664"

typedef struct {
    char type[6];
    __u64 e_count;
} xtc_fheader;

typedef struct {
    __u16 tabl_ndx;
    __u64 offset;
    __u64 count;
} xtc_ehdr;

struct xtc_oper {
    enum x86_op_type t;
    __u32 size;
};
struct xtc_instr {
    __u16 tabl_ndx;
    __u8 sub_ndx;
    struct {
        __u8 rex, addr, oper;
    } pfx;

    struct xtc_oper op[4];
    __u8 op_count;
};

typedef struct {
    FILE *f;
    xtc_fheader x_fhdr;
    xtc_ehdr *x_entries;
} x_t_c_dump;

int new_x_t_c(x_t_c_dump *x, char *dumpfile);
int xtc_make_insn(x_t_c_dump *x, char *mnemonic, struct xtc_oper *ops,
                  __u8 *sc);
void x_t_c_fini(x_t_c_dump *x);

#endif
