#include "../types.h"
#include "../mem.h"
#include "../llist.h"

#ifndef KRACK_DEX_H
#define KRACK_DEX_H
struct dex_taint_src_t {
	__u64		addr;
	__u64		size;
};

struct dex_taint_t {
	__u32	dst_reg;
	__u64	dst_addr;
	__u8	size;	// _QWORD_
};

typedef struct _dexternal_t {
	char				data[0x10];
	enum X86OperType	t;
	insn_t				in;

	struct {
		__u64	addr;
		__u64	imm;
		__u32	reg;
		__u64	sz;
	} dst;
} dexternal_t;

typedef struct {
	struct {
		x86_regs	regs;
	} vcpu;
	LLIST_OF(struct dex_taint_src_t)	ll_src;
	LLIST_OF(struct dex_taint_t)		ll_taints;
	dexternal_t							ctx;
} dex_ctx_t;
#endif
