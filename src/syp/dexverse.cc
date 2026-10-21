#include "../../include/syp/sype.hh"
#include "../../x86disass/disass.hpp"
extern "C" {
	#include "../../include/syp/dex.h"
};

namespace SlitYerPE::DexVerse
{
dex_ctx_t *newDexCtx() {
	dex_ctx_t *dex = (dex_ctx_t*)xmalloc(sizeof(dex_ctx_t));
	llist_init(&dex->ll_src,	sizeof(struct dex_taint_src_t));
	llist_init(&dex->ll_taints,	sizeof(struct dex_taint_t));
	return dex;
}

void addDexSource(dex_ctx_t *ctx, __u64 addr, __u64 size) {
	struct dex_taint_src_t e = {
		.addr=addr, .size=size
	};
	llist_push((_LL_TYPE_*)&ctx->ll_src, &e);
}

enum X86OperType dex_oper_type(operand *op) {
	if (!!op->rip)
		return X86OperType::RIP;
	else if (!!op->is_ptr)
		return X86OperType::PTR;
	else if (!!op->reg)
		return X86OperType::REG;
	else if (!!op->is_imm)
		return X86OperType::IMM;

	return X86OperType::NONE;
}

int dex_callback(dex_ctx_t *dex, uc_engine *uc, __u64 addr) {
	uc_err err{UC_ERR_OK};
	if (!dex) return -1;

	err = uc_mem_read(uc, addr, &dex->ctx.data, 0x10);
	if (!_uc_ok(err)) return err;

	if (c_init_instr(X86_64, &dex->ctx.in, dex->ctx.data) == -1)
		return -1;

	auto &in			= dex->ctx.in;
	operand *dst_oper	= &in.oper[0];
	auto dst			= &dex->ctx.dst;
	if (!dex->ctx.in.insn || !!dst_oper->is_empty)
	{	/* Null insn or no operands*/
		return 0;
	}


	switch (dex_oper_type(dst_oper))
	{
		case X86OperType::RIP:
			get_rip_ptr_addr(&in, reinterpret_cast<void*>(addr), &dst->addr);
			break;
		case X86OperType::IMM:
			dst->imm = *(__u64*)&dst_oper->imm;
			break;
		case X86OperType::REG:
			dst->reg = dst_oper->reg;
			break;
	}
	dst->sz = dst_oper->sz;

	__u8 iter{0};
	foreach_operand(op, &in) {
		switch (dex_oper_type(op)) {
			case X86OperType::RIP:
			{
				__u64 v{};
				if (!!get_rip_ptr_addr(&in, reinterpret_cast<void*>(addr), &v))
					return -1;

				ll_each(&dex->ll_src, e) {
					auto src = (struct dex_taint_src_t*)e->v;
					if (_contain_(src->addr, src->size, v))
					{
						if (iter > 0)
						{	/** Not the destination oper **/
							struct dex_taint_t e = {.size=op->sz };
							if (!!dst->reg) e.dst_reg = dst->reg;
							if (!!dst->addr)e.dst_addr= dst->addr;
							llist_push((_LL_TYPE_*)&dex->ll_taints, &e);
							c_pr_in_str(&in);
						}
					}
				}
			};
			break;
		}
		iter++;
	}
	return err;
}
};
