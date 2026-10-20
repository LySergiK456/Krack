#include <assert.h>
#include <unicorn/unicorn.h>
#include <windows.h>
#include "../../include/mem.h"
#include "../../include/syp/sype.hh"
#include "../../include/syp/uc.hh"
#include "../../x86disass/disass.hpp"
extern "C" {
    #include "../../include/utils.h"
    #include "../../include/syp/syscall.h"
};

static void dbg_pr_insn(insn_t &, void *, char *, char *, __u64, char *, char *,
                        __u64);
static NtSyscallTableEntry *win2wine_syscall_entry(__u64 nr);
typedef __s64 (*syscall_call_t)(__u64, __u64, __u64, __u64, __u64, __u64, __u64,
                                __u64);
static inline __u64 __syscall(__NtArgs &args);

using _KUSD_ = _KUSER_SHARED_DATA_;
static inline void memcpyTEB(_TEB_ *, _TEB_ *, shadow_mem_t *);
static inline void memcpyPEB(_PEB_ *, _PEB_ *, shadow_mem_t *);
static inline void memcpyLDR(_PEB_LDR_DATA_ *, _PEB_LDR_DATA_ *,
                             shadow_mem_t *);
static inline void memcpyKUSD(_KUSD_ *, _KUSD_ *, shadow_mem_t *);

namespace SlitYerPE {
void Dex::hook_code(uc_engine *uc, __u64 addr, __u64 i, void *raw_ctx) {
    auto dex = static_cast<Dex *>(raw_ctx);
    __u8 buf[0x10];
    Uc::read(uc, addr, buf, 0x10);
    auto insn = dex->d.disass(buf);

#ifdef HOOK_PR_INSN
    dex->PrintInsn(insn, reinterpret_cast<void*>(addr));
#endif

    if (!!IsSyscall(buf)) {
        __u64 retn = dispatch_syscall(uc, addr, i, raw_ctx);
        __u64 rip = Uc::reg(uc, X86Reg::rip);
        DBG_FMT(" syscall retn=0x%llx\n", retn);
        
        rip += insn.size();
        Uc::reg_wr(uc, X86Reg::rip, rip);
        Uc::reg_wr(uc, X86Reg::rax, retn);
    }
}
};

/* for each malloc - _defer( [&]{free(); }) */
namespace SlitYerPE {
__u64 Dex::dispatch_syscall(uc_engine *uc, __u64 addr, __u64 i, void *raw_ctx) {
    if (!raw_ctx) {
        DBGS("[-] !dispatch_syscall - supplied NULL raw_ctx");
        return -1;
    }
    auto dex = reinterpret_cast<Dex *>(raw_ctx);
    SlitYerPE::Ldr &r_ldr{dex->r->ldr};

    __u64 rsp = Uc::reg(uc, X86Reg::rsp);
    __NtArgs args = {.rax = Uc::reg(uc, X86Reg::rax),
                     .r10 = Uc::reg(uc, X86Reg::r10),
                     .rdx = Uc::reg(uc, X86Reg::rdx),
                     .r8 = Uc::reg(uc, X86Reg::r8),
                     .r9 = Uc::reg(uc, X86Reg::r9),
                     .rsp_h28 = Uc::read_u64(uc, rsp + 0x28),
                     .rsp_h30 = Uc::read_u64(uc, rsp + 0x30),
                     .rsp_h38 = Uc::read_u64(uc, rsp + 0x38),
                     .rsp_h40 = Uc::read_u64(uc, rsp + 0x40)};

    NT_ARGS_EACH(&args, pPtr, pSize, reg, pVal) {
        if (reg == (int)-1)
            reg = -1LL;

        if (!!Uc::get_map(uc, reg).begin) {
            auto map = r_ldr.VAtoShadow(reg);
            assert(!!map);

            *pPtr = reinterpret_cast<__u64>(map->ptr(reg));
            *pSize = map->size - (reg - map->uc_mem->addr);
            *pVal = *pPtr;
        } else {
            *pVal = reg;
        }
    }

    // Original [<teb,peb,ldr,kusd>] & Real [<teb,peb,ldr,kusd>]
    _TEB_ orig_teb{}, *teb = reinterpret_cast<_TEB_ *>(__readgsqword(0x30));
    _PEB_ orig_peb{}, *peb = reinterpret_cast<_PEB_ *>(__readgsqword(0x60));
    _PEB_LDR_DATA_ orig_ldr{},
        *ldr = reinterpret_cast<_PEB_LDR_DATA_ *>(peb->Ldr);
    _KUSD_ orig_kusd{},
        *kusd = reinterpret_cast<_KUSD_ *>(KUSER_SHARED_DATA_ADDR);
    /** Copy the Original [teb,peb,ldr,kusd]
     **/
    memcpy(reinterpret_cast<char *>(&orig_teb), teb, sizeof(_TEB_));
    memcpy(reinterpret_cast<char *>(&orig_peb), peb, sizeof(_PEB_));
    memcpy(reinterpret_cast<char *>(&orig_ldr), ldr, sizeof(_PEB_LDR_DATA_));
    memcpy(reinterpret_cast<char *>(&orig_kusd), kusd, sizeof(_KUSD_));

    /**
     * SH4D0W Memory **/
    auto shadow_teb = r_ldr.VAtoShadow(r_ldr.proc.teb_addr);
    auto shadow_peb = r_ldr.VAtoShadow(r_ldr.proc.peb_addr);
    auto shadow_ldr = r_ldr.VAtoShadow(r_ldr.proc.ldr_addr);
    auto shadow_kusd = r_ldr.VAtoShadow(r_ldr.proc.kusd_addr);

    __u32 _perm[4];
    __wr_init(teb, sizeof(_TEB_), &_perm[0]);
    __wr_init(peb, sizeof(_PEB_), &_perm[1]);
    __wr_init(peb, sizeof(_PEB_LDR_DATA_), &_perm[2]);
    __wr_init(kusd, sizeof(_KUSD_), &_perm[3]);

    /**
     * Replace/memcpy TEB->PEB->LDR->KUSD
     ** ~_~_~_~_ Danger [Z0ne] ~_~_~_~_ *
     * it needs to be in this order to not fuck something up,
     **/
    memcpyTEB(teb, &orig_teb, shadow_teb);
    memcpyPEB(peb, &orig_peb, shadow_peb);
    memcpyLDR(ldr, &orig_ldr, shadow_ldr);
    memcpyKUSD(kusd, &orig_kusd, shadow_kusd);

    /** Do syscall **/
    __u64 retn = __syscall(args);

    /* diff teb/peb*/
    memcpy(kusd, reinterpret_cast<char *>(&orig_kusd), sizeof(_KUSD_));
    memcpy(ldr, reinterpret_cast<char *>(&orig_ldr), sizeof(_PEB_LDR_DATA_));
    memcpy(peb, reinterpret_cast<char *>(&orig_peb), sizeof(_PEB_));
    memcpy(teb, reinterpret_cast<char *>(&orig_teb), sizeof(_TEB_));

    /**
     * Exit / VirtProtect(<base perms>) **/
    __wr_exit(teb, sizeof(_TEB_), _perm[0]);
    __wr_exit(peb, sizeof(_PEB_), _perm[1]);
    __wr_exit(peb, sizeof(_PEB_LDR_DATA_), _perm[2]);
    __wr_exit(kusd, sizeof(_KUSD_), _perm[3]);

    NT_ARGS_EACH(&args, pPtr, pSize, reg, _)
    if (!!*pPtr) {
        auto map = r_ldr.VAtoShadow(reg);
        if (map->IsX()) {
            _uc_assert(uc_mem_write(uc, reg, (void *)(*pPtr), *pSize));
        }
    }

    return retn;
}
};

static inline void memcpyTEB(_TEB_ *teb, _TEB_ *orig_teb,
                             shadow_mem_t *shadow_teb) {
    // make it work - not connected to current peb
    // teb->peb =
    // ((_TEB_*)shadow_teb->addr)->PebAddress -= 0x80000000;
    memcpy(teb, shadow_teb->addr,
           sizeof(_TEB_)); // need to fix teb StackAddr- etc...
    teb->PebAddress = orig_teb->PebAddress;
    teb->CurrentSEH = orig_teb->CurrentSEH;
    /* fake stack */
    teb->StackBase = orig_teb->StackBase;
    teb->StackLimit = orig_teb->StackLimit;
    teb->TebAddress = orig_teb->TebAddress;
    // (also peb,ldr,... dex pointing),
    // TlsAddress, RpcHandle, Win32ThreadInfo, CsrClientThreadAddre
    memcpy(teb->Win32ClientInfo, orig_teb->Win32ClientInfo,
           sizeof(teb->Win32ClientInfo));
    memcpy(teb->ReservedOS, orig_teb->ReservedOS, sizeof(teb->ReservedOS));
    teb->ReservedWow64 = orig_teb->ReservedWow64;
}

static inline void
memcpyPEB(_PEB_ *peb, _PEB_ *orig_peb, shadow_mem_t *shadow_peb)
{
    memcpy(peb, shadow_peb->addr, sizeof(_PEB_));
}

static inline void
memcpyLDR(_PEB_LDR_DATA_ *ldr, _PEB_LDR_DATA_ *orig_ldr, shadow_mem_t *shadow_ldr)
{
    memcpy(ldr, shadow_ldr->addr, sizeof(_PEB_LDR_DATA_));
}

static inline void
memcpyKUSD(_KUSD_ *kusd, _KUSD_ *orig_kusd, shadow_mem_t *shadow_kusd)
{
    memcpy(kusd, shadow_kusd->addr, sizeof(_KUSD_));
}

#define SYSCALL_OP const_cast<char *>("\x0F\x05")
#define SYSCALL_LEGACY_OP const_cast<char *>("\xCD\x2E")
bool SlitYerPE::Dex::IsSyscall(void *data) {
    return (!strncmp((char *)data, SYSCALL_OP, 2) ||
            !strncmp((char *)data, SYSCALL_LEGACY_OP, 2));
}

static inline __u64 __syscall(__NtArgs &args) {
    __u64 nr = args.rax;
    DBG_FMT("[SYSCALL=%i]", nr);

    NtSyscallTableEntry *entry = win2wine_syscall_entry(nr);
    if (!entry) {
        DBG_FMT(" [!] syscall (win10 NR)%i not implemented by wine\n", nr);
        return STATUS_ACCESS_VIOLATION;
    }
    if (!entry->fn) {
        DBG_FMT("[!] syscall ntdll!%s has non-initialized void(*)()\n",
                entry->name);
        return STATUS_ACCESS_VIOLATION;
    }

    auto fn = reinterpret_cast<syscall_call_t>(entry->fn);
    return fn(args.r10_v,      // 1st arg
              args.rdx_v,      // 2st
              args.r8_v,       // 3st
              args.r9_v,       // 4th
              args.rsp_h28_v,  // 5th
              args.rsp_h30_v,  // 6th
              args.rsp_h38_v,  // 7th
              args.rsp_h40_v); // 8th. 8+ not supported
}

static NtSyscallTableEntry *win2wine_syscall_entry(__u64 nr) {
    NtSyscallTableEntry *win10_syscall{};
    WIN10_EACH_SYSCALL(e) {
        if (e->v == nr)
            win10_syscall = e;
    }
    if (!win10_syscall)
        return nullptr;

    __u64 s_len = strlen(win10_syscall->name) + 1;
    WINE_EACH_SYSCALL(e) {
        if (!strncmp(win10_syscall->name, e->name, s_len))
            return e;
    }
    return nullptr;
}

namespace SlitYerPE {
void Dex::PrintInsn(insn_t &insn, void *addr) {
    auto src_img = r->ldr.VAtoImage(reinterpret_cast<__u64>(addr));
    if (!src_img) {
        insn.Print();
        return;
    }
    PE64 *src_pe = &src_img->bin;
    PE64_SYMBOL *src_sym{};

    if (!!src_pe->f.name)
        src_sym = src_pe->rva_to_sym((__u32)((__u64)addr - src_img->virt));

    char *src_sym_name =
        (!src_sym || !src_sym->name) ? const_cast<char *>("?") : src_sym->name;

    __u64 dst_addr = insn.PtrAddr((__u64)addr);
    if (dst_addr != -1) {
        auto dst_img = r->ldr.VAtoImage(dst_addr);
        if (!dst_img) goto pr_src;

        PE64 *dst_pe = &dst_img->bin;
        PE64_SYMBOL *dst_sym{};

        if (!!dst_pe->f.name)
            dst_sym =
                dst_pe->rva_to_sym((__u32)(((__u64)addr) - dst_img->virt));

        char *dst_sym_name = (!dst_sym || !dst_sym->name)
                                 ? const_cast<char *>("?")
                                 : dst_sym->name;

        dbg_pr_insn(
            insn,                // insn_t&
            addr,                // address
            src_pe->f.shortname, // "*.exe/dll"
            src_sym_name,        // symbol name
            (__u64)((!!src_sym) ? addr - (src_img->virt + src_sym->rva) : 0),
            dst_pe->f.shortname, // -> "*.exe/dll"
            dst_sym_name,        // dst symbol name
            dst_addr - dst_img->virt);
    } else {
        pr_src:
        dbg_pr_insn(
            insn, addr, src_pe->f.shortname, src_sym_name,
            (__u64)((!!src_sym) ? addr - (src_img->virt + src_sym->rva) : 0),
            nullptr, 0, 0);
    }
}
};

static void dbg_pr_insn(insn_t &insn, void *addr, char *src_name, char *src_sym,
                        __u64 src_sym_off, char *dst_name, char *dst_sym,
                        __u64 dst_sym_off) {
    Util::White();
    DBG_FMT("0x%-8lx ", addr);

    Util::Reset();
    DBG_F("[");
    Util::Green();
    DBG_FMT("%s", src_name);
    Util::Reset();

    DBG_F("] <");

    Util::Blue();
    DBG_FMT("%s", src_sym);
    Util::Reset();
    DBG_F("+");
    Util::White();
    DBG_FMT("0x%lx", src_sym_off);
    Util::Reset();
    DBG_F(">");

    if (!!dst_name) {
        DBG_F(" -~*> [");
        Util::Green();
        DBG_FMT("%s", dst_name);
        Util::Reset();

        DBG_F("] <");

        Util::Blue();
        DBG_FMT("%s", dst_sym);
        Util::Reset();
        DBG_F("+");
        Util::White();
        DBG_FMT("0x%lx", dst_sym_off);
        Util::Reset();
        DBG_F(">");
    }

    Util::Reset();
    DBG_F(" -~*> ");
    Util::Red();
    insn.Print();
    Util::Reset();
}
