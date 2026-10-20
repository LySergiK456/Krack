#include "../../x86disass/disass.hpp"
#include "../conf.hh"
#include "../mem.hh"
#include "../pe64/pe64.hh"
#include "./uc.hh"
#include <list>
#include <memory>
#include <type_traits>
#include <unicorn/unicorn.h>
extern "C" {
#include "../types.h"
};

#ifndef KRACK_SYPE_HH
#define KRACK_SYPE_HH
namespace SlitYerPE {
class Razor;
class RtlHeap;
class DbgTcp;
class Dex;
};

#define __ENTRY__(addr, entry, e) (__u64)(addr) + ((__u64)(entry) - (__u64)(e))

// using std::shared_ptr<PE64_IMAGE>	= std::shared_ptr<PE64_IMAGE>;
// using PE64_IMAGE_LIST	= std::list<std::shared_ptr<PE64_IMAGE>>;

namespace SlitYerPE {
__attribute__((constructor)) void init_wine_syscalls();
};

namespace SlitYerPE {
class Ldr {
  public:
    struct {
        int num;
        char **v;
    } args;
    struct {
        __u64 teb_addr{TEB_ADDR};
        __u64 peb_addr{PEB_ADDR};
        __u64 ldr_addr{LDR_ADDR};
        __u64 kusd_addr{KUSER_SHARED_DATA_ADDR};
    } proc;

    __u64 _gs{static_cast<__u64>(KrackConf::GS_ADDR)};
    __u64 _fs{static_cast<__u64>(KrackConf::FS_ADDR)};

  private:
    std::shared_ptr<PE64_IMAGE> main_image;
    std::list<std::shared_ptr<PE64_IMAGE>> img;

  public:
    std::list<mem_map_t *> pmem_maps;
    std::list<shadow_mem_t *> shadow;
    uc_engine *uc;
    __s8 ok{0};

    Ldr() = default;
    Ldr(int argc, char **argv);
    virtual ~Ldr() = default; // LdrUtils::RtlHeap
    uc_err Run();

    std::shared_ptr<PE64_IMAGE> VAtoImage(__u64 va);
    shadow_mem_t *VAtoShadow(__u64 virt);

    void addLdrEntry(std::shared_ptr<PE64_IMAGE> dll_img);
    void addLdrEntry(__u64 virt, char *basename, char *fullname);
    void addLdrEntry(__u64 virt, wchar_t *wbasename, wchar_t *wfullname);
    __u64 AllocUcStr(char *str);
    __u64 AllocUcStr(wchar_t *wstr);

  private:
    /** Init environment -
     * - TEB, PEB, LDR, stack, gs:[]&fs:[]
     **/
    uc_err InitProcEnv();
    uc_err init_gs_fs(__u64 gs, __u64 fs);
    uc_err init_stack(__u64 addr, __u64 sz);
    void initTEB();
    void initPEB();
    void initLDR();
    void initKUSD();

    uc_err InitDLLs(std::shared_ptr<PE64_IMAGE> pe_img);

    /** Image - relocation, IAT-fixups, Mappings
     */
    uc_err MapImage(std::shared_ptr<PE64_IMAGE> pe_img);
    uc_err MapImage(std::shared_ptr<PE64_IMAGE> pe_img, __u64 img_base);
    uc_err MapDLLs(std::shared_ptr<PE64_IMAGE> pe_img, __u64 *off);
    uc_err FixIAT(std::shared_ptr<PE64_IMAGE> pe_img);
    uc_err RelocateImage(std::shared_ptr<PE64_IMAGE> pe_img);

    /** uc~mappings 2 Sh4d0w mappings
     */
    void virt_map_fxd(__u64 addr, __u64 size, __u32 prot);
    uc_err uc_map_fxd(__u64 addr, __u64 size, __u32 prot);

    uc_err mmap(__u64 virt, __u64 size, __u32 perm);
    uc_err mmap(__u64 virt, __u64 size, __u32 perm, char *name);

  public:
    uc_err mmemcpy(__u64 virt, void *ptr, __u64 size);
    template <typename X = __u64, typename V, typename E, typename ST>
    uc_err mwrite(X v, V value, E *entry, ST *e) {
        return mwrite(__ENTRY__(v, entry, e), value);
    }
    uc_err mwrite(__u64 virt, auto v);
    template <typename T, typename V> uc_err mwrite(T virt, V v) {
        return mwrite((__u64)virt, v);
    }

    template <typename X = __u64, typename V, typename E, typename ST>
    uc_err mcopy(X v, V value, E *entry, ST *e) {
        return mcopy(__ENTRY__(v, entry, e), value);
    }
    uc_err mcopy(__u64 virt, auto v);
    template <typename T, typename V> uc_err mcopy(T virt, V v) {
        return mwrite((__u64)virt, v);
    }

    std::shared_ptr<PE64_IMAGE> FindDLL(char *name);

  private:
    __u64 uc_malloc(__u64 size);
    std::shared_ptr<PE64_IMAGE> img_push(char *file);
    std::shared_ptr<PE64_IMAGE> img_push(char *file, __u64 base);

    friend class RtlHeap;
    friend class Dex;
};

__s8 wine_name(char *ret, __u64 size, char *dll_name);
};

namespace SlitYerPE {
class Razor {
    Disass d;
    std::shared_ptr<PE64_IMAGE> ntoskrnl;
    std::list<std::shared_ptr<PE64_IMAGE>> ntoskrnl_dll;

    Dex *dex;
    uc_hook insn_hook_trace;

  public:
    Ldr ldr;

    Razor() = default;
    Razor(Razor &r) = default;
    Razor(Razor &&r) = default;
    Razor(Razor *r) : Razor(*r) {}
    Razor(int argc, char **argv);

    Razor &operator=(Razor &&r) = default;

    uc_err Run();
    void pe32_fix_imports(std::shared_ptr<PE64_IMAGE> pe_img);

  private:
    void load_dlls(std::shared_ptr<PE64_IMAGE> pe_img);
    std::shared_ptr<PE64_IMAGE> FindNtosktnlDLL(char *name);
    void test();
};

class Dex {
  public:
    Razor *r;
    Disass d;

    Dex(Dex &&x) = default;
    Dex(Razor *_r) : r{_r} {}

    void PrintInsn(insn_t &insn, void *addr);
    static void hook_code(uc_engine *uc, __u64 addr, __u64 i, void *raw_ctx);
    static __u64 dispatch_syscall(uc_engine *uc, __u64 addr, __u64 i,
                                  void *raw_ctx);
    static bool IsSyscall(void *data);
};
};

/**
 * Loader(~SlitYerPE::Ldr) Utils
 **/
namespace SlitYerPE {
namespace LdrUtils {
class RtlHeap {
    Ldr &ldr;
    std::shared_ptr<PE64_IMAGE> ntdll_img;
    PE64 *ntdll;
    __u64 retn_addr{0xdeadc000};

  public:
    __s8 ok{-1};

    RtlHeap(Ldr &l);
    operator bool() const { return ok != -1; }

  private:
    void setup_regs();
    uc_err init(__u64 fn);
};
}; // namespace LdrUtils
};
#endif
