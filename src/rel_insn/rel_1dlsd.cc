#include <windows.h>
#include "../../include/pe64/pe64.hh"
#include "../../include/rel/1dlsd.hh"
#include "../../include/conf.hh"
#include "../../include/utils.hh"
extern "C" {
    #include "../../include/rel/rel_yayo.h"
};

SlitYerPE::_1Dlsd::_1Dlsd(pe64_image &base_pe, lsd_pass &_p)
    : lyss(this, base_pe), pass{_p}
{
    llist_init(&pImg, sizeof(pe64_image *));
    llist_init(&px, sizeof(_1Dlsd_entry));
}


namespace SlitYerPE
{
namespace U = Util;
void Lyss::initSections() {
    PE_EACH_SEC(&base_pe.bin, sec) {
        enum _1DLSD_TYPE t{};

        __u64 hn = U::hash((char*)sec->Name);
        do {
            if (hn == U::hash((char*)".text"))          t=SEC_text;
            else if (hn == U::hash((char*)".data"))     t=SEC_data;
            else if (hn == U::hash((char*)".rdata"))    t=SEC_rdata;
            else if (hn == U::hash((char*)".bss"))      t=SEC_bss;
            else if (hn == U::hash((char*)".idata"))    t=SEC_idata;
            else if (hn == U::hash((char*)".edata"))    t=SEC_edata;
            else if (hn == U::hash((char*)".reloc"))    t=SEC_reloc;
            else if (hn == U::hash((char*)".rsrc"))     t=SEC_rsrc;
            else if (hn == U::hash((char*)".tls"))      t=SEC_tls;
            else if (hn == U::hash((char*)".pdata"))    t=SEC_pdata;
            else if (hn == U::hash((char*)".xdata"))    t=SEC_xdata;
            else if (hn == U::hash((char*)".debug"))    t=SEC_debug;
            else if (hn == U::hash((char*)".CRT"))      t=SEC_CRT;
            else if (hn == U::hash((char*)".gfids"))    t=SEC_gfids;
            else if (hn == U::hash((char*)".didat"))    t=SEC_didat;
            else if (hn == U::hash((char*)".sxdata"))   t=SEC_sxdata;
            else if (hn == U::hash((char*)".00cfg"))    t=SEC_00cfg;
            else if (hn == U::hash((char*)".gehcont"))  t=SEC_gehcont;
            else if (hn == U::hash((char*)".orpc"))     t=SEC_orpc;
            else if (hn == U::hash((char*)".arch"))     t=SEC_arch;
            else if (hn == U::hash((char*)".drectve"))  t=SEC_drectve;
        } while (0);

        auto hdr = new pe64_hdr_t{
            {
                (void*)&base_pe.bin.pMem[sec->PointerToRawData],
                MM_HEAP,
                sec->SizeOfRawData,
            }, sec->PointerToRawData
        };
        push(&base_pe, t, *hdr);
    }
}
};

namespace SlitYerPE {
__s8 _1Dlsd::make(char *f) {
    auto out = Util::outfile_t(f);

    DBG_FMT("-[_1Dlsd]-\t~[+]~ Dumping to [%s]\n", f);
    for (auto& [off, e] : lyss.map) {
    DBG_FMT("        -> @0x%llx - size 0x%lx\n", off, e.mm->sz);
        out.pwrite(e.mm->mem, e.mm->sz, off);
    }

    return 0;
}
};
