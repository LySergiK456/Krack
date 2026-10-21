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

SlitYerPE::Lyss::Lyss(_1Dlsd *l, pe64_image &_pe)
    : lsd{l}, base_pe{_pe}
{
    auto& pe_img    = base_pe;
    auto& pe        = pe_img.bin;
    push(&pe_img, DosHdr, pe_img.dos);
    push(&pe_img, DosStub,pe_img.dos_stub);
    push(&pe_img, NtHdrs, pe_img.nt);

    for (auto& sechdr : pe_img.sechdr)  push(&pe_img, SecHdr, sechdr);
    for (auto& sec : pe_img.sections)   push(&pe_img, Section, sec);

    PE_EACH_DATA_DIR(i)
    {
        auto dir = &pe.nt->OptionalHeader.DataDirectory[i];
        auto v = self << (pe64_hdr_t{
            { dir, MM_HEAP, sizeof(IMG_DATA_DIRECTORY) },
            ((__u64)dir - (__u64)pe.pMem)
        });
        push(&pe_img, DataDir, *v);
    }

    PE_EACH_DATA_DIR(i)
    {
        auto dir = &pe.nt->OptionalHeader.DataDirectory[i];
        __u64 off = pe.rva_to_off((__u64)dir->VirtualAddress);
        auto v = self << pe64_hdr_t{
            { &pe.pMem[off], MM_HEAP, dir->Size, },
            off
        };

        enum _1DLSD_TYPE t{};
        switch (i) {
            case IMG_DIR_EXPORT:        t = DataDirExport;      break;
            case IMG_DIR_IMPORT:        t = DataDirImport;      break;
            case IMG_DIR_RESOURCE:      t = DataDirRsrc;        break;
            case IMG_DIR_EXCEPTION:     t = DataDirExcept;      break;
            case IMG_DIR_SECURITY:      t = DataDirSec;         break;
            case IMG_DIR_BASERELOC:     t = DataDirReloc;       break;
            case IMG_DIR_DEBUG:         t = DataDirDbg;         break;
            case IMG_DIR_ARCHITECTURE:  t = DataDirArch;        break;
            case IMG_DIR_GLOBALPTR:     t = DataDirGlobalPtr;   break;
            case IMG_DIR_TLS:           t = DataDirTLS;         break;
            case IMG_DIR_LOAD_CONFIG:   t = DataDirLoadConf;    break;
            case IMG_DIR_BOUND_IMPORT:  t = DataDirBoundImp;    break;
            case IMG_DIR_IAT:           t = DataDirIAT;         break;
            case IMG_DIR_DELAY_IMPORT:  t = DataDirDelayImp;    break;
            case IMG_DIR_COM_DESCRIPTOR:t = DataDirComDesc;     break;
        }
        if (!!t) push(&pe_img, t, *v);
    }

    ChopSections();
    ChopSegments();
}

SlitYerPE::Lyss::~Lyss() {
    for (auto& ptr : tofree) delete ptr;
}

namespace SlitYerPE
{
void Lyss::ChopSections() {
    PE_EACH_SEC(&base_pe.bin, sec)
    {
        enum _1DLSD_TYPE t{};
        std::string name((char*)sec->Name);

        if (!sec->Name);
        else if (name == ".text")     t = SEC_text;
        else if (name == ".data")     t = SEC_data;
        else if (name == ".rdata")    t = SEC_rdata;
        else if (name == ".bss")      t = SEC_bss;
        else if (name == ".idata")    t = SEC_idata;
        else if (name == ".edata")    t = SEC_edata;
        else if (name == ".reloc")    t = SEC_reloc;
        else if (name == ".rsrc")     t = SEC_rsrc;
        else if (name == ".tls")      t = SEC_tls;
        else if (name == ".pdata")    t = SEC_pdata;
        else if (name == ".xdata")    t = SEC_xdata;
        else if (name == ".debug")    t = SEC_debug;
        else if (name == ".CRT")      t = SEC_CRT;
        else if (name == ".gfids")    t = SEC_gfids;
        else if (name == ".didat")    t = SEC_didat;
        else if (name == ".sxdata")   t = SEC_sxdata;
        else if (name == ".00cfg")    t = SEC_00cfg;
        else if (name == ".gehcont")  t = SEC_gehcont;
        else if (name == ".orpc")     t = SEC_orpc;
        else if (name == ".arch")     t = SEC_arch;
        else if (name == ".drectve")  t = SEC_drectve;

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

void Lyss::AlignHeaders(__u64 off, __u64 sz) {
    for (auto& [k, emm] : map) {
        if (_contain_(k, emm.mm->sz, off)) {
            map[k].mm->sz += sz;
        } else if (k >= off) {
            map.erase(k);
            map[k+sz] = emm;
        }
    }
}

void Lyss::ChopSegments() {
    using F = offsz_t;
    F *prev{};
    std::list<F> ll;
    
    for (auto& [off, e] : map) {
        ll.push_back({off, e.mm->sz});
    }
    ll.push_back({
        base_pe.bin.nt->OptionalHeader.SizeOfImage, 0
    });
    ll.sort([](F& a, F& b) { return a.off < b.off; });

    for (auto& e : ll) {
        __u64 p = (!!prev ? prev->off + prev->sz : 0);
        if (p < e.off) {
            map[p].mm = new mm_t({
                (void*)&base_pe.bin.pMem[p],
                MM_NONE,
                e.off-p,
            });
            map[p].src = {
                .pe=&base_pe, .off=p, .sz=e.off-p,
            };
        }
        prev = &e;
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
