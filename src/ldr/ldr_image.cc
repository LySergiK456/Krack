#include <assert.h>
#include <windows.h>
// #include <ntifs.h>
#include "../../include/syp/sype.hh"
#include "../../include/syp/uc.hh"

namespace SlitYerPE {
static bool is_contract_dll(char *name);
};

namespace SlitYerPE {
uc_err Ldr::InitDLLs(std::shared_ptr<PE64_IMAGE> pe_img) {
    uc_err err{UC_ERR_OK};
    auto pe = &pe_img->bin;

    DBG_FMT(" ~[+]~ Initializing DLL [%s]\n", pe->f.name);
    PE_EACH_XIMPORT(pe, imp) {
        if (is_contract_dll(imp->name))
            continue;

        char name[0x100];
        assert(!wine_name(name, sizeof(name), imp->name));

        std::shared_ptr<PE64_IMAGE> dll_img = FindDLL(name);
        assert(!!dll_img);

        __u64 entry_rva = dll_img->bin.nt->OptionalHeader.AddressOfEntryPoint;
        __u64 entry_va = dll_img->virt + entry_rva;
        if (!entry_rva)
            return UC_ERR_OK;

        err = InitDLLs(dll_img);
        if (!_uc_okay(err, ok))
            return err;

        Uc::reg_wr(uc, X86Reg::rcx, dll_img->virt);
        Uc::reg_wr(uc, X86Reg::edx, DLL_PROCESS_ATTACH);
        Uc::reg_wr(uc, X86Reg::r8, 0);

        DBG_FMT(" ~[*]~ calling DllMain of [%s] entry=0x%lx\n", imp->name,
                entry_va);
        err = uc_emu_start(uc, entry_va, 0, 0, 0);
        if (!_uc_okay(err, ok))
            return err;
    }

    return err;
}

std::shared_ptr<PE64_IMAGE> Ldr::img_push(char *file, __u64 base) {
    auto image = img_push(file);
    image->virt = base;
    return image;
}

std::shared_ptr<PE64_IMAGE> Ldr::img_push(char *file) {
    img.push_back(std::make_shared<PE64_IMAGE>(file, PE_SYMTAB_DIR));
    return img.back();
}
}; // namespace SlitYerPE

namespace SlitYerPE {
uc_err Ldr::MapImage(std::shared_ptr<PE64_IMAGE> pe_img) {
    return MapImage(pe_img, pe_img->virt);
}

uc_err Ldr::MapImage(std::shared_ptr<PE64_IMAGE> pe_img, __u64 base) {
    uc_err err{UC_ERR_OK};
    assert(!!pe_img && pe_img->bin.ok != -1);
    auto pe = &pe_img->bin;

    __u64 hdr_size = pe->nt->OptionalHeader.SizeOfHeaders;
    mmap(base, PAGE_ALIGN_UP(hdr_size), UC_PROT_RW, pe->f.shortname);
    mmemcpy(base, pe->pMap, hdr_size);
    __u64 img_size = pe->nt->OptionalHeader.SizeOfImage;

    PE_EACH_XSEC(pe, sec) {
        __u64 sec_size = PAGE_ALIGN_UP(sec->VirtSize);
        void *sec_ptr = static_cast<void *>(&pe->pMem[sec->Off]);

        __u32 perms = 0;
        if (sec->isR)
            perms |= UC_PROT_READ;
        if (sec->isW)
            perms |= UC_PROT_WRITE;
        if (sec->isX)
            perms |= UC_PROT_EXEC;

        mmap(base + sec->Virt, sec_size, perms, pe->f.shortname);
        mmemcpy(base + sec->Virt, sec_ptr, sec->FileSize);
    }

    err = RelocateImage(pe_img);
    if (!_uc_okay(err, ok))
        return err;

    __u64 entry = base + pe->nt->OptionalHeader.AddressOfEntryPoint;
    __u64 ep_entry_off =
        (__u64)&pe->nt->OptionalHeader.AddressOfEntryPoint - (__u64)pe->pMap;
    if (!_uc_ok(err = mwrite(base + ep_entry_off, entry)))
        return err;

    addLdrEntry(pe_img);
    return err;
}

uc_err Ldr::RelocateImage(std::shared_ptr<PE64_IMAGE> pe_img) {
    uc_err err{UC_ERR_OK};
    assert(!!pe_img && pe_img->bin.ok != -1);

    PE_EACH_RELOC(&pe_img->bin, reloc) {
        PE_EACH_RELOC_ENTRY(reloc, i) {
            __u64 rel_off = i & 0xfff;
            __u64 rel_type = i >> 12;
            __u64 uc_addr =
                (__u64)pe_img->rva_to_ptr(reloc->VirtualAddress + rel_off);
            __u64 v{};

            switch (rel_type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_DIR64: {
                err = uc_mem_read(uc, uc_addr, &v, sizeof(__u64));
                if (!_uc_okay(err, ok))
                    return err;
                v += pe_img->virt;
                // printf("%lx\n", Uc::get_map(uc, uc_addr).begin);
                err = mwrite(uc_addr, v);
                if (!_uc_okay(err, ok)) {
                    puts("FUCK!");
                    return err;
                }
            }; break;
            default: // eh..
                return UC_ERR_RESOURCE;
            }
        }
    }
    return err;
}

uc_err Ldr::MapDLLs(std::shared_ptr<PE64_IMAGE> pe_img, __u64 *off_ptr) {
    uc_err err{UC_ERR_OK};
    assert(!!pe_img && pe_img->bin.ok != -1);
    auto pe = &pe_img->bin;

    DBG_FMT("~[+]~ Loading %s\n", pe->f.shortname);

    PE_EACH_XIMPORT(pe, imp) {
        __u64 dll_base = LOAD_DLL_BASE + *off_ptr;
        if (is_contract_dll(imp->name))
            continue;

        char name[0x1000];
        assert(!wine_name(name, sizeof(name), imp->name));

        std::shared_ptr<PE64_IMAGE> dll_img;
        PE64 *dll_pe{};

        /** Find DLLs **/
        for (auto &image : img)
            if (!strncmp(name, image->bin.f.name, strlen(name) + 1)) {
                dll_img = image;
                dll_pe = &image->bin;
                break;
            }

        if (!dll_pe) {
            dll_img = img_push(name, dll_base);
            if (!dll_img)
                return UC_ERR_NOMEM;

            err = MapImage(dll_img, dll_base);
            if (!_uc_okay(err, ok))
                return err;
            dll_pe = &dll_img->bin;
            *off_ptr += PAGE_ALIGN_UP(dll_pe->nt->OptionalHeader.SizeOfImage);
        }

        err = MapDLLs(dll_img, off_ptr);
        if (!_uc_okay(err, ok))
            return err;
    }
    return err;
}

uc_err Ldr::FixIAT(std::shared_ptr<PE64_IMAGE> pe_img) {
    uc_err err{UC_ERR_OK};
    auto pe = &pe_img->bin;

    PE_EACH_XIMPORT(pe, imp) {
        if (is_contract_dll(imp->name))
            continue;

        char name[0x100];
        assert(!wine_name(name, sizeof(name), imp->name));

        std::shared_ptr<PE64_IMAGE> dll_img = FindDLL(name);
        assert(!!dll_img);
        PE64 *dll_pe = &dll_img->bin;
        __u64 dll_base = dll_img->virt;

        err = FixIAT(dll_img);
        if (!_uc_okay(err, ok))
            return err;

        for (__u32 i = 0; !!imp->ILT[i].u1.AddressOfData; i++) {
            __u32 fn_rva{};

            if (imp->ILT[i].u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                __u32 ord = imp->ILT[i].u1.Ordinal & 0xffff;
                fn_rva = dll_pe->exp.Func[ord - dll_pe->exp.Dir->Base];
            } else {
                IMAGE_IMPORT_BY_NAME *ibn =
                    reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(
                        pe->rva_to_ptr(imp->ILT[i].u1.AddressOfData));
                char *imp_name = ibn->Name;
                PE_EACH_EXPORT(dll_pe, i)
                if (!strcmp(imp_name,
                            (char *)dll_pe->rva_to_ptr(dll_pe->exp.Name[i]))) {
                    fn_rva = dll_pe->exp.Func[dll_pe->exp.Ords[i]];
                    break;
                }
            }
            if (!!fn_rva) {
                __u64 uc_iat = pe_img->virt;
                +pe->off_to_rva((__u64)imp->IAT - (__u64)pe->pMap);
                __u64 *uc_iat_fn =
                    &(((IMAGE_THUNK_DATA64 *)uc_iat)[i].u1.Function);
                mwrite(uc_iat_fn, dll_base + fn_rva);
            }
        }
    }
    return err;
}

std::shared_ptr<PE64_IMAGE> Ldr::FindDLL(char *name) {
    for (auto &image : img)
        if (!strncmp(name, image->bin.f.name, strlen(name) + 1) ||
            !strncmp(name, image->bin.f.shortname, strlen(name) + 1)) {
            return image;
        }

    return nullptr;
}
}; // namespace SlitYerPE

namespace SlitYerPE {
static bool is_contract_dll(char *name) {
    return !!name && (!strncmp(name, "api-ms-win-", 11) ||
                      !strncmp(name, "ext-ms-win-", 11));
}
}; // namespace SlitYerPE

namespace SlitYerPE::LdrUtils {
RtlHeap::RtlHeap(Ldr &l) : ldr{l} {
    ntdll_img = ldr.FindDLL("ntdll.dll");
    if (!ntdll_img && (ok == -1))
        return;
    ntdll = &ntdll_img->bin;

    PE64_SYMBOL *sym = ntdll->name_to_sym("RtlCreateHeap");
    if (!sym && (ok == -1))
        return;

    __u64 fn = ntdll_img->virt + sym->rva;

    /** Setup Registers[rbp, rsp[+0x28;+0x30], rcx,rdx,r8,r9 ]
     * rax = [in-VM] RtlCreateHeap(-{ REGS }-);
     */
    setup_regs();
    if (!_uc_okay(init(fn), ok))
        return;

    __u64 heap = Uc::reg(ldr.uc, X86Reg::rax);
    if (!HANDLE_OK(reinterpret_cast<HANDLE>(heap))) {
        ok = -1;
    } else {
        ldr.mwrite(&((_PEB_ *)ldr.proc.peb_addr)->ProcessHeap, heap);
    }
}

uc_err RtlHeap::init(__u64 fn) {
    uc_err err{UC_ERR_OK};
    auto uc = ldr.uc;
    err = uc_mem_map(uc, retn_addr, PAGE_SIZE, UC_PROT_RWX);
    if (!_uc_okay(err, ok))
        return err;

    err = uc_emu_start(uc, fn, retn_addr, 0, 0);
    if (!_uc_okay(err, ok))
        return err;

    err = uc_mem_unmap(uc, retn_addr, PAGE_SIZE);
    if (!_uc_okay(err, ok))
        return err;

    return UC_ERR_OK;
}

void RtlHeap::setup_regs() {
    auto uc = ldr.uc;
    Uc::reg_wr(uc, X86Reg::rbp, stack_base);
    Uc::reg_wr(uc, X86Reg::rcx, HEAP_GROWABLE);
    Uc::reg_wr(uc, X86Reg::rdx, 0);
    Uc::reg_wr(uc, X86Reg::r8, 0);
    Uc::reg_wr(uc, X86Reg::r9, 0);

    __u64 rsp = stack_base - 0x38;
    ldr.mwrite(rsp, retn_addr); // <+~ for 'retn' insn
    ldr.mwrite(rsp + 0x28, 0ULL);
    ldr.mwrite(rsp + 0x30, 0ULL);
    Uc::reg_wr(uc, X86Reg::rsp, rsp);
}
}; // namespace SlitYerPE::LdrUtils
