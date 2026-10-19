#include "../../include/syp/sype.hh"
#include <assert.h>
#include <windows.h>
extern "C" {
#include "../../include/utils.h"
};

namespace SlitYerPE {
Razor::Razor(int argc, char **argv) : ldr(argc, argv), dex{new Dex(this)} {
    uc_hook_add(ldr.uc, &insn_hook_trace, UC_HOOK_CODE, (void *)&Dex::hook_code,
                dex, 1, 0);

    _PEB_ *peb = reinterpret_cast<_PEB_ *>(__readgsqword(0x60));
    _PEB_LDR_DATA_ *peb_ldr = reinterpret_cast<_PEB_LDR_DATA_ *>(peb->Ldr);
    for (_LIST_ENTRY_ *l = peb_ldr->InMemoryOrderModuleList.Flink;
         l != &peb_ldr->InMemoryOrderModuleList; l = l->Flink) {
        _LDR_DATA_TABLE_ENTRY_ *entry =
            CONTAINING_RECORD(l, _LDR_DATA_TABLE_ENTRY_, InMemoryOrderLinks);

        ldr.addLdrEntry((__u64)entry->DllBase,
                        (wchar_t *)entry->BaseDllName.Buffer,
                        (wchar_t *)entry->FullDllName.Buffer);
    }
    puts("--------------------------------");
    // test();
}

void Razor::load_dlls(std::shared_ptr<PE64_IMAGE> pe_img) {
    auto pe = &pe_img->bin;

    PE_EACH_IMPORT(pe, impDesc) {
        char name[0x100];
        char *dll_name =
            reinterpret_cast<char *>(pe->rva_to_ptr(impDesc->Name));
        assert(!wine_name(name, sizeof(name), dll_name));

        if (!strncmp(dll_name, "api-ms-win-", 11) ||
            !strncmp(dll_name, "ext-ms-win-", 11))
            continue;

        std::shared_ptr<PE64_IMAGE> dll_img{};
        PE64 *dll_pe{};

        /** Find DLLs **/
        for (auto &dll : ntoskrnl_dll)
            if (!strncmp(name, dll->bin.f.name, strlen(name) + 1)) {
                dll_img = dll;
                dll_pe = &dll->bin;
                break;
            }

        if (!dll_pe) {
            printf("[+] ntoskrnl - initializing %-20s\n", dll_name);
            ntoskrnl_dll.emplace_back(new PE64_IMAGE(name, PE_SYMTAB_DIR));
            dll_img = ntoskrnl_dll.back();
            dll_pe = &dll_img->bin;
            assert(dll_pe->ok != -1);
        }

        PE_EACH_IMPORT(dll_pe, dllImpDesc) { load_dlls(dll_img); }
    }
}

void Razor::test() {
    PE64 *pe = &ntoskrnl->bin;
    assert(!pe->ok);
    // pe32_fix_imports(ntoskrnl);

    PE_EACH_EXPORT(pe, i_exp)
    if (!pe->rva_is_overflow(pe->exp.Name[i_exp])) {
        char *exp_name =
            reinterpret_cast<char *>(pe->rva_to_ptr(pe->exp.Name[i_exp]));
        __u32 exp_rva = pe->exp.Func[pe->exp.Ords[i_exp]];
        void *exp_ptr = pe->rva_to_ptr(exp_rva);

        if (!!exp_name && !!exp_ptr) {
            PE64_SYMBOL *exp_sym = pe->rva_to_sym(exp_rva);

            if (!!exp_sym && !!exp_sym->name) {
                puts(exp_sym->name);
                d.iter(pe->rva_to_ptr(exp_rva), 1, [&](__u64 i, insn_t &insn) {
                    /** Relocations and Imports! **/
                    __u32 dst_rva =
                        static_cast<__u32>(insn.PtrAddr(exp_rva + i));
                    insn.Print();

                    if (dst_rva != -1) {
                        void *dst_ptr = pe->rva_to_ptr(dst_rva);
                        if (!!dst_ptr)
                            PE_EACH_IMPORT(pe, impDesc) {
                                /* EACH , add to PE64 */
                                __u32 ilt_rva =
                                    (!!impDesc->OriginalFirstThunk)
                                        ? impDesc->OriginalFirstThunk
                                        : impDesc->FirstThunk;
                                IMAGE_THUNK_DATA64 *ilt =
                                    reinterpret_cast<IMAGE_THUNK_DATA64 *>(
                                        pe->rva_to_ptr(ilt_rva));
                                IMAGE_THUNK_DATA64 *iat =
                                    reinterpret_cast<IMAGE_THUNK_DATA64 *>(
                                        pe->rva_to_ptr(impDesc->FirstThunk));

                                for (__u32 i = 0; !!ilt[i].u1.AddressOfData;
                                     i++) {
                                    if (&iat[i].u1.Function == dst_ptr) {
                                        void *dst_addr = (*(void **)dst_ptr);

                                        // PE64_SYMBOL *imp_sym =
                                        // pe->rva_to_sym(dst_rva);
                                        if (!!dst_addr) {
                                            for (auto &dll : ntoskrnl_dll)
                                                if (!!_contain_(dll->bin.pMap,
                                                                dll->bin.f.size,
                                                                dst_addr))
                                                    printf(
                                                        "FROM %s\n",
                                                        dll->bin.f.shortname);
                                            // puts((!!imp_sym->name) ?
                                            // imp_sym->name :
                                            // const_cast<char*>("?"));
                                            d.iter(
                                                dst_addr, 0x10,
                                                [&](__u64 i, insn_t &i_insn) {
                                                    // if (i_insn.IsNull())
                                                    // return;
                                                    printf("\t");
                                                    i_insn.Print();
                                                });
                                        }
                                    }
                                }
                            }
                    }
                });
                puts("------------------------");
            }
        }
    }
}
uc_err Razor::Run() { return ldr.Run(); }
}; // namespace SlitYerPE

namespace SlitYerPE {
void Razor::pe32_fix_imports(std::shared_ptr<PE64_IMAGE> pe_img) {
    auto pe = &pe_img->bin;

    PE_EACH_IMPORT(pe, impDesc) {
        char name[0x100];
        char *dll_name =
            reinterpret_cast<char *>(pe->rva_to_ptr(impDesc->Name));
        assert(!wine_name(name, sizeof(name), dll_name));

        std::shared_ptr<PE64_IMAGE> dll_img = FindNtosktnlDLL(name);
        assert(!!dll_img);
        PE64 *dll_pe = &dll_img->bin;
        __u64 dll_base = reinterpret_cast<__u64>(dll_pe->pMap);

        puts(dll_pe->f.shortname);
        pe32_fix_imports(dll_img);

        __u32 ilt_rva = (!!impDesc->OriginalFirstThunk)
                            ? impDesc->OriginalFirstThunk
                            : impDesc->FirstThunk;
        IMAGE_THUNK_DATA64 *ilt =
            reinterpret_cast<IMAGE_THUNK_DATA64 *>(pe->rva_to_ptr(ilt_rva));
        IMAGE_THUNK_DATA64 *iat = reinterpret_cast<IMAGE_THUNK_DATA64 *>(
            pe->rva_to_ptr(impDesc->FirstThunk));

        for (__u32 i = 0; !!ilt[i].u1.AddressOfData; i++) {
            __u32 fn_rva{};

            if (ilt[i].u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                __u32 ord = ilt[i].u1.Ordinal & 0xffff;
                fn_rva = dll_pe->exp.Func[ord - dll_pe->exp.Dir->Base];
            } else {
                IMAGE_IMPORT_BY_NAME *ibn =
                    reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(
                        pe->rva_to_ptr(ilt[i].u1.AddressOfData));
                char *imp_name = ibn->Name;
                PE_EACH_EXPORT(dll_pe, i) {
                    if (!strcmp(imp_name, (char *)dll_pe->rva_to_ptr(
                                              dll_pe->exp.Name[i]))) {
                        fn_rva = dll_pe->exp.Func[dll_pe->exp.Ords[i]];
                        break;
                    }
                }
            }

            if (!!fn_rva)
                iat[i].u1.Function = dll_base + fn_rva;
        }
    }
}

/* Dll image list type */
std::shared_ptr<PE64_IMAGE> Razor::FindNtosktnlDLL(char *name) {
    for (auto &image : ntoskrnl_dll)
        if (!strncmp(name, image->bin.f.name, strlen(name) + 1))
            return image;

    return nullptr;
}
}; // namespace SlitYerPE