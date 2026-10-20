#include "../include/pe64/pe64.hh"
#include "../include/conf.hh"
#include <assert.h>
#include <fstream>
#include <functional>
#include <memory>
extern "C" {
#include "../include/utils.h"
};

__s8 PE64::_Load() {
    HANDLE h = CreateFileA(f.name, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!HANDLE_OK(h))
        goto fail;

    f.size = GetFileSize(h, NULL);

    f.hMap = CreateFileMappingA(h, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!HANDLE_OK(f.hMap))
        goto fail;

    CloseHandle(h);
    pMap = MapViewOfFile(f.hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pMap)
        goto fail;

    return 0;

fail:
    do {
        if (HANDLE_OK(h))
            CloseHandle(h);
        if (HANDLE_OK(f.hMap))
            CloseHandle(f.hMap);
        return -1;
    } while (0);
}

PE64::PE64(char *file, char *symtab_dir) {
    if (!!file) {
        f.lpcName = static_cast<char *>(xmalloc(strlen(file) + 1));
        strcpy(f.lpcName, file);
        if ((ok = _Load()) == -1)
            return;
    } else {
        ok = -1;
        return;
    }

    f.shortname = f.lpcName + strlen(f.lpcName);
    while (*(f.shortname - 1) != '/')
        f.shortname--;

    nt = (IMAGE_NT_HEADERS *)(&pMem[dos->e_lfanew]);
    section = (IMAGE_SECTION_HEADER *)(&pMem[dos->e_lfanew + sizeof(*nt)]);

    ParseIAT();
    ParseEAT();
    ParseReloc();
    if (!!symtab_dir) {
        if (LoadSymtabFromDir(symtab_dir) != ErrOK) {
            goto load_syms;
        } else {
            DBG_FMT(" [+] Loaded symbols from %s/%s\n", symtab_dir, f.shortname);
        }
    } else {
    load_syms:
        DBGS(" [+] Initializing symbol table");
        InitSymtab();
        if (!!symtab_dir) {
            DBG_FMT(" [+] Saving symbols to %s/%s\n", symtab_dir, f.shortname);
            perr_t err = SaveSymtab(symtab_dir);
            if (err != ErrOK && (ok = -1))
                puts(strerr(err));
        }
    }
}

void PE64::ParseIAT() {
    imp.DataDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    imp.Desc =
        (IMAGE_IMPORT_DESCRIPTOR *)rva_to_ptr(imp.DataDir->VirtualAddress);
}

void PE64::ParseReloc() {
    rel.DataDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    rel.entries =
        (IMAGE_BASE_RELOCATION *)rva_to_ptr(rel.DataDir->VirtualAddress);
}

void PE64::ParseEAT() {
    exp.DataDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exp.Dir = (IMAGE_EXPORT_DIRECTORY *)rva_to_ptr(exp.DataDir->VirtualAddress);
    exp.Func = (__u32 *)rva_to_ptr(exp.Dir->AddressOfFunctions);
    exp.Name = (__u32 *)rva_to_ptr(exp.Dir->AddressOfNames);
    exp.Ords = (__u16 *)rva_to_ptr(exp.Dir->AddressOfNameOrdinals);
}

#define X_MIN_IS(x_min, x_rva, rva)     \
    ((x_rva) > (rva) && (!(x_min) || (x_rva) < (x_min)))

__u32 PE64::rva_sym_size(__u32 rva) {
    __u32 x_min{};
    PE_EACH_SYMBOL(this, x_sym) {
        if (!!PE64_SYM_IS_SEC(this, x_sym)) {
            __u32 x_rva =
                section[x_sym->SectionNumber - 1].VirtualAddress + x_sym->Value;
            if (X_MIN_IS(x_min, x_rva, rva))
                x_min = x_rva;
        }
    }

    PE_EACH_EXPORT(this, i) {
        __u32 x_rva = exp.Func[exp.Ords[i]];
        if (!rva_is_overflow(x_rva))
            if (X_MIN_IS(x_min, x_rva, rva))
                x_min = x_rva;
    }

    PE_EACH_SEC(this, sec) {
        __u32 x_rva = sec->VirtualAddress;
        if (X_MIN_IS(x_min, x_rva, rva))
            x_min = x_rva;
    }

    return (x_min > rva) ? (x_min-rva) : 0;
}

perr_t PE64::LoadSymtabFromDir(char *dir) {
    if (!DirExists(dir))
        return ErrNoDir;

    char *entry_name =
        static_cast<char *>(xmalloc(strlen(dir) + 1 + strlen(f.shortname) + 4 +1));
    strcpy(entry_name, dir);
    strcat(entry_name, "/");
    strcat(entry_name, f.shortname);
    strcat(entry_name, ".dat");

    std::ifstream i_stream;
    i_stream.open(entry_name, std::ifstream::binary | std::ifstream::in);
    _defer([&i_stream] { i_stream.close(); });

    if (!i_stream.good())
        return ErrNoFile;

    dat_symtab_t dat_header;
    i_stream.read((char *)&dat_header, sizeof(dat_symtab_t));
    __u64 dat_size = sizeof(PE64_SYMBOL) * dat_header.num_of_syms;

    PE64_SYMBOL *s_arr = reinterpret_cast<PE64_SYMBOL *>(xmalloc(dat_size));
    _defer([&s_arr] { free(s_arr); });
    i_stream.read((char *)s_arr, dat_size);

    for (__u32 i = 0; i < dat_header.num_of_syms; i++) {
        if (!off_is_overflow(s_arr[i].name_off))
            s_arr[i].name = reinterpret_cast<char *>(&pMem[s_arr[i].name_off]);

        symbols.push(s_arr[i]);
    }

    return ErrOK;
}

perr_t PE64::SaveSymtab(char *dir) {
    if (!DirExists(dir))
        return ErrNoDir;

    char *entry_name =
        static_cast<char *>(xmalloc(strlen(dir) + 1 + strlen(f.shortname) + 4 +1));
    _defer([&] { free(entry_name); });
    strcpy(entry_name, dir);
    strcat(entry_name, "/");
    strcat(entry_name, f.shortname);
    strcat(entry_name, ".dat");

    std::ofstream o_stream;
    o_stream.open(entry_name, std::ofstream::binary | std::ofstream::out);
    _defer([&o_stream] { o_stream.close(); });

    if (!o_stream.good())
        return ErrCreateFile;

    dat_symtab_t dat_header = {.num_of_syms =
                                   static_cast<__u32>(symbols.size()),
                               .header_size = sizeof(dat_symtab_t)};

    o_stream.write(reinterpret_cast<char *>(&dat_header), sizeof(dat_symtab_t));
    for (auto &s : symbols) {
        PE64_SYMBOL sym(s);
        sym.name = nullptr;
        o_stream.write((char *)&sym, sizeof(PE64_SYMBOL));
    }

    return ErrOK;
}

PE64_SYMBOL *PE64::rva_to_sym(__u32 rva) {
    for (auto &s : symbols) {
        if (!!_contain_(s.rva, s.size, rva))
            return &s;
    }
    return nullptr;
}

PE64_SYMBOL *PE64::name_to_sym(char *name) {
    if (!name)
        return nullptr;

    for (auto &s : symbols) {
        if (s.name && !strncmp(s.name, name, strlen(name) + 1))
            return &s;
    }
    return nullptr;
}

void PE64::InitSymtab() {
    __u32 str_off = nt->FileHeader.PointerToSymbolTable +
                    nt->FileHeader.NumberOfSymbols * sizeof(IMAGE_SYMBOL);
    char *strtab = reinterpret_cast<char *>(&pMem[str_off]);

    PE_EACH_SYMBOL(this, sym) {
        PE64_SYMBOL new_sym{.t = PE64_SYM_T};
        new_sym.img_sym = sym;
        new_sym.name = (!!sym->N.Name.Short) ? (char *)sym->N.ShortName
                                             : &strtab[sym->N.Name.Long];
        new_sym.name_off =
            static_cast<__u32>((__u64)new_sym.name - (__u64)pMem);

        if (sym->SectionNumber > 0 &&
            sym->SectionNumber <= nt->FileHeader.NumberOfSections) {
            auto sym_sec = &section[sym->SectionNumber - 1];
            new_sym.rva = sym_sec->VirtualAddress + sym->Value;
            new_sym.off = rva_to_off(new_sym.rva);
            new_sym.size = rva_sym_size(new_sym.rva);
        }
        symbols.push(new_sym);
    }

    PE_EACH_EXPORT(this, i) {
        PE64_SYMBOL new_sym{.t = PE64_SYM_EXPORT_T};
        new_sym.name = (char *)rva_to_ptr(exp.Name[i]);
        new_sym.name_off = rva_to_off(exp.Name[i]);
        new_sym.exp_ndx = i;

        if (!rva_is_overflow(exp.Func[exp.Ords[i]])) {
            new_sym.rva = exp.Func[exp.Ords[i]];
            new_sym.off = rva_to_off(new_sym.rva);
            new_sym.size = rva_sym_size(new_sym.rva);
        }
        symbols.push(new_sym);
    }
}

bool PE64::rva_is_overflow(__u32 rva) {
    return (rva == -1 || !rva || rva >= nt->OptionalHeader.SizeOfImage);
}

bool PE64::off_is_overflow(__u32 off) {
    return off >= f.size;
}

__u64 PE64::base() { return nt->OptionalHeader.ImageBase; }

/* RawVirtAddress */
void *PE64::rva_to_ptr(__u32 rva) {
    if (rva < nt->OptionalHeader.SizeOfHeaders)
        return reinterpret_cast<void *>(&pMem[rva]);

    PE_EACH_SEC(this, sec) {
        if (!!_contain_(sec->VirtualAddress, sec->SizeOfRawData, rva))
            return reinterpret_cast<void *>(
                &pMem[sec->PointerToRawData + (rva - sec->VirtualAddress)]);
    }
    return NULL;
}

__s64 PE64::rva_to_off(__u32 rva) {
    if (rva < nt->OptionalHeader.SizeOfHeaders)
        return rva;

    PE_EACH_SEC(this, sec) {
        if (!!_contain_(sec->VirtualAddress, sec->SizeOfRawData,
                        rva)) // PAGE_ALIGN_UP
            return sec->PointerToRawData + (rva - sec->VirtualAddress);
    }
    return -1;
}

void *PE64_IMAGE::rva_to_ptr(__u32 rva) {
    if (rva < bin.nt->OptionalHeader.SizeOfHeaders)
        return reinterpret_cast<void *>(virt + rva);

    PE_EACH_SEC(&bin, sec) {
        if (_contain_(sec->VirtualAddress, sec->SizeOfRawData, rva))
            return reinterpret_cast<void *>(virt + (rva - sec->VirtualAddress));
    }
    return NULL;
}

__s64 PE64::off_to_rva(__u64 off) {
    if (off < nt->OptionalHeader.SizeOfHeaders)
        return off;

    PE_EACH_SEC(this, sec) {
        if (!!_contain_(sec->PointerToRawData, sec->SizeOfRawData, off))
            return sec->VirtualAddress + (off - sec->PointerToRawData);
    }
    return -1;
}

/* VirtAddress */
void *PE64::va_to_ptr(__u64 va) {
    return rva_to_ptr(va - nt->OptionalHeader.ImageBase);
}

__s64 PE64::va_to_off(__u64 va) {
    return rva_to_off(va - nt->OptionalHeader.ImageBase);
}

__s64 PE64_IMAGE::va_to_off(__u64 va) { return bin.rva_to_off(va - virt); }
void *PE64_IMAGE::va_to_ptr(__u64 va) { return rva_to_ptr(va - virt); }