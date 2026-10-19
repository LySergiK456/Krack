#include "../../include/syp/sype.hh"
#include "../../include/syp/uc.hh"
#include <stddef.h>
#include <windows.h>

namespace SlitYerPE {
uc_err Ldr::init_stack(__u64 addr, __u64 sz) {
    return mmap(addr - sz, sz, UC_PROT_RW, "[stack]");
}

uc_err Ldr::InitProcEnv() {
    uc_err err{UC_ERR_OK};

    err = init_stack(stack_base, STACK_SIZE);
    if (!_uc_okay(err, ok))
        return err;

    err = init_gs_fs(_gs, _fs);
    if (!_uc_okay(err, ok))
        return err;

    mmap(proc.teb_addr, PAGE_ALIGN_UP(sizeof(_TEB_)), UC_PROT_RW, "[TEB]");
    mmap(proc.peb_addr, PAGE_ALIGN_UP(sizeof(_PEB_)), UC_PROT_RW, "[PEB]");
    mmap(proc.ldr_addr, PAGE_ALIGN_UP(sizeof(_PEB_LDR_DATA_)), UC_PROT_RW);
    mmap(proc.kusd_addr, PAGE_ALIGN_UP(sizeof(_KUSER_SHARED_DATA_)),
         UC_PROT_RW);

    initTEB();
    initPEB();
    initLDR();
    initKUSD();

    mwrite(_gs + 0x30, proc.teb_addr);
    mwrite(_gs + 0x60, proc.peb_addr);
    mwrite(&((_PEB_ *)proc.peb_addr)->Ldr, proc.ldr_addr);

    return UC_ERR_OK;
}

uc_err Ldr::init_gs_fs(__u64 gs, __u64 fs) {
    uc_err err{UC_ERR_OK};
    uc_x86_msr msr_gs{}, msr_fs{};
    msr_gs = {.rid = IA32_GS_BASE, .value = gs};
    msr_fs = {.rid = IA32_FS_BASE, .value = fs};

    if (!_uc_ok(
            err = mmap(gs, static_cast<__u64>(KrackConf::GS_SIZE), UC_PROT_RW)))
        return err;
    if (!_uc_ok(
            err = mmap(fs, static_cast<__u64>(KrackConf::FS_SIZE), UC_PROT_RW)))
        return err;

    if (!_uc_ok(err = uc_reg_write(uc, UC_X86_REG_MSR, (void *)&msr_gs)))
        return err;
    if (!_uc_ok(err = uc_reg_write(uc, UC_X86_REG_MSR, (void *)&msr_fs)))
        return err;

    return err;
}
}; // namespace SlitYerPE

namespace SlitYerPE {
void Ldr::initKUSD() {
    _KUSER_SHARED_DATA_ kusd = *((_KUSER_SHARED_DATA_ *)KUSER_SHARED_DATA_ADDR);
    kusd.ImageNumberLow = IMAGE_FILE_MACHINE_I386;
    kusd.ImageNumberHigh = IMAGE_FILE_MACHINE_AMD64;
    kusd.NtProductType = 1;
    kusd.NtMajorVersion = 10;
    kusd.NtMinorVersion = 0;
    memcpy(&kusd.NtSystemRoot, "C:\\windows", 11);

    mmemcpy(proc.kusd_addr, &kusd, sizeof(_KUSER_SHARED_DATA_));
}
}; // namespace SlitYerPE

namespace SlitYerPE {
void Ldr::initTEB() {
    _TEB_ *real_teb = reinterpret_cast<_TEB_ *>(__readgsqword(0x30));
    _TEB_ *teb = reinterpret_cast<_TEB_ *>(proc.teb_addr);

    mwrite(&teb->TebAddress, proc.teb_addr);
    mwrite(&teb->PebAddress, proc.peb_addr);
    mwrite(&teb->StackBase, stack_base);
    mwrite(&teb->StackLimit, stack_base - STACK_SIZE);
    mcopy(&teb->ProcessID, real_teb->ProcessID);
    mcopy(&teb->ThreadID, real_teb->ThreadID);
}
/* the fucking problem */
// mem_write(teb_addr, teb, sizeof(_TEB_));

using BSSDATA = BASE_STATIC_SERVER_DATA;

void Ldr::initPEB() {
    _PEB_ *peb = reinterpret_cast<_PEB_ *>(proc.peb_addr);

    mwrite(&peb->ImageBaseAddress, static_cast<__u32>(main_image->virt));
    mwrite(&peb->Ldr, proc.ldr_addr);
    mwrite(&peb->ProcessParameters, uc_malloc(0x100));
    // mwrite(&peb->ProcessHeap,		uc_malloc(0x100));/*No*/

    __u64 srv_arr = uc_malloc(sizeof(PVOID) * 2);
    __u64 srv_dat = uc_malloc(sizeof(BASE_STATIC_SERVER_DATA));
    BASE_STATIC_SERVER_DATA *bssd = (BASE_STATIC_SERVER_DATA *)srv_dat;
    mwrite(srv_arr + 0x0, 0);
    mwrite(srv_arr + 0x8, srv_dat);

    mwrite(&bssd->WindowsDirectory, AllocUcStr(L"C:\\windows"));
    mwrite(&bssd->WindowsSystemDirectory, AllocUcStr(L"C:\\windows\\system32"));
    mwrite(&bssd->NamedObjectDirectory, AllocUcStr(L"\\BaseNamedObjects"));

    mwrite(&bssd->WindowsMajorVersion, (__u16)10);
    mwrite(&bssd->WindowsMinorVersion, (__u16)0);
    mwrite(&bssd->BuildNumber, (__u16)WIN10_BUILD_NUMBER);
    mwrite((BYTE *)peb + 0x98, srv_arr);

    mcopy(&peb->CriticalSectionTimeout, -120000000LL);
    mcopy(&peb->HeapSegmentReserve, 0x100000LL);
    mcopy(&peb->HeapSegmentCommit, 0x1000LL);
    mcopy(&peb->HeapDeCommitTotalFreeThreshold, 0x10000LL);
    mcopy(&peb->HeapDeCommitFreeBlockThreshold, 0x1000LL);
    mcopy(&peb->NumberOfProcessors, 8);
}

void Ldr::initLDR() {
    auto ldr = (_PEB_LDR_DATA_ *)proc.ldr_addr;

    mwrite(&ldr->InLoadOrderModuleList.Flink,
           (void *)&ldr->InLoadOrderModuleList);
    mwrite(&ldr->InLoadOrderModuleList.Blink,
           (void *)&ldr->InLoadOrderModuleList);

    mwrite(&ldr->InMemoryOrderModuleList.Flink,
           (void *)&ldr->InMemoryOrderModuleList);
    mwrite(&ldr->InMemoryOrderModuleList.Blink,
           (void *)&ldr->InMemoryOrderModuleList);

    mwrite(&ldr->InInitializationOrderModuleList.Flink,
           (void *)&ldr->InInitializationOrderModuleList);
    mwrite(&ldr->InInitializationOrderModuleList.Blink,
           (void *)&ldr->InInitializationOrderModuleList);
}

using _LIST_LDR_ = _LIST_LDR_DATA_TABLE_ENTRY_;

void Ldr::addLdrEntry(__u64 virt, wchar_t *wbase, wchar_t *wfull) {
    if (!wbase || !wfull)
        return;
    _PEB_LDR_DATA_ *ldr = (_PEB_LDR_DATA_ *)proc.ldr_addr;
    _LIST_LDR_ *e = (_LIST_LDR_ *)uc_malloc(sizeof(_LIST_LDR_));

    // need uppercase KERNEL32.dll
    mwrite(&e->e.DllBase, virt);
    wprintf(L"   ~[+]~ Adding %-18ls to ->[!PEB_LDR_DATA]\n", wbase);

    __u16 b_len = wcslen(wbase) * sizeof(wchar_t);
    __u16 f_len = wcslen(wfull) * sizeof(wchar_t);

    __u64 basename = uc_malloc(b_len + 2);
    __u64 fullname = uc_malloc(f_len + 2);
    mmemcpy(basename, wbase, b_len + 2);
    mmemcpy(fullname, wfull, f_len + 2);

    mwrite(&e->e.BaseDllName.Buffer, basename);
    mwrite(&e->e.FullDllName.Buffer, fullname);
    mcopy(&e->e.BaseDllName.Length, (__u16)(b_len + 2));
    mcopy(&e->e.FullDllName.Length, (__u16)(f_len + 2));

    __u64 head_load_addr = reinterpret_cast<__u64>(&ldr->InLoadOrderModuleList);
    __u64 head_mem_addr =
        reinterpret_cast<__u64>(&ldr->InMemoryOrderModuleList);
    __u64 head_init_addr =
        reinterpret_cast<__u64>(&ldr->InInitializationOrderModuleList);

    _LIST_LDR_ Lhead_load_e{}, Lhead_mem_e{}, Lhead_init_e{};
    _LIST_LDR_ Lflink_load{}, Lflink_mem{}, Lflink_init{};
    // /**
    //  * Traverse the _LIST_ENTRY_
    //  **/
    Uc::read(uc, head_load_addr, (void *)&Lhead_load_e, sizeof(_LIST_LDR_));
    Uc::read(uc, head_mem_addr, (void *)&Lhead_mem_e, sizeof(_LIST_LDR_));
    Uc::read(uc, head_init_addr, (void *)&Lhead_init_e, sizeof(_LIST_LDR_));

    _LIST_ENTRY_ *new_load_link = &e->e.InLoadOrderLinks;
    _LIST_ENTRY_ *new_mem_link = &e->e.InMemoryOrderLinks;
    _LIST_ENTRY_ *new_init_link = &e->e.InInitializationOrderLinks;

    if (head_load_addr ==
        reinterpret_cast<__u64>(
            Lhead_load_e.list.Blink)) { /* Self linked _LIST_ENTRY_ */
        mwrite(&e->e.InLoadOrderLinks.Flink, head_load_addr);
        mwrite(&e->e.InMemoryOrderLinks.Flink, head_mem_addr);
        mwrite(&e->e.InInitializationOrderLinks.Flink, head_init_addr);

        mwrite(head_load_addr, (void *)new_load_link, &Lhead_load_e.list.Flink,
               &Lhead_load_e);
        mwrite(head_mem_addr, (void *)new_mem_link, &Lhead_mem_e.list.Flink,
               &Lhead_mem_e);
        mwrite(head_init_addr, (void *)new_init_link, &Lhead_init_e.list.Flink,
               &Lhead_init_e);
    } else {
        __u64 load_flink = reinterpret_cast<__u64>(Lhead_load_e.list.Blink);
        __u64 mem_flink = reinterpret_cast<__u64>(Lhead_mem_e.list.Blink);
        __u64 init_flink = reinterpret_cast<__u64>(Lhead_init_e.list.Blink);

        Uc::read(uc, load_flink, (void *)&Lflink_load, sizeof(_LIST_LDR_));
        Uc::read(uc, mem_flink, (void *)&Lflink_mem, sizeof(_LIST_LDR_));
        Uc::read(uc, init_flink, (void *)&Lflink_init, sizeof(_LIST_LDR_));

        mwrite(&e->e.InLoadOrderLinks.Flink, head_load_addr);
        mwrite(&e->e.InMemoryOrderLinks.Flink, head_mem_addr);
        mwrite(&e->e.InInitializationOrderLinks.Flink, head_init_addr);

        mwrite(load_flink, (void *)new_load_link, &Lflink_load.list.Flink,
               &Lflink_load);
        mwrite(mem_flink, (void *)new_mem_link, &Lflink_mem.list.Flink,
               &Lflink_mem);
        mwrite(init_flink, (void *)new_init_link, &Lflink_init.list.Flink,
               &Lflink_init);
    }

    mwrite(&e->e.InLoadOrderLinks.Blink, (void *)Lhead_load_e.list.Blink);
    mwrite(head_load_addr, (void *)new_load_link, &Lhead_load_e.list.Blink,
           &Lhead_load_e);

    mwrite(&e->e.InMemoryOrderLinks.Blink, (void *)Lhead_mem_e.list.Blink);
    mwrite(head_mem_addr, (void *)new_mem_link, &Lhead_mem_e.list.Blink,
           &Lhead_mem_e);

    mwrite(&e->e.InInitializationOrderLinks.Blink,
           (void *)Lhead_init_e.list.Blink);
    mwrite(head_init_addr, (void *)new_init_link, &Lhead_init_e.list.Blink,
           &Lhead_init_e);
}

void Ldr::addLdrEntry(__u64 virt, char *base, char *full) {
    __u64 b_len = strlen(base);
    __u64 f_len = strlen(full);

    wchar_t wbase[0x100]{}, wfull[0x100]{};
    for (__u64 i = 0; i < b_len + 1; i++)
        wbase[i] = static_cast<__u16>(base[i]);

    for (__u64 i = 0; i < f_len + 1; i++)
        wfull[i] = static_cast<__u16>(full[i]);

    addLdrEntry(virt, wbase, wfull);
}
void Ldr::addLdrEntry(std::shared_ptr<PE64_IMAGE> dll_img) {
    addLdrEntry(dll_img->virt, dll_img->bin.f.shortname, dll_img->bin.f.name);
}
}; // namespace SlitYerPE
