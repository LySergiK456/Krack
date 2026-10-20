#include "../../include/syp/sype.hh"
#include <ntdef.h>
#include <unicorn/unicorn.h>
#include <windows.h>

static inline uc_err _uc_init_x86_64_(uc_engine **uc) {
    return uc_open(UC_ARCH_X86, UC_MODE_64, uc);
}

namespace SlitYerPE {
Ldr::Ldr(int argc, char **argv)
    : args{argc, argv}, main_image(img_push(argv[0])) {
    __u64 off{0};
    uc_err err{UC_ERR_OK};
    if (!_uc_okay(_uc_init_x86_64_(&uc), ok))
        goto failed;

    if (!main_image || (!!main_image && main_image->bin.ok == -1) && (ok = -1))
        return;

    main_image->virt = main_image->bin.base();

    DBGS("~[+]~ Initializing (vm) Process Environment");
    err = InitProcEnv();
    if (!_uc_okay(err, ok))
        goto failed;

    DBGS("~[+]~ Mapping main PE32+");
    err = MapImage(main_image);
    if (!_uc_okay(err, ok))
        goto failed;

    DBGS("~[+]~ Mapping Dll's");
    err = MapDLLs(main_image, &off);
    if (!_uc_okay(err, ok))
        goto failed;

    DBGS("~[+]~ Fixing IAT of binaries");
    err = FixIAT(main_image);
    if (!_uc_okay(err, ok))
        goto failed;

    Uc::reg_wr(uc, X86Reg::rsp, stack_base + STACK_SIZE - PAGE_SIZE);
    Uc::reg_wr(uc, X86Reg::rbp, stack_base + STACK_SIZE - PAGE_SIZE);
    DBG_FMT("       $rsp=$rbp=0x%lx\n", Uc::reg(uc, X86Reg::rsp));

    return;
failed:
    do {
        puts(uc_strerror(err));
        ok = -1;
    } while (0);
}

std::shared_ptr<PE64_IMAGE> Ldr::VAtoImage(__u64 va) {
    if (va == -1)
        return nullptr;

    for (auto &image : img)
        if (!!_contain_(image->virt, image->size, va))
            return image;

    return nullptr;
}
};

namespace SlitYerPE {
uc_err Ldr::Run() {
    uc_err err{UC_ERR_OK};

    if (!LdrUtils::RtlHeap(*this)) {
        DBGS(" -[!]- Failed to RtlHeap");
        return uc_err(-1);
    }

    err = InitDLLs(main_image);
    if (!_uc_okay(err, ok))
        return err;

    puts("Starting");
    __u64 entry = main_image->virt +
                  main_image->bin.nt->OptionalHeader.AddressOfEntryPoint;
    err = uc_emu_start(uc, entry, 0, 0, 0);
    if (!_uc_okay(err, ok))
        return err;

    return err;
}
};
