#include "./include/mem.h"
#include "./include/syp/dbgserver.hh"
#include "./include/syp/sype.hh"
#include "./include/syp/uc.hh"
#include <assert.h>
#include <memory>
#include <string.h>
#include <unicorn/unicorn.h>
#include <windows.h>
// #include "./include/conf.hh"
#include "./x86disass/disass.hpp"
extern "C" {
#include "./include/utils.h"
};

namespace SYPE = SlitYerPE;

int main(int argc, char **argv) {
    // _TEB_ *teb = reinterpret_cast<_TEB_*>(__readgsqword(0x30));
    // _PEB_ *peb = reinterpret_cast<_PEB_*>(__readgsqword(0x60));
    // assert((void*)teb->PebAddress == (void*)peb);

    // _TEB_ orig_teb, virt_teb;
    // memcpy(reinterpret_cast<char*>(&orig_teb), teb, sizeof(_TEB_));
    // _uc_assert(uc_mem_read(r->ldr.uc, r->ldr.teb_addr, (void*)&virt_teb,
    // sizeof(_TEB_)));

    /* setup TEB properly inside ldr/ - */
    // memcpy(teb, &virt_teb, sizeof(_TEB_));
    // fucking shadow memory

    auto razor = SYPE::Razor(argc - 1, &argv[1]);
    // auto razor = std::make_shared<SYPE::Razor>(new SYPE::Razor(argc-1,
    // &argv[1])); printf("++%lx\n", razor.ldr.ok);

    uc_err err = razor.Run();
    puts("+");
    if (!_uc_ok(err)) {
        puts(uc_strerror(err));
        return -1;
    }
    // auto dbgserver = DbgTcp(razor, DEBUG_PORT);
    // dbgserver.Run();
    return 0;
}
