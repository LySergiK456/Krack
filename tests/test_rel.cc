#include "../include/rel/1dlsd.hh"
#include "../include/xtc/xtc.hh"
#include "../x86disass/disass.hpp"
extern "C" {
#include "../include/xtc/xtc.h"
};

struct my_pack : SlitYerPE::lsd_pass {
    my_pack() = default;
    LSD_STATUS _init_(SlitYerPE::_1Dlsd *lsd) {
        return LSD_OK;
    }
};

int main() {
    auto xtc = x_t_c();
    x_t_c_dump x;
    assert(!new_x_t_c(&x, XTC_DEFAULT_OUTFILE));
    _defer([&x] { x_t_c_fini(&x); });

    auto d = Disass();

    for (int i = 0; i < 0x10000; i++) {
        __u8 sc[15]{0};
        struct xtc_oper ops[4] = {
            {X86_OP_PTR, _DWORD_},
            {X86_OP_REG, _DWORD_},
        };
        assert(!xtc_make_insn(&x, "MOV", (struct xtc_oper *)&ops, sc));
    }

    // insn_t(sc).Print();
    // hexdump(sc, 0x10);
    // auto pe = std::make_shared<PE64_IMAGE>(new
    // PE64_IMAGE("/home/rax/win10_dll/ntdll.dll"));
    puts("++");
    // char *sc = "\xe8\xd8\x9a\xff\xff";
    auto pass = my_pack();
    pe64_image *pe = new_pe64("/home/rax/uc/specimen/b.exe");
    assert(!!pe);
    puts("@");
    auto lsd = SlitYerPE::_1Dlsd(*pe, pass);
    // for (int i = 0; i < 0xdead00; i++)
    //     ;
    lsd.make("/tmp/hello.exe");
    // if (syp.ins_insn(0xecafeb01, sc, pe) != SYP_OK)
    // puts("FUCK!");
    return 0;
}