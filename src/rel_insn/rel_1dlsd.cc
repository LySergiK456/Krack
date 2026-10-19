#include "../../include/rel/1dlsd.hh"
#include <windows.h>
extern "C" {
#include "../../include/rel/rel_yayo.h"
};

namespace SlitYerPE {
_1Dlsd::_1Dlsd(pe64_image &base_pe, lsd_pass &_p)
    : lyss(this, base_pe), pass{_p} {
    llist_init(&pImg, sizeof(pe64_image *));
    llist_init(&px, sizeof(_1Dlsd_entry));
}
}; // namespace SlitYerPE