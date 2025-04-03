#include "c_types.h"
#include "rel_addr.h"

#ifndef _WIN64

#pragma optimize("", off)

__declspec(naked)
static uintptr GetEIP()
{
    _asm {
        call get_eip
    get_eip:
        pop eax    ; get eip and return address
        sub eax, 5 ; reduce the size of "call"
        ret
    }
}

void* GetFuncAddr(void* func)
{
    uintptr offset = (uintptr)(func) - (uintptr)(&GetEIP);
    return (void*)(GetEIP() + offset);
}

#pragma optimize("", on)

#endif // _WIN64
