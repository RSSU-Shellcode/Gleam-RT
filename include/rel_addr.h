#ifndef REL_ADDR_H
#define REL_ADDR_H

// x64 can obtain the absolute address of a function through
// RIP relative addressing without external tool modification.
// However, on x86, since "mov reg, abs_addr" is always used
// to obtain function addresses, external tools & inline assembly
// techniques are required to implement relative addressing.

#ifdef _WIN64
    #define GetFuncAddr(func)(func)
#elif _WIN32
    void* GetFuncAddr(void* func);
#endif

#endif // REL_ADDR_H
