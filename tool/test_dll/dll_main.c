#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "runtime.h"

#pragma comment(linker, "/ENTRY:DllMain")
BOOL DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    (void)hModule;
    (void)dwReason;
    (void)lpReserved;
    return true;
}

BOOL Init(Runtime_Opts* opts)
{
    if (InitRuntime(opts) == NULL)
    {
        return false;
    }
    return true;
}
