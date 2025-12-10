#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "pe_image.h"
#include "errno.h"
#include "runtime.h"

bool initialized = false;

#pragma comment(linker, "/ENTRY:DllMain")
BOOL DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        return true;
    case DLL_PROCESS_DETACH:
        if (!initialized)
        {
            return true;
        }
        return RT_Exit() == NO_ERROR;
    case DLL_THREAD_ATTACH:
        return true;
    case DLL_THREAD_DETACH:
        return true;
    default:
        return false;
    }
    (void)hModule;
    (void)lpReserved;
}

BOOL Init(Runtime_Opts* opts)
{
    if (InitRuntime(opts) == NULL)
    {
        return false;
    }
    initialized = true;
    return true;
}
