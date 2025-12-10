#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "pe_image.h"
#include "errno.h"
#include "runtime.h"

Runtime_M* RuntimeM = NULL;

#pragma comment(linker, "/ENTRY:DllMain")
BOOL DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        return true;
    case DLL_PROCESS_DETACH:
        if (RuntimeM == NULL)
        {
            return true;
        }
        errno err = RuntimeM->Core.Exit();
        if (err != NO_ERROR)
        {
            SetLastErrno(err);
            return false;
        }
        return true;
    case DLL_THREAD_ATTACH:
        return true;
    case DLL_THREAD_DETACH:
        return true;
    }
    (void)hModule;
    (void)lpReserved;
    return false;
}

BOOL Init(Runtime_Opts* opts)
{
    RuntimeM = InitRuntime(opts);
    if (RuntimeM == NULL)
    {
        return false;
    }
    return true;
}
