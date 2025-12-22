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
    (void)hModule;
    (void)dwReason;
    (void)lpReserved;
    return true;
}

BOOL Initialize(Runtime_Opts* opts)
{
    if (RuntimeM != NULL)
    {
        return true;
    }
    RuntimeM = InitRuntime(opts);
    if (RuntimeM == NULL)
    {
        return false;
    }
    return true;
}

BOOL Uninitialize()
{
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
}
