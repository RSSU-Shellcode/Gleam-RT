#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "errno.h"
#include "context.h"
#include "sysmon.h"
#include "debug.h"

typedef struct {
    // store options
    bool NotEraseInstruction;

    CreateWaitableTimerA_t CreateWaitableTimerA;
    SetWaitableTimer_t     SetWaitableTimer;
    ReleaseMutex_t         ReleaseMutex;
    WaitForSingleObject_t  WaitForSingleObject;
    CloseHandle_t          CloseHandle;

    SM_Status status;

    // protect data
    HANDLE hMutex;
} Sysmon;

// methods for user
bool SM_GetStatus();

// methods for runtime
errno SM_Pause();
errno SM_Continue();
errno SM_Stop();

// hard encoded address in getModulePointer for replacement
#ifdef _WIN64
    #define MODULE_POINTER 0x7FABCDEF111111F1
#elif _WIN32
    #define MODULE_POINTER 0x7FABCDF1
#endif
static Sysmon* getModulePointer();

Sysmon_M* InitSysmon(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr moduleAddr = address + 24000 + RandUintN(address, 128);
    uintptr methodAddr = address + 25000 + RandUintN(address, 128);
    // initialize module
    Sysmon* module = (Sysmon*)moduleAddr;
    mem_init(module, sizeof(Sysmon));
    // store options
    module->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
}
