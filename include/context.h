#ifndef CONTEXT_H
#define CONTEXT_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "errno.h"

typedef errno (*rt_lock_mods_t)();
typedef errno (*rt_unlock_mods_t)();
typedef void  (*rt_try_lock_mods_t)();
typedef void  (*rt_try_unlock_mods_t)();

typedef void* (*mt_malloc_t)(uint size);
typedef void* (*mt_calloc_t)(uint num, uint size);
typedef void* (*mt_realloc_t)(void* ptr, uint size);
typedef void  (*mt_free_t)(void* ptr);
typedef uint  (*mt_msize_t)(void* ptr);
typedef uint  (*mt_mcap_t)(void* ptr);

typedef HANDLE (*TT_NewThread_t)(void* address, void* parameter, bool track);
typedef errno  (*TT_RecoverThreads_t)();
typedef errno  (*TT_ForceKillThreads_t)();

typedef errno (*RT_Cleanup_t)();
typedef void  (*RT_Stop_t)();

typedef bool (*WD_IsEnabled_t)();

typedef struct {
    // runtime options
    bool DisableSysmon;
    bool DisableWatchdog;
    bool NotEraseInstruction;
    bool TrackCurrentThread;

    // about process environment
    uintptr PEB;
    uintptr IMOML;

    // runtime context data
    uintptr MainMemPage;
    uint32  PageSize;

    // runtime internal methods
    malloc_t  malloc;
    calloc_t  calloc;
    realloc_t realloc;
    free_t    free;
    msize_t   msize;
    mcap_t    mcap;

    // runtime lock submodules
    rt_lock_mods_t       lock_mods;
    rt_unlock_mods_t     unlock_mods;
    rt_try_lock_mods_t   try_lock_mods;
    rt_try_unlock_mods_t try_unlock_mods;

    // for initialize runtime submodules
    LoadLibraryA_t           LoadLibraryA;
    FreeLibrary_t            FreeLibrary;
    VirtualAlloc_t           VirtualAlloc;
    VirtualFree_t            VirtualFree;
    VirtualProtect_t         VirtualProtect;
    FlushInstructionCache_t  FlushInstructionCache;
    SuspendThread_t          SuspendThread;
    ResumeThread_t           ResumeThread;
    ExitThread_t             ExitThread;
    CreateMutexA_t           CreateMutexA;
    ReleaseMutex_t           ReleaseMutex;
    CreateEventA_t           CreateEventA;
    SetEvent_t               SetEvent;
    CreateWaitableTimerA_t   CreateWaitableTimerA;
    SetWaitableTimer_t       SetWaitableTimer;
    WaitForSingleObject_t    WaitForSingleObject;
    WaitForMultipleObjects_t WaitForMultipleObjects;
    DuplicateHandle_t        DuplicateHandle;
    CloseHandle_t            CloseHandle;
    Sleep_t                  Sleep;

    // for initialize high-level modules
    mt_malloc_t  mt_malloc;
    mt_calloc_t  mt_calloc;
    mt_realloc_t mt_realloc;
    mt_free_t    mt_free;
    mt_msize_t   mt_msize;
    mt_mcap_t    mt_mcap;

    // for initialize sysmon and watchdog
    HANDLE hMutex_LT;
    HANDLE hMutex_MT;
    HANDLE hMutex_TT;
    HANDLE hMutex_RT;
    HANDLE hMutex_AS;
    HANDLE hMutex_IMS;

    TT_NewThread_t        TT_NewThread;
    TT_RecoverThreads_t   TT_RecoverThreads;
    TT_ForceKillThreads_t TT_ForceKillThreads;

    RT_Cleanup_t RT_Cleanup;
    RT_Stop_t    RT_Stop;

    WD_IsEnabled_t WD_IsEnabled;
} Context;

#endif // CONTEXT_H
