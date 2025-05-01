#ifndef CONTEXT_H
#define CONTEXT_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "errno.h"

typedef errno (*rt_lock_t)();
typedef errno (*rt_unlock_t)();

typedef void* (*mt_malloc_t)(uint size);
typedef void* (*mt_calloc_t)(uint num, uint size);
typedef void* (*mt_realloc_t)(void* ptr, uint size);
typedef void  (*mt_free_t)(void* ptr);
typedef uint  (*mt_msize_t)(void* ptr);
typedef uint  (*mt_mcap_t)(void* ptr);

typedef HANDLE (*NewThread_t)(void* address, void* parameter, bool track);

typedef struct {
    // runtime options
    bool NotEraseInstruction;
    bool TrackCurrentThread;

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

    rt_lock_t   lock;
    rt_unlock_t unlock;

    // for initialize runtime submodules
    LoadLibraryA_t           LoadLibraryA;
    FreeLibrary_t            FreeLibrary;
    VirtualAlloc_t           VirtualAlloc;
    VirtualFree_t            VirtualFree;
    VirtualProtect_t         VirtualProtect;
    FlushInstructionCache_t  FlushInstructionCache;
    SuspendThread_t          SuspendThread;
    ResumeThread_t           ResumeThread;
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

    // for sysmon
    HANDLE hMutex_LT;
    HANDLE hMutex_MT;
    HANDLE hMutex_TT;
    HANDLE hMutex_RT;
    HANDLE hMutex_AS;
    HANDLE hMutex_IMS;

    NewThread_t NewThread;
} Context;

#endif // CONTEXT_H
