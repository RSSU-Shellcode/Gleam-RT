#ifndef MOD_THREAD_H
#define MOD_THREAD_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "errno.h"
#include "context.h"

typedef struct {
    int64 NumThreads;
    int64 NumTLSIndex;
    int64 NumSuspend;
} TT_Status;

typedef HANDLE (*ThdNew_t)(void* address, void* parameter, bool track);
typedef void   (*ThdExit_t)(uint32 code);
typedef void   (*ThdSleep_t)(uint32 milliseconds);

typedef bool (*ThdLockThread_t)(DWORD id);
typedef bool (*ThdUnlockThread_t)(DWORD id);
typedef bool (*ThdGetStatus_t)(TT_Status* status);
typedef bool (*ThdKillAllMu_t)();

typedef bool  (*ThdLock_t)();
typedef bool  (*ThdUnlock_t)();
typedef errno (*ThdSuspend_t)();
typedef errno (*ThdResume_t)();
typedef errno (*ThdRecover_t)();
typedef errno (*ThdForceKill_t)();
typedef errno (*ThdKillAll_t)();
typedef errno (*ThdClean_t)();

typedef struct {
    CreateThread_t     CreateThread;
    ExitThread_t       ExitThread;
    SuspendThread_t    SuspendThread;
    ResumeThread_t     ResumeThread;
    GetThreadContext_t GetThreadContext;
    SetThreadContext_t SetThreadContext;
    TerminateThread_t  TerminateThread;
    TlsAlloc_t         TlsAlloc;
    TlsFree_t          TlsFree;

    ThdNew_t   New;
    ThdExit_t  Exit;
    ThdSleep_t Sleep;

    ThdLockThread_t   LockThread;
    ThdUnlockThread_t UnlockThread;
    ThdGetStatus_t    GetStatus;
    ThdKillAllMu_t    KillAllMu;

    ThdLock_t      Lock;
    ThdUnlock_t    Unlock;
    ThdSuspend_t   Suspend;
    ThdResume_t    Resume;
    ThdRecover_t   Recover;
    ThdForceKill_t ForceKill;
    ThdKillAll_t   KillAll;
    ThdClean_t     Clean;

    HANDLE hMutex;
} ThreadTracker_M;

ThreadTracker_M* InitThreadTracker(Context* context);

#endif // MOD_THREAD_H
