#ifndef MOD_THREAD_H
#define MOD_THREAD_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "context.h"
#include "errno.h"

typedef HANDLE (*ThdNew_t)(void* address, void* parameter, bool track);
typedef void   (*ThdExit_t)();

typedef bool  (*ThdLock_t)();
typedef bool  (*ThdUnlock_t)();
typedef errno (*ThdSuspend_t)();
typedef errno (*ThdResume_t)();
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

    ThdNew_t  New;
    ThdExit_t Exit;

    ThdLock_t    Lock;
    ThdUnlock_t  Unlock;
    ThdSuspend_t Suspend;
    ThdResume_t  Resume;
    ThdKillAll_t KillAll;
    ThdClean_t   Clean;
} ThreadTracker_M;

ThreadTracker_M* InitThreadTracker(Context* context);

#endif // MOD_THREAD_H
