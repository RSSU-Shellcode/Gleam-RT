#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "sysmon.h"
#include "debug.h"

#define RESULT_FAILED     0
#define RESULT_SUCCESS    1
#define RESULT_STOP_EVENT 2

typedef struct {
    // store options
    bool DisableSysmon;
    bool NotEraseInstruction;

    SuspendThread_t          SuspendThread;
    ResumeThread_t           ResumeThread;
    GetThreadContext_t       GetThreadContext;
    CreateWaitableTimerA_t   CreateWaitableTimerA;
    SetWaitableTimer_t       SetWaitableTimer;
    SetEvent_t               SetEvent;
    ReleaseMutex_t           ReleaseMutex;
    WaitForSingleObject_t    WaitForSingleObject;
    WaitForMultipleObjects_t WaitForMultipleObjects;
    CloseHandle_t            CloseHandle;

    // copy from runtime methods
    rt_try_lock_mods_t   RT_TryLockMods;
    rt_try_unlock_mods_t RT_TryUnlockMods;

    // copy from runtime submodules
    TT_RecoverThreads_t   TT_RecoverThreads;
    TT_ForceKillThreads_t TT_ForceKillThreads;
    WD_IsEnabled_t        WD_IsEnabled;
    RT_Cleanup_t          RT_Cleanup;
    RT_Stop_t             RT_Stop;

    HANDLE ModMutex[8];

    // global mutex
    HANDLE hMutex;

    // about watcher
    HANDLE hEvent;
    HANDLE hThread;

    // sysmon status
    SM_Status status;
    HANDLE    statusMu;
} Sysmon;

// methods for user
BOOL SM_GetStatus(SM_Status* status);

// methods for runtime
bool  SM_Lock();
bool  SM_Unlock();
errno SM_Pause();
errno SM_Continue();
errno SM_Stop();

// hard encoded address in getSysmonPointer for replacement
#ifdef _WIN64
    #define SYSMON_POINTER 0x7FABCDEF111111F1
#elif _WIN32
    #define SYSMON_POINTER 0x7FABCDF1
#endif
static Sysmon* getSysmonPointer();

static bool initSysmonAPI(Sysmon* sysmon, Context* context);
static bool updateSysmonPointer(Sysmon* sysmon);
static bool recoverSysmonPointer(Sysmon* sysmon);
static bool initSysmonEnvironment(Sysmon* sysmon, Context* context);
static void eraseSysmonMethods(Context* context);
static void cleanSysmon(Sysmon* sysmon);

static uint sm_watcher();
static uint sm_watch();
static uint sm_sleep(uint32 seconds);

static bool sm_lock_status();
static bool sm_unlock_status();
static void sm_add_normal();
static void sm_add_recover();
static void sm_add_panic();

Sysmon_M* InitSysmon(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr sysmonAddr = addr + LAYOUT_SM_STRUCT + RandUintN(addr, 128);
    uintptr methodAddr = addr + LAYOUT_SM_METHOD + RandUintN(addr, 128);
    // allocate sysmon memory
    Sysmon* sysmon = (Sysmon*)sysmonAddr;
    mem_init(sysmon, sizeof(Sysmon));
    // store options
    sysmon->DisableSysmon       = context->DisableSysmon;
    sysmon->NotEraseInstruction = context->NotEraseInstruction;
    // initialize sysmon
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initSysmonAPI(sysmon, context))
        {
            errno = ERR_SYSMON_INIT_API;
            break;
        }
        if (!updateSysmonPointer(sysmon))
        {
            errno = ERR_SYSMON_UPDATE_PTR;
            break;
        }
        if (!initSysmonEnvironment(sysmon, context))
        {
            errno = ERR_SYSMON_INIT_ENV;
            break;
        }
        break;
    }
    eraseSysmonMethods(context);
    if (errno != NO_ERROR)
    {
        cleanSysmon(sysmon);
        SetLastErrno(errno);
        return NULL;
    }
    // create thread for watcher
    if (!context->DisableSysmon)
    {
        void*  address = GetFuncAddr(&sm_watcher);
        HANDLE hThread = context->TT_NewThread(address, NULL, false);
        if (hThread == NULL)
        {
            SetLastErrno(ERR_SYSMON_START_WATCHER);
            return NULL;
        }
        sysmon->hThread = hThread;
        // update sysmon status
        sysmon->status.IsEnabled = true;
    }
    // create methods for sysmon
    Sysmon_M* method = (Sysmon_M*)methodAddr;
    // methods for user
    method->GetStatus = GetFuncAddr(&SM_GetStatus);
    // methods for runtime
    method->Lock     = GetFuncAddr(&SM_Lock);
    method->Unlock   = GetFuncAddr(&SM_Unlock);
    method->Pause    = GetFuncAddr(&SM_Pause);
    method->Continue = GetFuncAddr(&SM_Continue);
    method->Stop     = GetFuncAddr(&SM_Stop);
    return method;
}

__declspec(noinline)
static bool initSysmonAPI(Sysmon* sysmon, Context* context)
{
    sysmon->SuspendThread          = context->SuspendThread;
    sysmon->ResumeThread           = context->ResumeThread;
    sysmon->GetThreadContext       = context->GetThreadContext;
    sysmon->CreateWaitableTimerA   = context->CreateWaitableTimerA;
    sysmon->SetWaitableTimer       = context->SetWaitableTimer;
    sysmon->SetEvent               = context->SetEvent;
    sysmon->ReleaseMutex           = context->ReleaseMutex;
    sysmon->WaitForSingleObject    = context->WaitForSingleObject;
    sysmon->WaitForMultipleObjects = context->WaitForMultipleObjects;
    sysmon->CloseHandle            = context->CloseHandle;
    return true;
}

// CANNOT merge updateSysmonPointer and recoverSysmonPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateSysmonPointer(Sysmon* sysmon)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getSysmonPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != SYSMON_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)sysmon;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool recoverSysmonPointer(Sysmon* sysmon)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getSysmonPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)sysmon)
        {
            target++;
            continue;
        }
        *pointer = SYSMON_POINTER;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool initSysmonEnvironment(Sysmon* sysmon, Context* context)
{
    // create global mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_SM_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return false;
    }
    sysmon->hMutex = hMutex;
    // create status mutex
    HANDLE statusMu = context->CreateMutexA(NULL, false, NAME_RT_SM_MUTEX_STATUS);
    if (statusMu == NULL)
    {
        return false;
    }
    sysmon->statusMu = statusMu;
    // create event for stop watcher
    HANDLE hEvent = context->CreateEventA(NULL, true, false, NAME_RT_SM_EVENT_STOP);
    if (hMutex == NULL)
    {
        return false;
    }
    sysmon->hEvent = hEvent;
    // copy runtime methods
    sysmon->RT_TryLockMods   = context->try_lock_mods;
    sysmon->RT_TryUnlockMods = context->try_unlock_mods;
    // copy methods from context
    sysmon->TT_RecoverThreads   = context->TT_RecoverThreads;
    sysmon->TT_ForceKillThreads = context->TT_ForceKillThreads;
    sysmon->WD_IsEnabled        = context->WD_IsEnabled;
    sysmon->RT_Cleanup          = context->RT_Cleanup;
    sysmon->RT_Stop             = context->RT_Stop;
    // copy mutex from context
    mem_copy(sysmon->ModMutex, context->ModMutex, sizeof(context->ModMutex));
    return true;
}

__declspec(noinline)
static void eraseSysmonMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initSysmonAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseSysmonMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

__declspec(noinline)
static void cleanSysmon(Sysmon* sysmon)
{
    if (sysmon->CloseHandle == NULL)
    {
        return;
    }
    if (sysmon->hMutex != NULL)
    {
        sysmon->CloseHandle(sysmon->hMutex);
    }
    if (sysmon->statusMu != NULL)
    {
        sysmon->CloseHandle(sysmon->statusMu);
    }
    if (sysmon->hEvent != NULL)
    {
        sysmon->CloseHandle(sysmon->hEvent);
    }
}

// updateSysmonPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateSysmonPointer will fail.
#pragma optimize("", off)
static Sysmon* getSysmonPointer()
{
    uintptr pointer = SYSMON_POINTER;
    return (Sysmon*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static uint sm_watcher()
{
    Sysmon* sysmon = getSysmonPointer();

    int numFail = 0;
    for (;;)
    {
        switch (sm_watch())
        {
        case RESULT_SUCCESS:
            numFail = 0;
            break;
        case RESULT_STOP_EVENT:
            return 0;
        case RESULT_FAILED:
            numFail++;
            break;
        default:
            panic(PANIC_UNREACHABLE_CODE);
        }

        switch (numFail)
        {
        case 0:
            sm_add_normal();
            break;
        case 1:
            // if timeout, try to recover threads first.
            // In Go programs, threads are occasionally 
            // suspended incorrectly, causing deadlocks.
            errno err = sysmon->TT_RecoverThreads();
            if (err != NO_ERROR)
            {
                dbg_log("[sysmon]", "occurred error when recover threads: 0x%X", err);
            }
            sm_add_recover();
            break;
        case 2:
            // if watchdog is disabled, exit runtime.
            if (!sysmon->WD_IsEnabled())
            {
                sysmon->RT_Stop(true, ERR_STOP_CODE_WATCHDOG_DISABLED);
                break;
            }
            // if failed to recover, use force kill threads,
            // then the Watchdog will restart program.
            sysmon->RT_TryLockMods();
            err = sysmon->TT_ForceKillThreads();
            if (err != NO_ERROR)
            {
                dbg_log("[sysmon]", "occurred error when kill threads: 0x%X", err);
            }
            sysmon->RT_TryUnlockMods();
            // cleanup runtime tracked resource
            err = sysmon->RT_Cleanup();
            if (err != NO_ERROR)
            {
                dbg_log("[sysmon]", "occurred error when cleanup: 0x%X", err);
            }
            sm_add_panic();
            break;
        default:
            // if failed to reset program or watchdog 
            // is disabled, exit runtime.
            sysmon->RT_Stop(true, ERR_STOP_CODE_RESET_PROGRAM);
            break;
        }

        switch (sm_sleep(3 + RandIntN(0, 3)))
        {
        case RESULT_SUCCESS:
            break;
        case RESULT_STOP_EVENT:
            return 0;
        case RESULT_FAILED:
            dbg_log("[sysmon]", "occurred error when sleep: 0x%X", GetLastErrno());
            return 1;
        default:
            panic(PANIC_UNREACHABLE_CODE);
        }
    }
}

__declspec(noinline)
static uint sm_watch()
{
    Sysmon* sysmon = getSysmonPointer();

    uint result = RESULT_SUCCESS;
    for (int i = 0; i < arrlen(sysmon->ModMutex); i++)
    {
        bool stopped = false;

        HANDLE objects[] = { sysmon->ModMutex[i], sysmon->hEvent };
        switch (sysmon->WaitForMultipleObjects(2, objects, false, 10000))
        {
        case WAIT_OBJECT_0+0: case WAIT_ABANDONED+0:
            if (!sysmon->ReleaseMutex(sysmon->ModMutex[i]))
            {
                result = RESULT_FAILED;
            }
            break;
        case WAIT_OBJECT_0+1:
            stopped = true;
            break;
        default:
            result = RESULT_FAILED;
            break;
        }

        if (stopped)
        {
            return RESULT_STOP_EVENT;
        }
    }
    return result;
}

__declspec(noinline)
static uint sm_sleep(uint32 seconds)
{
    Sysmon* sysmon = getSysmonPointer();

    uint result = RESULT_FAILED;
    HANDLE hTimer = sysmon->CreateWaitableTimerA(NULL, false, NAME_RT_SM_TIMER_SLEEP);
    if (hTimer == NULL)
    {
        return result;
    }
    for (;;)
    {
        int64 dueTime = -((int64)seconds * 1000 * 1000 * 10);
        if (!sysmon->SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, true))
        {
            break;
        }
        HANDLE objects[] = { hTimer, sysmon->hEvent };
        switch (sysmon->WaitForMultipleObjects(2, objects, false, INFINITE))
        {
        case WAIT_OBJECT_0+0:
            result = RESULT_SUCCESS;
            break;
        case WAIT_OBJECT_0+1:
            result = RESULT_STOP_EVENT;
            break;
        default:
            break;
        }
        break;
    }
    sysmon->CloseHandle(hTimer);
    return result;
}

__declspec(noinline)
bool sm_lock_status()
{
    Sysmon* sysmon = getSysmonPointer();

    DWORD event = sysmon->WaitForSingleObject(sysmon->statusMu, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool sm_unlock_status()
{
    Sysmon* sysmon = getSysmonPointer();

    return sysmon->ReleaseMutex(sysmon->statusMu);
}

__declspec(noinline)
static void sm_add_normal()
{
    Sysmon* sysmon = getSysmonPointer();

    if (!sm_lock_status())
    {
        return;
    }

    sysmon->status.NumNormal++;

    if (!sm_unlock_status())
    {
        return;
    }
}

__declspec(noinline)
static void sm_add_recover()
{
    Sysmon* sysmon = getSysmonPointer();

    if (!sm_lock_status())
    {
        return;
    }

    sysmon->status.NumRecover++;

    if (!sm_unlock_status())
    {
        return;
    }
}

__declspec(noinline)
static void sm_add_panic()
{
    Sysmon* sysmon = getSysmonPointer();

    if (!sm_lock_status())
    {
        return;
    }

    sysmon->status.NumPanic++;

    if (!sm_unlock_status())
    {
        return;
    }
}

__declspec(noinline)
BOOL SM_GetStatus(SM_Status* status)
{
    Sysmon* sysmon = getSysmonPointer();

    if (!SM_Lock())
    {
        return false;
    }

    sm_lock_status();
    *status = sysmon->status;
    sm_unlock_status();

    if (!SM_Unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
bool SM_Lock()
{
    Sysmon* sysmon = getSysmonPointer();

    DWORD event = sysmon->WaitForSingleObject(sysmon->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool SM_Unlock()
{
    Sysmon* sysmon = getSysmonPointer();

    return sysmon->ReleaseMutex(sysmon->hMutex);
}

__declspec(noinline)
errno SM_Pause()
{
    Sysmon* sysmon = getSysmonPointer();

    if (sysmon->DisableSysmon)
    {
        return NO_ERROR;
    }

    if (sysmon->SuspendThread(sysmon->hThread) == (DWORD)(-1))
    {
        return GetLastErrno();
    }
    // must get the thread context because SuspendThread only
    // requests a suspend. GetThreadContext actually blocks
    // until it's suspended.
    CONTEXT ctx;
    mem_init(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_INTEGER;
    if (!sysmon->GetThreadContext(sysmon->hThread, &ctx))
    {
        return GetLastErrno();
    }
    return NO_ERROR;
}

__declspec(noinline)
errno SM_Continue()
{
    Sysmon* sysmon = getSysmonPointer();

    if (sysmon->DisableSysmon)
    {
        return NO_ERROR;
    }

    errno errno = NO_ERROR;
    if (sysmon->ResumeThread(sysmon->hThread) == (DWORD)(-1))
    {
        errno = GetLastErrno();
    }
    return errno;
}

__declspec(noinline)
errno SM_Stop()
{
    Sysmon* sysmon = getSysmonPointer();

    errno errno = NO_ERROR;

    if (!sysmon->DisableSysmon)
    {
        // send stop event to watcher
        if (sysmon->SetEvent(sysmon->hEvent))
        {
            // wait watcher thread exit
            if (sysmon->WaitForSingleObject(sysmon->hThread, 1000) != WAIT_OBJECT_0)
            {
                errno = ERR_SYSMON_WAIT_THREAD;
            }
        } else {
            errno = ERR_SYSMON_SEND_EVENT;
        }

        if (!sysmon->CloseHandle(sysmon->hThread) && errno == NO_ERROR)
        {
            errno = ERR_SYSMON_CLOSE_THREAD;
        }
    }

    // clean resource about watcher
    if (!sysmon->CloseHandle(sysmon->hEvent) && errno == NO_ERROR)
    {
        errno = ERR_SYSMON_CLOSE_EVENT;
    }

    // close mutex
    if (!sysmon->CloseHandle(sysmon->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_SYSMON_CLOSE_MUTEX;
    }
    if (!sysmon->CloseHandle(sysmon->statusMu) && errno == NO_ERROR)
    {
        errno = ERR_SYSMON_CLOSE_STATUS;
    }

    // recover instructions
    if (sysmon->NotEraseInstruction)
    {
        if (!recoverSysmonPointer(sysmon) && errno == NO_ERROR)
        {
            errno = ERR_SYSMON_RECOVER_INST;
        }
    }
    return errno;
}
