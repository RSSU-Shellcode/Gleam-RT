#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "watchdog.h"
#include "debug.h"

#define RESULT_FAILED     0
#define RESULT_SUCCESS    1
#define RESULT_STOP_EVENT 2

typedef struct {
    // store options
    bool DisableWatchdog;
    bool NotEraseInstruction;

    SuspendThread_t          SuspendThread;
    ResumeThread_t           ResumeThread;
    GetThreadContext_t       GetThreadContext;
    CreateWaitableTimerA_t   CreateWaitableTimerA;
    SetWaitableTimer_t       SetWaitableTimer;
    SetEvent_t               SetEvent;
    ResetEvent_t             ResetEvent;
    ReleaseMutex_t           ReleaseMutex;
    WaitForSingleObject_t    WaitForSingleObject;
    WaitForMultipleObjects_t WaitForMultipleObjects;
    CloseHandle_t            CloseHandle;

    // copy from runtime methods
    rt_try_lock_mods_t   RT_TryLockMods;
    rt_try_unlock_mods_t RT_TryUnlockMods;

    // copy from runtime submodules
    TT_NewThread_t        TT_NewThread;
    TT_ForceKillThreads_t TT_ForceKillThreads;
    RT_Cleanup_t          RT_Cleanup;
    RT_Stop_t             RT_Stop;

    // reset handler
    WDHandler_t handler;

    // global mutex
    HANDLE hMutex;

    // about watcher
    HANDLE hEvent;
    HANDLE hThread;

    // watchdog status
    WD_Status status;
    HANDLE    statusMu;
} Watchdog;

// methods for user
void  WD_SetHandler(WDHandler_t handler);
errno WD_Kick();
errno WD_Enable();
errno WD_Disable();
BOOL  WD_IsEnabled();
BOOL  WD_GetStatus(WD_Status* status);

// methods for runtime
bool  WD_Lock();
bool  WD_Unlock();
errno WD_Pause();
errno WD_Continue();
errno WD_Stop();

// hard encoded address in getWatchdogPointer for replacement
#ifdef _WIN64
    #define WATCHDOG_POINTER 0x7FABCDEF111111F2
#elif _WIN32
    #define WATCHDOG_POINTER 0x7FABCDF2
#endif
static Watchdog* getWatchdogPointer();

static bool initWatchdogAPI(Watchdog* watchdog, Context* context);
static bool updateWatchdogPointer(Watchdog* watchdog);
static bool recoverWatchdogPointer(Watchdog* watchdog);
static bool initWatchdogEnvironment(Watchdog* watchdog, Context* context);
static void eraseWatchdogMethods(Context* context);
static void cleanWatchdog(Watchdog* watchdog);

static uint  wd_watcher();
static uint  wd_sleep(uint32 milliseconds);
static errno wd_stop();
static bool  wd_is_enabled();

static bool  wd_lock_status();
static bool  wd_unlock_status();
static int64 wd_get_kick();
static void  wd_add_kick();
static void  wd_add_normal();
static void  wd_add_reset();

Watchdog_M* InitWatchdog(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr watchdogAddr = addr + LAYOUT_WD_STRUCT + RandUintN(addr, 128);
    uintptr methodAddr   = addr + LAYOUT_WD_METHOD + RandUintN(addr, 128);
    // allocate watchdog memory
    Watchdog* watchdog = (Watchdog*)watchdogAddr;
    mem_init(watchdog, sizeof(Watchdog));
    // store options
    watchdog->DisableWatchdog     = context->DisableWatchdog;
    watchdog->NotEraseInstruction = context->NotEraseInstruction;
    // initialize watchdog
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initWatchdogAPI(watchdog, context))
        {
            errno = ERR_WATCHDOG_INIT_API;
            break;
        }
        if (!updateWatchdogPointer(watchdog))
        {
            errno = ERR_WATCHDOG_UPDATE_PTR;
            break;
        }
        if (!initWatchdogEnvironment(watchdog, context))
        {
            errno = ERR_WATCHDOG_INIT_ENV;
            break;
        }
        break;
    }
    eraseWatchdogMethods(context);
    if (errno != NO_ERROR)
    {
        cleanWatchdog(watchdog);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for watchdog
    Watchdog_M* method = (Watchdog_M*)methodAddr;
    // methods for user
    method->SetHandler = GetFuncAddr(&WD_SetHandler);
    method->Kick       = GetFuncAddr(&WD_Kick);
    method->Enable     = GetFuncAddr(&WD_Enable);
    method->Disable    = GetFuncAddr(&WD_Disable);
    method->IsEnabled  = GetFuncAddr(&WD_IsEnabled);
    method->GetStatus  = GetFuncAddr(&WD_GetStatus);
    // methods for runtime
    method->Lock     = GetFuncAddr(&WD_Lock);
    method->Unlock   = GetFuncAddr(&WD_Unlock);
    method->Pause    = GetFuncAddr(&WD_Pause);
    method->Continue = GetFuncAddr(&WD_Continue);
    method->Stop     = GetFuncAddr(&WD_Stop);
    return method;
}

static bool initWatchdogAPI(Watchdog* watchdog, Context* context)
{
    typedef struct { 
        uint mHash; uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x30BFA6B95AFB38E9, 0xB85028D3B8C79467, 0xE741B3D6D25343A1 }, // ResetEvent
    };
#elif _WIN32
    {
        { 0x9603D553, 0x5C129486, 0x12BD2862 }, // ResetEvent
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item = list[i];
        void*  proc = context->FindAPI(item.mHash, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    watchdog->ResetEvent = list[0x00].proc;

    watchdog->SuspendThread          = context->SuspendThread;
    watchdog->ResumeThread           = context->ResumeThread;
    watchdog->GetThreadContext       = context->GetThreadContext;
    watchdog->CreateWaitableTimerA   = context->CreateWaitableTimerA;
    watchdog->SetWaitableTimer       = context->SetWaitableTimer;
    watchdog->SetEvent               = context->SetEvent;
    watchdog->ReleaseMutex           = context->ReleaseMutex;
    watchdog->WaitForSingleObject    = context->WaitForSingleObject;
    watchdog->WaitForMultipleObjects = context->WaitForMultipleObjects;
    watchdog->CloseHandle            = context->CloseHandle;
    return true;
}

// CANNOT merge updateWatchdogPointer and recoverWatchdogPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

static bool updateWatchdogPointer(Watchdog* watchdog)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getWatchdogPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != WATCHDOG_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)watchdog;
        success = true;
        break;
    }
    return success;
}

static bool recoverWatchdogPointer(Watchdog* watchdog)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getWatchdogPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)watchdog)
        {
            target++;
            continue;
        }
        *pointer = WATCHDOG_POINTER;
        success = true;
        break;
    }
    return success;
}

static bool initWatchdogEnvironment(Watchdog* watchdog, Context* context)
{
    // create global mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_WD_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return false;
    }
    watchdog->hMutex = hMutex;
    // create status mutex
    HANDLE statusMu = context->CreateMutexA(NULL, false, NAME_RT_WD_MUTEX_STATUS);
    if (statusMu == NULL)
    {
        return false;
    }
    watchdog->statusMu = statusMu;
    // create event for stop watcher
    HANDLE hEvent = context->CreateEventA(NULL, true, false, NAME_RT_WD_EVENT_STOP);
    if (hMutex == NULL)
    {
        return false;
    }
    watchdog->hEvent = hEvent;
    // copy runtime methods
    watchdog->RT_TryLockMods   = context->try_lock_mods;
    watchdog->RT_TryUnlockMods = context->try_unlock_mods;
    // copy method from context
    watchdog->TT_NewThread        = context->TT_NewThread;
    watchdog->TT_ForceKillThreads = context->TT_ForceKillThreads;
    watchdog->RT_Cleanup          = context->RT_Cleanup;
    watchdog->RT_Stop             = context->RT_Stop;
    return true;
}

static void eraseWatchdogMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initWatchdogAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseWatchdogMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

static void cleanWatchdog(Watchdog* watchdog)
{
    if (watchdog->CloseHandle == NULL)
    {
        return;
    }
    if (watchdog->hMutex != NULL)
    {
        watchdog->CloseHandle(watchdog->hMutex);
    }
    if (watchdog->statusMu != NULL)
    {
        watchdog->CloseHandle(watchdog->statusMu);
    }
    if (watchdog->hEvent != NULL)
    {
        watchdog->CloseHandle(watchdog->hEvent);
    }
}

// updateWatchdogPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateWatchdogPointer will fail.
#pragma optimize("", off)
static Watchdog* getWatchdogPointer()
{
    uintptr pointer = WATCHDOG_POINTER;
    return (Watchdog*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static uint wd_watcher()
{
    Watchdog* watchdog = getWatchdogPointer();

    int64 numKick = 0;
    int16 numFail = 0;
    for (;;)
    {
        int64 num = wd_get_kick();
        if (num > numKick)
        {
            numKick = num;
            numFail = 0;
            wd_add_normal();
        } else {
            numFail++;
        }

        if (numFail == 3)
        {
            // if program dead, use force kill threads,
            // then the Watchdog will call reset handler.
            watchdog->RT_TryLockMods();
            errno err = watchdog->TT_ForceKillThreads();
            if (err != NO_ERROR)
            {
                dbg_log("[watchdog]", "occurred error when kill threads: 0x%X", err);
            }
            watchdog->RT_TryUnlockMods();
            // cleanup runtime tracked resource
            err = watchdog->RT_Cleanup();
            if (err != NO_ERROR)
            {
                dbg_log("[watchdog]", "occurred error when cleanup: 0x%X", err);
            }
            watchdog->handler();
            wd_add_reset();
        }

        if (numFail >= 6)
        {
            watchdog->RT_Stop();
            return 2;
        }

        switch (wd_sleep(5000 + RandIntN(0, 5000)))
        {
        case RESULT_SUCCESS:
            break;
        case RESULT_STOP_EVENT:
            return 0;
        case RESULT_FAILED:
            dbg_log("[watchdog]", "occurred error when sleep: 0x%X", GetLastErrno());
            return 1;
        default:
            panic(PANIC_UNREACHABLE_CODE);
        }
    }
}

__declspec(noinline)
static uint wd_sleep(uint32 milliseconds)
{
    Watchdog* watchdog = getWatchdogPointer();

    uint result = RESULT_FAILED;
    HANDLE hTimer = watchdog->CreateWaitableTimerA(NULL, false, NAME_RT_WD_TIMER_SLEEP);
    if (hTimer == NULL)
    {
        return result;
    }
    for (;;)
    {
        if (milliseconds < 10)
        {
            milliseconds = 10;
        }
        int64 dueTime = -((int64)milliseconds * 1000 * 10);
        if (!watchdog->SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, true))
        {
            break;
        }
        HANDLE objects[] = { hTimer, watchdog->hEvent };
        switch (watchdog->WaitForMultipleObjects(2, objects, false, INFINITE))
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
    watchdog->CloseHandle(hTimer);
    return result;
}

__declspec(noinline)
static errno wd_stop()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (watchdog->hThread == NULL)
    {
        return NO_ERROR;
    }

    errno errno = NO_ERROR;

    // send stop event to watcher
    if (watchdog->SetEvent(watchdog->hEvent))
    {
        // wait watcher thread exit
        if (watchdog->WaitForSingleObject(watchdog->hThread, 3000) != WAIT_OBJECT_0)
        {
            errno = ERR_WATCHDOG_WAIT_THREAD;
        }
    } else {
        errno = ERR_WATCHDOG_SEND_EVENT;
    }

    // clean resource about watcher
    if (!watchdog->CloseHandle(watchdog->hThread) && errno == NO_ERROR)
    {
        errno = ERR_WATCHDOG_CLOSE_THREAD;
    }
    if (!watchdog->ResetEvent(watchdog->hEvent) && errno == NO_ERROR)
    {
        errno = ERR_WATCHDOG_RESET_EVENT;
    }

    // reset watcher thread status
    watchdog->hThread = NULL;
    return errno;
}

__declspec(noinline)
static bool wd_is_enabled()
{
    Watchdog* watchdog = getWatchdogPointer();

    return watchdog->hThread != NULL;
}

__declspec(noinline)
static bool wd_lock_status()
{
    Watchdog* watchdog = getWatchdogPointer();

    DWORD event = watchdog->WaitForSingleObject(watchdog->statusMu, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool wd_unlock_status()
{
    Watchdog* watchdog = getWatchdogPointer();

    return watchdog->ReleaseMutex(watchdog->statusMu);
}

__declspec(noinline)
static int64 wd_get_kick()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (!wd_lock_status())
    {
        return 0;
    }

    int64 num = watchdog->status.NumKick;

    if (!wd_unlock_status())
    {
        return 0;
    }
    return num;
}

__declspec(noinline)
static void wd_add_kick()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (watchdog->DisableWatchdog)
    {
        return;
    }

    if (!wd_lock_status())
    {
        return;
    }

    watchdog->status.NumKick++;

    if (!wd_unlock_status())
    {
        return;
    }
}

__declspec(noinline)
static void wd_add_normal()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (!wd_lock_status())
    {
        return;
    }

    watchdog->status.NumNormal++;

    if (!wd_unlock_status())
    {
        return;
    }
}

__declspec(noinline)
static void wd_add_reset()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (!wd_lock_status())
    {
        return;
    }

    watchdog->status.NumReset++;

    if (!wd_unlock_status())
    {
        return;
    }
}

__declspec(noinline)
void WD_SetHandler(WDHandler_t handler)
{
    Watchdog* watchdog = getWatchdogPointer();

    watchdog->handler = handler;
}

__declspec(noinline)
errno WD_Kick()
{
    if (!WD_Lock())
    {
        return ERR_WATCHDOG_LOCK;
    }

    wd_add_kick();

    if (!WD_Unlock())
    {
        return ERR_WATCHDOG_UNLOCK;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno WD_Enable()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (watchdog->DisableWatchdog)
    {
        return NO_ERROR;
    }

    if (!WD_Lock())
    {
        return ERR_WATCHDOG_LOCK;
    }

    errno errno = NO_ERROR;
    for (;;)
    {
        if (watchdog->hThread != NULL)
        {
            break;
        }
        if (watchdog->handler == NULL)
        {
            errno = ERR_WATCHDOG_EMPTY_HANDLER;
            break;
        }
        void*  address = GetFuncAddr(&wd_watcher);
        HANDLE hThread = watchdog->TT_NewThread(address, NULL, false);
        if (hThread == NULL)
        {
            errno = ERR_WATCHDOG_START_WATCHER;
            break;
        }
        watchdog->hThread = hThread;
        break;
    }

    if (!WD_Unlock())
    {
        return ERR_WATCHDOG_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
errno WD_Disable()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (watchdog->DisableWatchdog)
    {
        return NO_ERROR;
    }

    if (!WD_Lock())
    {
        return ERR_WATCHDOG_LOCK;
    }

    errno errno = wd_stop();

    if (!WD_Unlock())
    {
        return ERR_WATCHDOG_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
BOOL WD_IsEnabled()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (watchdog->DisableWatchdog)
    {
        return false;
    }

    if (!WD_Lock())
    {
        return false;
    }

    bool enabled = wd_is_enabled();

    if (!WD_Unlock())
    {
        return false;
    }
    return enabled;
}

__declspec(noinline)
BOOL WD_GetStatus(WD_Status* status)
{
    Watchdog* watchdog = getWatchdogPointer();

    if (!WD_Lock())
    {
        return false;
    }

    wd_lock_status();
    *status = watchdog->status;
    wd_unlock_status();
    status->IsEnabled = wd_is_enabled();

    if (!WD_Unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
bool WD_Lock()
{
    Watchdog* watchdog = getWatchdogPointer();

    DWORD event = watchdog->WaitForSingleObject(watchdog->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool WD_Unlock()
{
    Watchdog* watchdog = getWatchdogPointer();

    return watchdog->ReleaseMutex(watchdog->hMutex);
}

__declspec(noinline)
errno WD_Pause()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (watchdog->DisableWatchdog || watchdog->hThread == NULL)
    {
        return NO_ERROR;
    }

    if (watchdog->SuspendThread(watchdog->hThread) == (DWORD)(-1))
    {
        return GetLastErrno();
    }
    // must get the thread context because SuspendThread only
    // requests a suspend. GetThreadContext actually blocks
    // until it's suspended.
    CONTEXT ctx;
    mem_init(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_INTEGER;
    if (!watchdog->GetThreadContext(watchdog->hThread, &ctx))
    {
        return GetLastErrno();
    }
    return NO_ERROR;
}

__declspec(noinline)
errno WD_Continue()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (watchdog->DisableWatchdog || watchdog->hThread == NULL)
    {
        return NO_ERROR;
    }

    errno errno = NO_ERROR;
    if (watchdog->ResumeThread(watchdog->hThread) == (DWORD)(-1))
    {
        errno = GetLastErrno();
    }
    return errno;
}

__declspec(noinline)
errno WD_Stop()
{
    Watchdog* watchdog = getWatchdogPointer();

    errno errno = wd_stop();

    // clean resource about watcher
    if (!watchdog->CloseHandle(watchdog->hEvent) && errno == NO_ERROR)
    {
        errno = ERR_WATCHDOG_CLOSE_EVENT;
    }

    // close mutex
    if (!watchdog->CloseHandle(watchdog->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_WATCHDOG_CLOSE_MUTEX;
    }
    if (!watchdog->CloseHandle(watchdog->statusMu) && errno == NO_ERROR)
    {
        errno = ERR_WATCHDOG_CLOSE_STATUS;
    }

    // recover instructions
    if (watchdog->NotEraseInstruction)
    {
        if (!recoverWatchdogPointer(watchdog) && errno == NO_ERROR)
        {
            errno = ERR_WATCHDOG_RECOVER_INST;
        }
    }
    return errno;
}
