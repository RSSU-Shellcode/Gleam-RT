#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "errno.h"
#include "context.h"
#include "watchdog.h"
#include "debug.h"

#define RESULT_FAILED     0
#define RESULT_SUCCESS    1
#define RESULT_STOP_EVENT 2

typedef struct {
    // store options
    bool NotEraseInstruction;

    SuspendThread_t          SuspendThread;
    ResumeThread_t           ResumeThread;
    CreateWaitableTimerA_t   CreateWaitableTimerA;
    SetWaitableTimer_t       SetWaitableTimer;
    SetEvent_t               SetEvent;
    ResetEvent_t             ResetEvent;
    ReleaseMutex_t           ReleaseMutex;
    WaitForSingleObject_t    WaitForSingleObject;
    WaitForMultipleObjects_t WaitForMultipleObjects;
    CloseHandle_t            CloseHandle;

    WDHandler_t handler;

    // about watcher
    HANDLE hEvent;
    HANDLE hThread;

    // global mutex
    HANDLE hMutex;

    // watchdog status
    WD_Status status;
    HANDLE    statusMu;
} Watchdog;

// methods for user
errno WD_Kick();
errno WD_Enable();
errno WD_Disable();
void  WD_SetHandler(WDHandler_t handler);
bool  WD_GetStatus(WD_Status* status);

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

static void  wd_watcher();
static uint  wd_sleep(uint32 milliseconds);
static errno wd_stop();

static bool wd_lock_status();
static bool wd_unlock_status();
static void wd_add_kick();
static void wd_add_normal();
static void wd_add_reset();

Watchdog_M* InitWatchdog(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr watchdogAddr = address + 26000 + RandUintN(address, 128);
    uintptr methodAddr   = address + 27000 + RandUintN(address, 128);
    // initialize watchdog
    Watchdog* watchdog = (Watchdog*)watchdogAddr;
    mem_init(watchdog, sizeof(Watchdog));
    // store options
    watchdog->NotEraseInstruction = context->NotEraseInstruction;
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
    // create methods for tracker
    Watchdog_M* method = (Watchdog_M*)methodAddr;
    // methods for user
    method->Kick       = GetFuncAddr(&WD_Kick);
    method->Enable     = GetFuncAddr(&WD_Enable);
    method->Disable    = GetFuncAddr(&WD_Disable);
    method->SetHandler = GetFuncAddr(&WD_SetHandler);
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
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xA6F25F2ADD9B1353, 0x8B729F0C74C2C45F }, // ResetEvent
    };
#elif _WIN32
    {
        { 0xD60A0046, 0x4292DD1E }, // ResetEvent
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    watchdog->ResetEvent = list[0x00].proc;

    watchdog->SuspendThread          = context->SuspendThread;
    watchdog->ResumeThread           = context->ResumeThread;
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
static void wd_watcher()
{

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
        if (watchdog->WaitForSingleObject(watchdog->hThread, 1000) != WAIT_OBJECT_0)
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
    return errno;
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
static void wd_add_kick()
{
    Watchdog* watchdog = getWatchdogPointer();

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
void WD_SetHandler(WDHandler_t handler)
{
    Watchdog* watchdog = getWatchdogPointer();

    watchdog->handler = handler;
}

__declspec(noinline)
bool WD_GetStatus(WD_Status* status)
{
    Watchdog* watchdog = getWatchdogPointer();

    if (!WD_Lock())
    {
        return false;
    }

    wd_lock_status();
    *status = watchdog->status;
    wd_unlock_status();

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

    if (watchdog->hThread == NULL)
    {
        return NO_ERROR;
    }

    errno errno = NO_ERROR;
    if (watchdog->SuspendThread(watchdog->hThread) == (DWORD)(-1))
    {
        errno = GetLastErrno();
    }
    return errno;
}

__declspec(noinline)
errno WD_Continue()
{
    Watchdog* watchdog = getWatchdogPointer();

    if (watchdog->hThread == NULL)
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
