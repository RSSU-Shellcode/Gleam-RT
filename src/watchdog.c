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

typedef struct {
    // store options
    bool NotEraseInstruction;

    SuspendThread_t          SuspendThread;
    ResumeThread_t           ResumeThread;
    CreateWaitableTimerA_t   CreateWaitableTimerA;
    SetWaitableTimer_t       SetWaitableTimer;
    SetEvent_t               SetEvent;
    ReleaseMutex_t           ReleaseMutex;
    WaitForSingleObject_t    WaitForSingleObject;
    WaitForMultipleObjects_t WaitForMultipleObjects;
    CloseHandle_t            CloseHandle;

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
void WD_Kick();
void WD_Enable();
void WD_Disable();
void WD_SetHandler(WDHandler_t handler);
bool WD_GetStatus(WD_Status* status);

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

static void wd_watcher();
static uint wd_sleep(uint32 milliseconds);

static bool wd_lock_status();
static bool wd_unlock_status();
static void wd_add_kick();
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

}

static bool initWatchdogAPI(Watchdog* watchdog, Context* context)
{
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

// CANNOT merge updateSysmonPointer and recoverSysmonPointer
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

