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

#define SLEEP_REASON_FAILED     0
#define SLEEP_REASON_TIMER      1
#define SLEEP_REASON_STOP_EVENT 2

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

    HANDLE hMutex_LT;
    HANDLE hMutex_MT;
    HANDLE hMutex_TT;
    HANDLE hMutex_RT;
    HANDLE hMutex_AS;
    HANDLE hMutex_IMS;

    SM_Status status;

    // protect data
    HANDLE hMutex;
} Sysmon;

// methods for user
bool SM_GetStatus(SM_Status* status);

// methods for runtime
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

static bool sm_lock();
static bool sm_unlock();

static bool initSysmonAPI(Sysmon* sysmon, Context* context);
static bool updateSysmonPointer(Sysmon* sysmon);
static bool recoverSysmonPointer(Sysmon* sysmon);
static bool initSysmonEnvironment(Sysmon* sysmon, Context* context);
static void eraseSysmonMethods(Context* context);
static void cleanSysmon(Sysmon* sysmon);

static void sm_watcher();
static uint sm_sleep(uint32 milliseconds);

Sysmon_M* InitSysmon(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr sysmonAddr = address + 24000 + RandUintN(address, 128);
    uintptr methodAddr = address + 25000 + RandUintN(address, 128);
    // initialize sysmon
    Sysmon* sysmon = (Sysmon*)sysmonAddr;
    mem_init(sysmon, sizeof(Sysmon));
    // store options
    sysmon->NotEraseInstruction = context->NotEraseInstruction;
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
    // create methods for tracker
    Sysmon_M* method = (Sysmon_M*)methodAddr;
    // methods for user
    method->GetStatus = GetFuncAddr(&SM_GetStatus);
    // methods for runtime
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
    // create event for controller
    HANDLE hEvent = context->CreateEventA(NULL, false, false, NAME_RT_SM_EVENT_CTRL);
    if (hMutex == NULL)
    {
        return false;
    }
    sysmon->hEvent = hEvent;
    // create thread for watcher
    HANDLE hThread = context->NewThread(GetFuncAddr(&sm_watcher), NULL, false);
    if (hThread == NULL)
    {
        return false;
    }
    sysmon->hThread = hThread;
    // copy mutex from context
    sysmon->hMutex_LT  = context->hMutex_LT;
    sysmon->hMutex_MT  = context->hMutex_MT;
    sysmon->hMutex_TT  = context->hMutex_TT;
    sysmon->hMutex_RT  = context->hMutex_RT;
    sysmon->hMutex_AS  = context->hMutex_AS;
    sysmon->hMutex_IMS = context->hMutex_IMS;
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
    if (sysmon->CloseHandle != NULL && sysmon->hMutex != NULL)
    {
        sysmon->CloseHandle(sysmon->hMutex);
    }
    // TODO
    if (sysmon->CloseHandle != NULL && sysmon->hThread != NULL)
    {

        sysmon->CloseHandle(sysmon->hThread);
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
static bool sm_lock()
{
    Sysmon* sysmon = getSysmonPointer();

    DWORD event = sysmon->WaitForSingleObject(sysmon->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool sm_unlock()
{
    Sysmon* sysmon = getSysmonPointer();

    return sysmon->ReleaseMutex(sysmon->hMutex);
}

__declspec(noinline)
static void sm_watcher()
{
    for (;;)
    {

        uint reason = sm_sleep(1000 + RandIntN(0, 3000));
        switch (reason)
        {
        case SLEEP_REASON_TIMER:
            break;
        case SLEEP_REASON_STOP_EVENT:
            return;
        default:
            return;
        }
    }
}

__declspec(noinline)
static uint sm_sleep(uint32 milliseconds)
{
    Sysmon* sysmon = getSysmonPointer();

    uint reason = SLEEP_REASON_FAILED;
    HANDLE hTimer = sysmon->CreateWaitableTimerA(NULL, false, NAME_RT_TT_TIMER_SLEEP);
    if (hTimer == NULL)
    {
        return reason;
    }
    for (;;)
    {
        if (milliseconds < 10)
        {
            milliseconds = 10;
        }
        int64 dueTime = -((int64)milliseconds * 1000 * 10);
        if (!sysmon->SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, true))
        {
            break;
        }
        HANDLE objects[] = { hTimer, sysmon->hEvent };
        switch (sysmon->WaitForMultipleObjects(2, objects, false, INFINITE))
        {
        case WAIT_OBJECT_0+0:
            reason = SLEEP_REASON_TIMER;
            break;
        case WAIT_OBJECT_0+1:
            reason = SLEEP_REASON_STOP_EVENT;
            break;
        default:
            break;
        }
        break;
    }
    sysmon->CloseHandle(hTimer);
    return reason;
}

__declspec(noinline)
bool SM_GetStatus(SM_Status* status)
{
    Sysmon* sysmon = getSysmonPointer();

    if (!sm_lock())
    {
        return false;
    }

    *status = sysmon->status;

    if (!sm_unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
errno SM_Pause()
{
    Sysmon* sysmon = getSysmonPointer();

    if (!sm_lock())
    {
        return ERR_SYSMON_LOCK;
    }

    errno errno = NO_ERROR;
    if (sysmon->SuspendThread(sysmon->hThread) == (DWORD)(-1))
    {
        errno = GetLastErrno();
    }

    if (!sm_unlock())
    {
        return ERR_SYSMON_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
errno SM_Continue()
{
    Sysmon* sysmon = getSysmonPointer();

    if (!sm_lock())
    {
        return ERR_SYSMON_LOCK;
    }

    errno errno = NO_ERROR;
    if (sysmon->ResumeThread(sysmon->hThread) == (DWORD)(-1))
    {
        errno = GetLastErrno();
    }

    if (!sm_unlock())
    {
        return ERR_SYSMON_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
errno SM_Stop()
{
    Sysmon* sysmon = getSysmonPointer();

    errno errno = NO_ERROR;

    // close mutex
    if (!sysmon->CloseHandle(sysmon->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_SYSMON_CLOSE_MUTEX;
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
