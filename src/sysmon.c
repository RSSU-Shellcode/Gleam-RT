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
    ReleaseMutex_t           ReleaseMutex;
    WaitForSingleObject_t    WaitForSingleObject;
    WaitForMultipleObjects_t WaitForMultipleObjects;
    CloseHandle_t            CloseHandle;

    // about watcher
    HANDLE hEvent;
    HANDLE hThread;

    // global mutex
    HANDLE hMutex;

    // watcher status
    SM_Status status;
    HANDLE    statusMu;

    // copy from runtime submodules
    HANDLE hMutex_LT;
    HANDLE hMutex_MT;
    HANDLE hMutex_TT;
    HANDLE hMutex_RT;
    HANDLE hMutex_AS;
    HANDLE hMutex_IMS;

    RecoverThreads_t   RecoverThreads;
    ForceKillThreads_t ForceKillThreads;
} Sysmon;

// methods for user
bool SM_GetStatus(SM_Status* status);

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

static void sm_watcher();
static uint sm_watch();
static uint sm_sleep(uint32 milliseconds);

static bool sm_lock_status();
static bool sm_unlock_status();
static void sm_add_loop();
static void sm_add_recover();
static void sm_add_panic();

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
    // create thread for watcher
    HANDLE hThread = context->NewThread(GetFuncAddr(&sm_watcher), NULL, false);
    if (hThread == NULL)
    {
        SetLastErrno(ERR_SYSMON_START_WATCHER);
        return NULL;
    }
    sysmon->hThread = hThread;
    // create methods for tracker
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
    // copy mutex from context
    sysmon->hMutex_LT  = context->hMutex_LT;
    sysmon->hMutex_MT  = context->hMutex_MT;
    sysmon->hMutex_TT  = context->hMutex_TT;
    sysmon->hMutex_RT  = context->hMutex_RT;
    sysmon->hMutex_AS  = context->hMutex_AS;
    sysmon->hMutex_IMS = context->hMutex_IMS;
    // copy methods from context
    sysmon->RecoverThreads   = context->RecoverThreads;
    sysmon->ForceKillThreads = context->ForceKillThreads;
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
static void sm_watcher()
{
    Sysmon* sysmon = getSysmonPointer();

    for (;;)
    {
        switch (sm_watch())
        {
        case RESULT_SUCCESS:
            break;
        case RESULT_STOP_EVENT:
            return;
        case RESULT_FAILED:
            // for trigger debugger
        #ifndef RELEASE_MODE
            sysmon->CloseHandle((HANDLE)(0x19999999));
        #endif
            errno err = sysmon->RecoverThreads();
            if (err != NO_ERROR)
            {
                dbg_log("[sysmon]", "occurred error when recover threads: 0x%X", err);
            }
            if (sm_sleep(1000 + RandIntN(0, 3000)) == RESULT_STOP_EVENT)
            {
                return;
            }
            switch (sm_watch())
            {
            case RESULT_SUCCESS:
                sm_add_recover();
                break;
            case RESULT_STOP_EVENT:
                return;
            case RESULT_FAILED:
                // if failed to recover, use force kill threads,
                // then the Watchdog will restart program.
                err = sysmon->ForceKillThreads();
                if (err != NO_ERROR)
                {
                    dbg_log("[sysmon]", "occurred error when kill threads: 0x%X", err);
                }
                sm_add_panic();
            default:
                panic(PANIC_UNREACHABLE_CODE);
            }
        default:
            panic(PANIC_UNREACHABLE_CODE);
        }
        switch (sm_sleep(1000 + RandIntN(0, 3000)))
        {
        case RESULT_SUCCESS:
            sm_add_loop();
            break;
        case RESULT_STOP_EVENT:
            sm_add_loop();
            return;
        case RESULT_FAILED:
            return;
        default:
            panic(PANIC_UNREACHABLE_CODE);
        }
    }
}

__declspec(noinline)
static uint sm_watch()
{
    Sysmon* sysmon = getSysmonPointer();

    HANDLE handles[] = {
        sysmon->hMutex_LT, sysmon->hMutex_MT, sysmon->hMutex_TT,
        sysmon->hMutex_RT, sysmon->hMutex_AS, sysmon->hMutex_IMS,
    };
    uint result  = RESULT_SUCCESS;
    bool stopped = false;
    for (int i = 0; i < arrlen(handles); i++)
    {
        HANDLE objects[] = { handles[i], sysmon->hEvent };
        DWORD  timeout   = (DWORD)(5000 + RandUintN(0, 10000));
        switch (sysmon->WaitForMultipleObjects(2, objects, false, timeout))
        {
        case WAIT_OBJECT_0+0: case WAIT_ABANDONED+0:
            break;
        case WAIT_OBJECT_0+1:
            stopped = true;
            break;
        default:
            result = RESULT_FAILED;
            break;
        }
    }
    for (int i = arrlen(handles) - 1; i >= 0; i--)
    {
        if (!sysmon->ReleaseMutex(handles[i]))
        {
            result = RESULT_FAILED;
        }
    }
    if (stopped)
    {
        return RESULT_STOP_EVENT;
    }
    return result;
}

__declspec(noinline)
static uint sm_sleep(uint32 milliseconds)
{
    Sysmon* sysmon = getSysmonPointer();

    uint result = RESULT_FAILED;
    HANDLE hTimer = sysmon->CreateWaitableTimerA(NULL, false, NAME_RT_TT_TIMER_SLEEP);
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
static void sm_add_loop()
{
    Sysmon* sysmon = getSysmonPointer();

    if (!sm_lock_status())
    {
        return;
    }

    sysmon->status.NumLoop++;

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
bool SM_GetStatus(SM_Status* status)
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

    errno errno = NO_ERROR;
    if (sysmon->SuspendThread(sysmon->hThread) == (DWORD)(-1))
    {
        errno = GetLastErrno();
    }
    return errno;
}

__declspec(noinline)
errno SM_Continue()
{
    Sysmon* sysmon = getSysmonPointer();

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

    // send stop event to watcher
    if (!sysmon->SetEvent(sysmon->hEvent))
    {
        errno = ERR_SYSMON_SEND_EVENT;
    }
    // wait watcher thread exit
    if (sysmon->WaitForSingleObject(sysmon->hThread, INFINITE) != WAIT_OBJECT_0)
    {
        errno = ERR_SYSMON_WAIT_EXIT;
    }

    // clean resource about watcher
    if (!sysmon->CloseHandle(sysmon->hThread))
    {
        errno = ERR_SYSMON_CLOSE_THREAD;
    }
    if (!sysmon->CloseHandle(sysmon->hEvent))
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
