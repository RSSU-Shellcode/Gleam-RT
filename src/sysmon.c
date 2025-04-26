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

typedef struct {
    // store options
    bool NotEraseInstruction;

    CreateWaitableTimerA_t CreateWaitableTimerA;
    SetWaitableTimer_t     SetWaitableTimer;
    ReleaseMutex_t         ReleaseMutex;
    WaitForSingleObject_t  WaitForSingleObject;
    CloseHandle_t          CloseHandle;

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
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xC8EB9C09DC007FB8, 0x87980B49B926FE1D }, // CreateWaitableTimerA
        { 0x3A5329D6B69F9A72, 0x3E19B62A8A1EDA64 }, // SetWaitableTimer
    };
#elif _WIN32
    {
        { 0xA508BB38, 0x7323A00D }, // CreateWaitableTimerA
        { 0x10F559AB, 0xA7FD156A }, // SetWaitableTimer
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
    sysmon->CreateWaitableTimerA = list[0x00].proc;
    sysmon->SetWaitableTimer     = list[0x01].proc;

    sysmon->ReleaseMutex        = context->ReleaseMutex;
    sysmon->WaitForSingleObject = context->WaitForSingleObject;
    sysmon->CloseHandle         = context->CloseHandle;
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
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_SYSMON_MUTEX);
    if (hMutex == NULL)
    {
        return false;
    }
    sysmon->hMutex = hMutex;
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
bool SM_GetStatus(SM_Status* status)
{
    return true;
}

__declspec(noinline)
errno SM_Pause()
{
    return NO_ERROR;
}

__declspec(noinline)
errno SM_Continue()
{
    return NO_ERROR;
}

__declspec(noinline)
errno SM_Stop()
{
    return NO_ERROR;
}
