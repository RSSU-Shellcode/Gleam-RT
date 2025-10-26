#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "list_md.h"
#include "random.h"
#include "crypto.h"
#include "win_api.h"
#include "thread.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "mod_thread.h"
#include "debug.h"

typedef struct {
    DWORD  threadID;
    HANDLE hThread;
    int32  numSuspend;
    bool   locked;
} thread;

typedef struct {
    // store options
    bool NotEraseInstruction;

    // store environment
    void* IMOML;

    // API addresses
    CreateThread_t         CreateThread;
    ExitThread_t           ExitThread;
    SuspendThread_t        SuspendThread;
    ResumeThread_t         ResumeThread;
    SwitchToThread_t       SwitchToThread;
    GetThreadContext_t     GetThreadContext;
    SetThreadContext_t     SetThreadContext;
    GetThreadID_t          GetThreadID;
    GetCurrentThreadID_t   GetCurrentThreadID;
    TerminateThread_t      TerminateThread;
    TlsAlloc_t             TlsAlloc;
    TlsFree_t              TlsFree;
    CreateWaitableTimerA_t CreateWaitableTimerA;
    SetWaitableTimer_t     SetWaitableTimer;
    ReleaseMutex_t         ReleaseMutex;
    WaitForSingleObject_t  WaitForSingleObject;
    DuplicateHandle_t      DuplicateHandle;
    CloseHandle_t          CloseHandle;

    // runtime methods
    rt_lock_mods_t   RT_LockMods;
    rt_unlock_mods_t RT_UnlockMods;

    // protect data
    HANDLE hMutex;

    // record the number of total SuspendThread
    int64 NumSuspend;

    // store all threads information
    List Threads;
    byte ThreadsKey[CRYPTO_KEY_SIZE];
    byte ThreadsIV [CRYPTO_IV_SIZE];

    // store allocated TLS slot index
    List TLSIndex;
    byte TLSIndexKey[CRYPTO_KEY_SIZE];
    byte TLSIndexIV [CRYPTO_IV_SIZE];
} ThreadTracker;

// methods for API redirector
HANDLE TT_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
);
void  TT_ExitThread(DWORD dwExitCode);
DWORD TT_SuspendThread(HANDLE hThread);
DWORD TT_ResumeThread(HANDLE hThread);
BOOL  TT_SwitchToThread();
BOOL  TT_GetThreadContext(HANDLE hThread, CONTEXT* lpContext);
BOOL  TT_SetThreadContext(HANDLE hThread, CONTEXT* lpContext);
BOOL  TT_TerminateThread(HANDLE hThread, DWORD dwExitCode);
DWORD TT_TlsAlloc();
BOOL  TT_TlsFree(DWORD dwTlsIndex);

// methods for user
HANDLE TT_ThdNew(void* address, void* parameter, bool track);
void   TT_ThdExit(uint32 code);
void   TT_ThdSleep(uint32 milliseconds);
bool   TT_LockThread(DWORD id);
bool   TT_UnlockThread(DWORD id);
bool   TT_GetStatus(TT_Status* status);
bool   TT_KillAllMu();

// methods for runtime
bool  TT_Lock();
bool  TT_Unlock();
errno TT_Suspend();
errno TT_Resume();
errno TT_Recover();
errno TT_ForceKill();
errno TT_KillAll();
errno TT_Clean();

HANDLE tt_createThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId, BOOL track
);

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF111111C3
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCDC3
#endif
static ThreadTracker* getTrackerPointer();

static bool initTrackerAPI(ThreadTracker* tracker, Context* context);
static bool updateTrackerPointer(ThreadTracker* tracker);
static bool recoverTrackerPointer(ThreadTracker* tracker);
static bool initTrackerEnvironment(ThreadTracker* tracker, Context* context);
static void eraseTrackerMethods(Context* context);
static void cleanTracker(ThreadTracker* tracker);

static bool getThread(ThreadTracker* tracker, DWORD threadID, thread** pThread);
static bool addThread(ThreadTracker* tracker, DWORD threadID, HANDLE hThread);
static void delThread(ThreadTracker* tracker, DWORD threadID);
static bool addTLSIndex(ThreadTracker* tracker, DWORD index);
static void delTLSIndex(ThreadTracker* tracker, DWORD index);
static bool setThreadLocker(DWORD threadID, bool lock);

ThreadTracker_M* InitThreadTracker(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr trackerAddr = addr + LAYOUT_TT_STRUCT + RandUintN(addr, 128);
    uintptr moduleAddr  = addr + LAYOUT_TT_MODULE + RandUintN(addr, 128);
    // allocate tracker memory
    ThreadTracker* tracker = (ThreadTracker*)trackerAddr;
    mem_init(tracker, sizeof(ThreadTracker));
    // store options
    tracker->NotEraseInstruction = context->NotEraseInstruction;
    // store environment
    tracker->IMOML = context->IMOML;
    // initialize tracker
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errno = ERR_THREAD_INIT_API;
            break;
        }
        if (!updateTrackerPointer(tracker))
        {
            errno = ERR_THREAD_UPDATE_PTR;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errno = ERR_THREAD_INIT_ENV;
            break;
        }
        break;
    }
    eraseTrackerMethods(context);
    if (errno != NO_ERROR)
    {
        cleanTracker(tracker);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for tracker
    ThreadTracker_M* module = (ThreadTracker_M*)moduleAddr;
    // methods for API redirector
    module->CreateThread     = GetFuncAddr(&TT_CreateThread);
    module->ExitThread       = GetFuncAddr(&TT_ExitThread);
    module->SuspendThread    = GetFuncAddr(&TT_SuspendThread);
    module->ResumeThread     = GetFuncAddr(&TT_ResumeThread);
    module->SwitchToThread   = GetFuncAddr(&TT_SwitchToThread);
    module->GetThreadContext = GetFuncAddr(&TT_GetThreadContext);
    module->SetThreadContext = GetFuncAddr(&TT_SetThreadContext);
    module->TerminateThread  = GetFuncAddr(&TT_TerminateThread);
    module->TlsAlloc         = GetFuncAddr(&TT_TlsAlloc);
    module->TlsFree          = GetFuncAddr(&TT_TlsFree);
    // methods for user
    module->New   = GetFuncAddr(&TT_ThdNew);
    module->Exit  = GetFuncAddr(&TT_ThdExit);
    module->Sleep = GetFuncAddr(&TT_ThdSleep);
    module->LockThread   = GetFuncAddr(&TT_LockThread);
    module->UnlockThread = GetFuncAddr(&TT_UnlockThread);
    module->GetStatus    = GetFuncAddr(&TT_GetStatus);
    module->KillAllMu    = GetFuncAddr(&TT_KillAllMu);
    // methods for runtime
    module->Lock      = GetFuncAddr(&TT_Lock);
    module->Unlock    = GetFuncAddr(&TT_Unlock);
    module->Suspend   = GetFuncAddr(&TT_Suspend);
    module->Resume    = GetFuncAddr(&TT_Resume);
    module->Recover   = GetFuncAddr(&TT_Recover);
    module->ForceKill = GetFuncAddr(&TT_ForceKill);
    module->KillAll   = GetFuncAddr(&TT_KillAll);
    module->Clean     = GetFuncAddr(&TT_Clean);
    // data for sysmon
    module->hMutex = tracker->hMutex;
    return module;
}

__declspec(noinline)
static bool initTrackerAPI(ThreadTracker* tracker, Context* context)
{
    typedef struct { 
        uint mHash; uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xBE904CF80CF17C39, 0x519776E56C20ED23, 0x5301991C18DCD17D }, // CreateThread
        { 0xF23240D671D7EC62, 0x0C68B86B8614EB50, 0x45ACC1750A672E67 }, // SwitchToThread
        { 0x7ECC38B577C35684, 0x1FF7CABA157024A2, 0x899DCA1F272AF8EB }, // GetThreadContext
        { 0x8B18734C0789B973, 0xA2C60822A1BE2D5A, 0x76B5C9DD472F424A }, // SetThreadContext
        { 0x9994C637BC7D7FCB, 0xF2FE8E7A503389EA, 0x26E4C3B35DA8BD0E }, // GetThreadId
        { 0xB71E7C8FEFD05DB5, 0x8A0B3145841ADACF, 0xE46B1941576D6197 }, // GetCurrentThreadId
        { 0xE77B1C721DEE4878, 0xCF70DFC838ECCA31, 0xC28365451F8D8061 }, // TerminateThread
        { 0xE6A216055D1CEF2E, 0x0B5C25B37828D617, 0xA44A88E4F1BD1B3F }, // TlsAlloc
        { 0xBCED74DF5203BAD4, 0x22130B4B51186B34, 0xC9741392031C8FF3 }, // TlsFree
    };
#elif _WIN32
    {
        { 0x21B7D96A, 0xBFD234C5, 0x79B41A6D }, // CreateThread
        { 0x10389EFD, 0xFD4F3BAC, 0xDE25CF78 }, // SwitchToThread
        { 0xBAB8418D, 0x9C6574EC, 0x0450B317 }, // GetThreadContext
        { 0xAF648BCE, 0xAB5EB7D9, 0x885A79B8 }, // SetThreadContext
        { 0xD932B610, 0x1EDB556A, 0xEAE314E1 }, // GetThreadId
        { 0x9DCDA638, 0xD7F7DC6A, 0xE476968C }, // GetCurrentThreadId
        { 0xEC2E0B2B, 0x010AE228, 0x72B16724 }, // TerminateThread
        { 0x09C1B0DC, 0xE9B75640, 0x5532D70D }, // TlsAlloc
        { 0xAB3BF90E, 0x828A480E, 0xB2033621 }, // TlsFree
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
    tracker->CreateThread       = list[0x00].proc;
    tracker->SwitchToThread     = list[0x01].proc;
    tracker->GetThreadContext   = list[0x02].proc;
    tracker->SetThreadContext   = list[0x03].proc;
    tracker->GetThreadID        = list[0x04].proc;
    tracker->GetCurrentThreadID = list[0x05].proc;
    tracker->TerminateThread    = list[0x06].proc;
    tracker->TlsAlloc           = list[0x07].proc;
    tracker->TlsFree            = list[0x08].proc;

    tracker->ExitThread           = context->ExitThread;
    tracker->SuspendThread        = context->SuspendThread;
    tracker->ResumeThread         = context->ResumeThread;
    tracker->CreateWaitableTimerA = context->CreateWaitableTimerA;
    tracker->SetWaitableTimer     = context->SetWaitableTimer;
    tracker->ReleaseMutex         = context->ReleaseMutex;
    tracker->WaitForSingleObject  = context->WaitForSingleObject;
    tracker->DuplicateHandle      = context->DuplicateHandle;
    tracker->CloseHandle          = context->CloseHandle;
    return true;
}

// CANNOT merge updateTrackerPointer and recoverTrackerPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateTrackerPointer(ThreadTracker* tracker)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getTrackerPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != TRACKER_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)tracker;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool recoverTrackerPointer(ThreadTracker* tracker)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getTrackerPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)tracker)
        {
            target++;
            continue;
        }
        *pointer = TRACKER_POINTER;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool initTrackerEnvironment(ThreadTracker* tracker, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_TT_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return false;
    }
    tracker->hMutex = hMutex;
    // initialize thread and TLS index list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Threads,  &ctx, sizeof(thread));
    List_Init(&tracker->TLSIndex, &ctx, sizeof(DWORD));
    // set crypto context data
    RandBuffer(tracker->ThreadsKey,  CRYPTO_KEY_SIZE);
    RandBuffer(tracker->ThreadsIV,   CRYPTO_IV_SIZE);
    RandBuffer(tracker->TLSIndexKey, CRYPTO_KEY_SIZE);
    RandBuffer(tracker->TLSIndexIV,  CRYPTO_IV_SIZE);
    // add current thread for special executable file like Golang
    if (context->TrackCurrentThread)
    {
        DWORD threadID = tracker->GetCurrentThreadID();
        if (threadID == 0)
        {
            return false;
        }
        if (!addThread(tracker, threadID, CURRENT_THREAD))
        {
            return false;
        }
    }
    // copy runtime methods
    tracker->RT_LockMods   = context->lock_mods;
    tracker->RT_UnlockMods = context->unlock_mods;
    return true;
}

__declspec(noinline)
static void eraseTrackerMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initTrackerAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseTrackerMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

__declspec(noinline)
static void cleanTracker(ThreadTracker* tracker)
{
    // close mutex handle
    if (tracker->CloseHandle != NULL && tracker->hMutex != NULL)
    {
        tracker->CloseHandle(tracker->hMutex);
    }

    // close already tracked handles
    List* threads = &tracker->Threads;
    uint len = threads->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        thread* thread = List_Get(threads, idx);
        if (thread->threadID == 0)
        {
            continue;
        }
        if (tracker->CloseHandle != NULL)
        {
            tracker->CloseHandle(thread->hThread);
        }
        num++;
    }
    List_Free(threads);
    List_Free(&tracker->TLSIndex);
}

// updateTrackerPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateTrackerPointer will fail.
#pragma optimize("", off)
static ThreadTracker* getTrackerPointer()
{
    uintptr pointer = TRACKER_POINTER;
    return (ThreadTracker*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
HANDLE TT_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
){
    return tt_createThread(
        lpThreadAttributes, dwStackSize, lpStartAddress,
        lpParameter, dwCreationFlags, lpThreadId, true
    );
}

__declspec(noinline)
HANDLE tt_createThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId, BOOL track
){
    ThreadTracker* tracker = getTrackerPointer();

    if (!TT_Lock())
    {
        return NULL;
    }

    DWORD  threadID;
    HANDLE hThread = NULL;

    bool success = false;
    for (;;)
    {
        // create thread from camouflaged start address and pause it
        bool  resume   = (dwCreationFlags & 0xF) != CREATE_SUSPENDED;
        void* fakeAddr = CamouflageStartAddress(tracker->IMOML, lpStartAddress);
        dwCreationFlags |= CREATE_SUSPENDED;
        hThread = tracker->CreateThread(
            lpThreadAttributes, dwStackSize, fakeAddr,
            lpParameter, dwCreationFlags, &threadID
        );
        if (hThread == NULL)
        {
            break;
        }

        // use "mem_init" for prevent incorrect compiler
        // optimize and generate incorrect shellcode
        CONTEXT ctx;
        mem_init(&ctx, sizeof(CONTEXT));

        // hijack RCX/EAX for set the actual thread start address
        // When use CREATE_SUSPENDED, the RIP/EIP will be set to
        // the RtlUserThreadStart(StartAddress, Parameter)
        ctx.ContextFlags = CONTEXT_CONTROL|CONTEXT_INTEGER;

        if (!tracker->GetThreadContext(hThread, &ctx))
        {
            break;
        }
    #ifdef _WIN64
        ctx.RCX = (QWORD)lpStartAddress;
    #elif _WIN32
        // TODO x86
        // skip return address and the second parameter
        // uintptr esp = ctx.ESP + 2*sizeof(uintptr);
        // *(uintptr*)esp = lpStartAddress;
        dbg_log("[thread]", "ctx: 0x%zX", &ctx);

        dbg_log("[thread]", "start: 0x%zX", lpStartAddress);
        dbg_log("[thread]", "param: 0x%zX", lpParameter);

        dbg_log("[thread]", "EDX: 0x%zX", ctx.EDX);
        dbg_log("[thread]", "ECX: 0x%zX", ctx.ECX);
        dbg_log("[thread]", "EAX: 0x%zX", ctx.EAX);
        dbg_log("[thread]", "ESP: 0x%zX", ctx.ESP);
        dbg_log("[thread]", "EIP: 0x%zX", ctx.EIP);

        // the context data is ???????
        ctx.EAX = (DWORD)lpStartAddress;

        uintptr addr = (uintptr)(&ctx);
        addr += 11 * 16;
        *(uintptr*)addr = (uintptr)lpStartAddress;

        dbg_log("[thread]", "EDX: 0x%zX", ctx.EDX);
        dbg_log("[thread]", "ECX: 0x%zX", ctx.ECX);
        dbg_log("[thread]", "EAX: 0x%zX", ctx.EAX);
        dbg_log("[thread]", "ESP: 0x%zX", ctx.ESP);
        dbg_log("[thread]", "EIP: 0x%zX", ctx.EIP);

        // tracker->WaitForSingleObject(-1, INFINITE);
    #endif
        if (!tracker->SetThreadContext(hThread, &ctx))
        {
            break;
        }

        // resume the thread
        if (resume && !tracker->ResumeThread(hThread))
        {
            break;
        }
        if (track && !addThread(tracker, threadID, hThread))
        {
            break;
        }
        dbg_log("[thread]", "Fake Address: 0x%zX", fakeAddr);
        dbg_log("[thread]", "CreateThread: 0x%zX, %lu", lpStartAddress, threadID);
        success = true;
        break;
    }

    if (!TT_Unlock())
    {
        if (hThread != NULL)
        {
            tracker->TerminateThread(hThread, 0);
            tracker->CloseHandle(hThread);
        }
        return NULL;
    }
    if (!success)
    {
        if (hThread != NULL)
        {
            tracker->TerminateThread(hThread, 0);
            tracker->CloseHandle(hThread);
        }
        return NULL;
    }
    if (lpThreadId != NULL)
    {
        *lpThreadId = threadID;
    }
    return hThread;
}

__declspec(noinline)
void TT_ExitThread(DWORD dwExitCode)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!TT_Lock())
    {
        return;
    }

    DWORD threadID = tracker->GetCurrentThreadID();
    if (threadID != 0)
    {
        delThread(tracker, threadID);
    }

    dbg_log("[thread]", "ExitThread: %d, id: %d", dwExitCode, threadID);

    if (!TT_Unlock())
    {
        return;
    }
    tracker->ExitThread(dwExitCode);
}

__declspec(noinline)
DWORD TT_SuspendThread(HANDLE hThread)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (tracker->RT_LockMods() != NO_ERROR)
    {
        return (DWORD)(-1);
    }

    DWORD count = tracker->SuspendThread(hThread);
    if (count != (DWORD)(-1))
    {
        DWORD threadID = tracker->GetThreadID(hThread);
        if (threadID != 0)
        {
            thread* thread;
            if (getThread(tracker, threadID, &thread))
            {
                thread->numSuspend++;
            }
        }
        tracker->NumSuspend++;
    }
    dbg_log("[thread]", "SuspendThread: 0x%zX", hThread);

    if (tracker->RT_UnlockMods() != NO_ERROR)
    {
        return (DWORD)(-1);
    }
    return count;
}

__declspec(noinline)
DWORD TT_ResumeThread(HANDLE hThread)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (tracker->RT_LockMods() != NO_ERROR)
    {
        return (DWORD)(-1);
    }

    DWORD count = tracker->ResumeThread(hThread);
    if (count != (DWORD)(-1))
    {
        DWORD threadID = tracker->GetThreadID(hThread);
        if (threadID != 0)
        {
            thread* thread;
            if (getThread(tracker, threadID, &thread))
            {
                thread->numSuspend--;
            }
        }
        tracker->NumSuspend--;
    }
    dbg_log("[thread]", "ResumeThread: 0x%zX", hThread);

    if (tracker->RT_UnlockMods() != NO_ERROR)
    {
        return (DWORD)(-1);
    }
    return count;
}

__declspec(noinline)
BOOL TT_SwitchToThread()
{
    ThreadTracker* tracker = getTrackerPointer();

    if (tracker->RT_LockMods() != NO_ERROR)
    {
        return false;
    }

    BOOL success = tracker->SwitchToThread();
    dbg_log("[thread]", "SwitchToThread");

    if (tracker->RT_UnlockMods() != NO_ERROR)
    {
        return false;
    }
    return success;
}

__declspec(noinline)
BOOL TT_GetThreadContext(HANDLE hThread, CONTEXT* lpContext)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (tracker->RT_LockMods() != NO_ERROR)
    {
        return false;
    }

    BOOL success = tracker->GetThreadContext(hThread, lpContext);

    dbg_log("[thread]", "GetThreadContext: 0x%zX", hThread);

    if (tracker->RT_UnlockMods() != NO_ERROR)
    {
        return false;
    }
    return success;
}

__declspec(noinline)
BOOL TT_SetThreadContext(HANDLE hThread, CONTEXT* lpContext)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (tracker->RT_LockMods() != NO_ERROR)
    {
        return false;
    }

    BOOL success = tracker->SetThreadContext(hThread, lpContext);

    dbg_log("[thread]", "SetThreadContext: 0x%zX", hThread);

    if (tracker->RT_UnlockMods() != NO_ERROR)
    {
        return false;
    }
    return success;
}

__declspec(noinline)
BOOL TT_TerminateThread(HANDLE hThread, DWORD dwExitCode)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (tracker->RT_LockMods() != NO_ERROR)
    {
        return false;
    }

    DWORD threadID = tracker->GetThreadID(hThread);
    if (threadID != 0)
    {
        delThread(tracker, threadID);
    }

    dbg_log("[thread]", "TerminateThread: %d", threadID);

    if (tracker->RT_UnlockMods() != NO_ERROR)
    {
        return false;
    }
    return tracker->TerminateThread(hThread, dwExitCode);
}

static bool getThread(ThreadTracker* tracker, DWORD threadID, thread** pThread)
{
    List* threads = &tracker->Threads;
    thread thread = {
        .threadID = threadID,
    };
    uint index;
    if (!List_Find(threads, &thread, sizeof(thread.threadID), &index))
    {
        return false;
    }
    *pThread = List_Get(threads, index);
    return true;
}

static bool addThread(ThreadTracker* tracker, DWORD threadID, HANDLE hThread)
{
    // duplicate thread handle
    HANDLE dupHandle;
    if (!tracker->DuplicateHandle(
        CURRENT_PROCESS, hThread, CURRENT_PROCESS,
        &dupHandle, 0, false, DUPLICATE_SAME_ACCESS
    )){
        return false;
    }
    thread thread = {
        .threadID   = threadID,
        .hThread    = dupHandle,
        .numSuspend = 0,
        .locked     = false,
    };
    if (!List_Insert(&tracker->Threads, &thread))
    {
        tracker->CloseHandle(dupHandle);
        return false;
    }
    return true;
}

static void delThread(ThreadTracker* tracker, DWORD threadID)
{
    List* threads = &tracker->Threads;
    thread thread = {
        .threadID = threadID,
    };
    uint index;
    if (!List_Find(threads, &thread, sizeof(thread.threadID), &index))
    {
        return;
    }
    if (!List_Delete(threads, index))
    {
        return;
    }
    tracker->CloseHandle(thread.hThread);
}

__declspec(noinline)
DWORD TT_TlsAlloc()
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!TT_Lock())
    {
        return TLS_OUT_OF_INDEXES;
    }

    DWORD index;

    bool success = false;
    for (;;)
    {
        index = tracker->TlsAlloc();
        if (index == TLS_OUT_OF_INDEXES)
        {
            break;
        }
        if (!addTLSIndex(tracker, index))
        {
            SetLastErrno(ERR_THREAD_ADD_TLS_INDEX);
            break;
        }
        success = true;
        break;
    }

    dbg_log("[thread]", "TlsAlloc: %d", index);

    if (!TT_Unlock())
    {
        return TLS_OUT_OF_INDEXES;
    }

    if (!success)
    {
        return TLS_OUT_OF_INDEXES;
    }
    return index;
}

__declspec(noinline)
BOOL TT_TlsFree(DWORD dwTlsIndex)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!TT_Lock())
    {
        return false;
    }

    BOOL success = false;
    for (;;)
    {
        if (!tracker->TlsFree(dwTlsIndex))
        {
            break;
        }
        delTLSIndex(tracker, dwTlsIndex);
        success = true;
        break;
    }

    dbg_log("[thread]", "TlsFree: %d", dwTlsIndex);

    if (!TT_Unlock())
    {
        return false;
    }
    return success;
}

static bool addTLSIndex(ThreadTracker* tracker, DWORD index)
{
    // for prevent zero index and conflict in List
    DWORD idx = index + 1;

    if (!List_Insert(&tracker->TLSIndex, &idx))
    {
        tracker->TlsFree(index);
        return false;
    }
    return true;
}

static void delTLSIndex(ThreadTracker* tracker, DWORD index)
{
    // for prevent zero index and conflict in List
    index++;

    List* tlsIndex = &tracker->TLSIndex;
    uint idx;
    if (!List_Find(tlsIndex, &index, sizeof(index), &idx))
    {
        return;
    }
    List_Delete(tlsIndex, idx);
}

__declspec(noinline)
HANDLE TT_ThdNew(void* address, void* parameter, bool track)
{
    return tt_createThread(NULL, 0, address, parameter, 0, NULL, track);
}

__declspec(noinline)
void TT_ThdExit(uint32 code)
{
    TT_ExitThread(code);
}

__declspec(noinline)
void TT_ThdSleep(uint32 milliseconds)
{
    ThreadTracker* tracker = getTrackerPointer();

    // copy API address
    if (!TT_Lock())
    {
        return;
    }

    CreateWaitableTimerA_t create = tracker->CreateWaitableTimerA;
    SetWaitableTimer_t     set    = tracker->SetWaitableTimer;
    WaitForSingleObject_t  wait   = tracker->WaitForSingleObject;
    CloseHandle_t          close  = tracker->CloseHandle;

    if (!TT_Unlock())
    {
        return;
    }

    // simulate kernel32.Sleep
    HANDLE hTimer = create(NULL, false, NAME_RT_TT_TIMER_SLEEP);
    if (hTimer == NULL)
    {
        return;
    }
    for (;;)
    {
        if (milliseconds < 10)
        {
            milliseconds = 10;
        }
        int64 dueTime = -((int64)milliseconds * 1000 * 10);
        if (!set(hTimer, &dueTime, 0, NULL, NULL, true))
        {
            break;
        }
        if (wait(hTimer, INFINITE) != WAIT_OBJECT_0)
        {
            break;
        }
        break;
    }
    close(hTimer);
}

__declspec(noinline)
bool TT_LockThread(DWORD id)
{
    bool success = setThreadLocker(id, true);
    dbg_log("[thread]", "lock thread: %d", id);
    return success;
}

__declspec(noinline)
bool TT_UnlockThread(DWORD id)
{
    bool success = setThreadLocker(id, false);
    dbg_log("[thread]", "unlock thread: %d", id);
    return success;
}

__declspec(noinline)
static bool setThreadLocker(DWORD id, bool lock)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!TT_Lock())
    {
        return false;
    }

    bool success = false;
    for (;;)
    {
        List* threads = &tracker->Threads;
        // search thread list
        thread thd = {
            .threadID = id,
        };
        uint index;
        if (!List_Find(threads, &thd, sizeof(thd.threadID), &index))
        {
            break;
        }
        // set thread locker
        thread* thread = List_Get(threads, index);
        thread->locked = lock;
        success = true;
        break;
    }

    if (!TT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
bool TT_GetStatus(TT_Status* status)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!TT_Lock())
    {
        return false;
    }

    status->NumThreads  = (int64)(tracker->Threads.Len);
    status->NumTLSIndex = (int64)(tracker->TLSIndex.Len);
    status->NumSuspend  = (int64)(tracker->NumSuspend);

    if (!TT_Unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
bool TT_KillAllMu()
{
    ThreadTracker* tracker = getTrackerPointer();

    dbg_log("[thread]", "KillAll has been called");

    errno lastErr = NO_ERROR;
    for (;;)
    {
        lastErr = tracker->RT_LockMods();
        if (lastErr != NO_ERROR)
        {
            break;
        }
        lastErr = TT_KillAll();
        errno err = tracker->RT_UnlockMods();
        if (err != NO_ERROR && lastErr == NO_ERROR)
        {
            lastErr = err;
        }
        break;
    }
    if (lastErr != NO_ERROR)
    {
        SetLastErrno(lastErr);
        return false;
    }
    return true;
}

__declspec(noinline)
bool TT_Lock()
{
    ThreadTracker* tracker = getTrackerPointer();

    DWORD event = tracker->WaitForSingleObject(tracker->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool TT_Unlock()
{
    ThreadTracker* tracker = getTrackerPointer();

    return tracker->ReleaseMutex(tracker->hMutex);
}

__declspec(noinline)
errno TT_Suspend()
{
    ThreadTracker* tracker = getTrackerPointer();

    DWORD currentTID = tracker->GetCurrentThreadID();
    if (currentTID == 0)
    {
        return ERR_THREAD_GET_CURRENT_TID;
    }

    List* threads = &tracker->Threads;
    errno errno   = NO_ERROR;

    // suspend threads
    uint len = threads->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        thread* thread = List_Get(threads, idx);
        if (thread->threadID == 0)
        {
            continue;
        }
        // skip self thread
        if (thread->threadID == currentTID)
        {
            num++;
            continue;
        }
        DWORD count = tracker->SuspendThread(thread->hThread);
        if (count != (DWORD)(-1))
        {
            thread->numSuspend++;
        } else {
            delThread(tracker, thread->threadID);
            errno = ERR_THREAD_SUSPEND;
        }
        num++;
    }

    // encrypt thread list
    List* list = &tracker->Threads;
    byte* key  = tracker->ThreadsKey;
    byte* iv   = tracker->ThreadsIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);

    // encrypt TLS slot index list
    list = &tracker->TLSIndex;
    key  = tracker->TLSIndexKey;
    iv   = tracker->TLSIndexIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);
    return errno;
}

__declspec(noinline)
errno TT_Resume()
{
    ThreadTracker* tracker = getTrackerPointer();

    DWORD currentTID = tracker->GetCurrentThreadID();
    if (currentTID == 0)
    {
        return ERR_THREAD_GET_CURRENT_TID;
    }

    // decrypt thread list
    List* list = &tracker->Threads;
    byte* key  = tracker->ThreadsKey;
    byte* iv   = tracker->ThreadsIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    // decrypt TLS slot index list
    list = &tracker->TLSIndex;
    key  = tracker->TLSIndexKey;
    iv   = tracker->TLSIndexIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    List* threads = &tracker->Threads;
    errno errno   = NO_ERROR;

    // resume threads
    uint len = threads->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        thread* thread = List_Get(threads, idx);
        if (thread->threadID == 0)
        {
            continue;
        }
        // skip self thread
        if (thread->threadID == currentTID)
        {
            num++;
            continue;
        }
        DWORD count = tracker->ResumeThread(thread->hThread);
        if (count != (DWORD)(-1))
        {
            thread->numSuspend--;
        } else {
            delThread(tracker, thread->threadID);
            errno = ERR_THREAD_RESUME;
        }
        num++;
    }

    dbg_log("[thread]", "threads:   %zu", tracker->Threads.Len);
    dbg_log("[thread]", "TLS slots: %zu", tracker->TLSIndex.Len);
    return errno;
}

__declspec(noinline)
errno TT_Recover()
{
    ThreadTracker* tracker = getTrackerPointer();

    // try to lock
    DWORD event = tracker->WaitForSingleObject(tracker->hMutex, 1000);
    bool locked = event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;

    List* threads = &tracker->Threads;
    errno errno   = NO_ERROR;

    uint len = threads->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        thread* thread = List_Get(threads, idx);
        if (thread->threadID == 0)
        {
            continue;
        }
        int32 numSuspend = thread->numSuspend;
        if (numSuspend == 0)
        {
            num++;
            continue;
        }
        for (int32 i = 0; i < numSuspend; i++)
        {
            DWORD count = tracker->ResumeThread(thread->hThread);
            if (count == (DWORD)(-1))
            {
                errno = ERR_THREAD_RESUME;
            }
        }
        num++;
    }

    if (locked)
    {
        tracker->ReleaseMutex(tracker->hMutex);
    }
    return errno;
}

__declspec(noinline)
errno TT_ForceKill()
{
    ThreadTracker* tracker = getTrackerPointer();

    List* threads = &tracker->Threads;
    errno errno   = NO_ERROR;

    // suspend all threads before terminate
    uint len = threads->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        thread* thread = List_Get(threads, idx);
        if (thread->threadID == 0)
        {
            continue;
        }
        DWORD count = tracker->SuspendThread(thread->hThread);
        if (count == (DWORD)(-1))
        {
            errno = ERR_THREAD_SUSPEND;
        }
        num++;
    }

    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        thread* thread = List_Get(threads, idx);
        if (thread->threadID == 0)
        {
            continue;
        }
        if (!tracker->TerminateThread(thread->hThread, 0))
        {
            errno = ERR_THREAD_TERMINATE;
        }
        if (tracker->WaitForSingleObject(thread->hThread, 1000) != WAIT_OBJECT_0)
        {
            errno = ERR_THREAD_WAIT_TERMINATE;
        }
        if (!tracker->CloseHandle(thread->hThread))
        {
            errno = ERR_THREAD_CLOSE_HANDLE;
        }
        if (!List_Delete(threads, idx))
        {
            errno = ERR_THREAD_DELETE_THREAD;
        }
        num++;
    }
    return errno;
}

__declspec(noinline)
errno TT_KillAll()
{
    ThreadTracker* tracker = getTrackerPointer();

    DWORD currentTID = tracker->GetCurrentThreadID();
    if (currentTID == 0)
    {
        return ERR_THREAD_GET_CURRENT_TID;
    }

    List* threads  = &tracker->Threads;
    List* tlsIndex = &tracker->TLSIndex;
    errno errno    = NO_ERROR;

    // suspend all threads before terminate
    uint len = threads->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        thread* thread = List_Get(threads, idx);
        if (thread->threadID == 0)
        {
            continue;
        }
        // skip locked thread
        if (thread->locked)
        {
            num++;
            continue;
        }
        // skip self thread
        if (thread->threadID == currentTID)
        {
            num++;
            continue;
        }
        DWORD count = tracker->SuspendThread(thread->hThread);
        if (count == (DWORD)(-1))
        {
            errno = ERR_THREAD_SUSPEND;
        }
        num++;
    }

    // terminate all threads
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        thread* thread = List_Get(threads, idx);
        if (thread->threadID == 0)
        {
            continue;
        }
        // skip locked thread
        if (thread->locked)
        {
            num++;
            continue;
        }
        // skip self thread
        if (thread->threadID != currentTID)
        {
            if (!tracker->TerminateThread(thread->hThread, 0))
            {
                errno = ERR_THREAD_TERMINATE;
            }
            if (tracker->WaitForSingleObject(thread->hThread, 1000) != WAIT_OBJECT_0)
            {
                errno = ERR_THREAD_WAIT_TERMINATE;
            }
        }
        if (!tracker->CloseHandle(thread->hThread))
        {
            errno = ERR_THREAD_CLOSE_HANDLE;
        }
        if (!List_Delete(threads, idx))
        {
            errno = ERR_THREAD_DELETE_THREAD;
        }
        num++;
    }

    // free all TLS slots
    len = tlsIndex->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        DWORD* pIdx = List_Get(tlsIndex, idx);
        DWORD index = *pIdx;
        if (index == 0)
        {
            continue;
        }
        if (!tracker->TlsFree(index - 1))
        {
            errno = ERR_THREAD_FREE_TLS_SLOT;
        }
        if (!List_Delete(tlsIndex, idx))
        {
            errno = ERR_THREAD_DELETE_TLS_INDEX;
        }
        num++;
    }

    dbg_log("[thread]", "threads:   %zu", tracker->Threads.Len);
    dbg_log("[thread]", "TLS slots: %zu", tracker->TLSIndex.Len);
    return errno;
}

__declspec(noinline)
errno TT_Clean()
{
    ThreadTracker* tracker = getTrackerPointer();

    DWORD currentTID = tracker->GetCurrentThreadID();
    if (currentTID == 0)
    {
        return ERR_THREAD_GET_CURRENT_TID;
    }

    List* threads  = &tracker->Threads;
    List* tlsIndex = &tracker->TLSIndex;
    errno errno    = NO_ERROR;

    // suspend all threads before terminate
    uint len = threads->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        thread* thread = List_Get(threads, idx);
        if (thread->threadID == 0)
        {
            continue;
        }
        // skip self thread
        if (thread->threadID == currentTID)
        {
            num++;
            continue;
        }
        DWORD count = tracker->SuspendThread(thread->hThread);
        if (count == (DWORD)(-1) && errno == NO_ERROR)
        {
            errno = ERR_THREAD_SUSPEND;
        }
        num++;
    }

    // terminate all threads
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        thread* thread = List_Get(threads, idx);
        if (thread->threadID == 0)
        {
            continue;
        }
        // skip self thread
        if (thread->threadID != currentTID)
        {
            if (!tracker->TerminateThread(thread->hThread, 0) && errno == NO_ERROR)
            {
                errno = ERR_THREAD_TERMINATE;
            }
            if (tracker->WaitForSingleObject(thread->hThread, 1000) != WAIT_OBJECT_0)
            {
                if (errno == NO_ERROR)
                {
                    errno = ERR_THREAD_WAIT_TERMINATE;
                }
            }
        }
        if (!tracker->CloseHandle(thread->hThread) && errno == NO_ERROR)
        {
            errno = ERR_THREAD_CLOSE_HANDLE;
        }
        num++;
    }

    // free all TLS slots
    len = tlsIndex->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        DWORD* pIdx = List_Get(tlsIndex, idx);
        DWORD index = *pIdx;
        if (index == 0)
        {
            continue;
        }
        if (!tracker->TlsFree(index - 1) && errno == NO_ERROR)
        {
            errno = ERR_THREAD_FREE_TLS_SLOT;
        }
        num++;
    }

    // clean thread list
    RandBuffer(threads->Data, List_Size(threads));
    RandBuffer(tlsIndex->Data, List_Size(tlsIndex));
    if (!List_Free(threads) && errno == NO_ERROR)
    {
        errno = ERR_THREAD_FREE_THREAD_LIST;
    }
    if (!List_Free(tlsIndex) && errno == NO_ERROR)
    {
        errno = ERR_THREAD_FREE_TLS_IDX_LIST;
    }

    // close mutex
    if (!tracker->CloseHandle(tracker->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_THREAD_CLOSE_MUTEX;
    }

    // recover instructions
    if (tracker->NotEraseInstruction)
    {
        if (!recoverTrackerPointer(tracker) && errno == NO_ERROR)
        {
            errno = ERR_THREAD_RECOVER_INST;
        }
    }

    dbg_log("[thread]", "threads:   %zu", tracker->Threads.Len);
    dbg_log("[thread]", "TLS slots: %zu", tracker->TLSIndex.Len);
    return errno;
}
