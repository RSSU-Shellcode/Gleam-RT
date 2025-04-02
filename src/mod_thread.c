#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "list_md.h"
#include "random.h"
#include "crypto.h"
#include "pe_image.h"
#include "win_api.h"
#include "errno.h"
#include "context.h"
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

    // API addresses
    CreateThread_t         CreateThread;
    ExitThread_t           ExitThread;
    SuspendThread_t        SuspendThread;
    ResumeThread_t         ResumeThread;
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
    rt_lock_t   RT_Lock;
    rt_unlock_t RT_Unlock;

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

// methods for IAT hooks
HANDLE TT_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
);
void  TT_ExitThread(DWORD dwExitCode);
DWORD TT_SuspendThread(HANDLE hThread);
DWORD TT_ResumeThread(HANDLE hThread);
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

static void* camouflageStartAddress(void* address);
static bool  addThread(ThreadTracker* tracker, DWORD threadID, HANDLE hThread);
static void  delThread(ThreadTracker* tracker, DWORD threadID);
static bool  addTLSIndex(ThreadTracker* tracker, DWORD index);
static void  delTLSIndex(ThreadTracker* tracker, DWORD index);
static bool  setThreadLocker(DWORD threadID, bool lock);

ThreadTracker_M* InitThreadTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 7000 + RandUintN(address, 128);
    uintptr moduleAddr  = address + 8000 + RandUintN(address, 128);
    // initialize tracker
    ThreadTracker* tracker = (ThreadTracker*)trackerAddr;
    mem_init(tracker, sizeof(ThreadTracker));
    // store options
    tracker->NotEraseInstruction = context->NotEraseInstruction;
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
    // Windows API hooks
    module->CreateThread     = GetFuncAddr(&TT_CreateThread);
    module->ExitThread       = GetFuncAddr(&TT_ExitThread);
    module->SuspendThread    = GetFuncAddr(&TT_SuspendThread);
    module->ResumeThread     = GetFuncAddr(&TT_ResumeThread);
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
    module->Lock    = GetFuncAddr(&TT_Lock);
    module->Unlock  = GetFuncAddr(&TT_Unlock);
    module->Suspend = GetFuncAddr(&TT_Suspend);
    module->Resume  = GetFuncAddr(&TT_Resume);
    module->KillAll = GetFuncAddr(&TT_KillAll);
    module->Clean   = GetFuncAddr(&TT_Clean);
    return module;
}

__declspec(noinline)
static bool initTrackerAPI(ThreadTracker* tracker, Context* context)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x430932D6A2AC04EA, 0x9AF52A6480DA3C93 }, // CreateThread
        { 0x91238A1B4E365AB0, 0x6C621931AE641330 }, // ExitThread
        { 0x3A4D5132CF0D20D8, 0x89E05A81B86A26AE }, // SuspendThread
        { 0xB1917786CE5B5A94, 0x6BC3328C112C6DDA }, // ResumeThread
        { 0x59361F47711B4B27, 0xB97411CC715D4940 }, // GetThreadContext
        { 0xFB9A4AF393D77518, 0xA0CA2E8823A27560 }, // SetThreadContext
        { 0x5133BE509803E44E, 0x20498B6AFFAED91B }, // GetThreadId
        { 0x9AF119F551D952CF, 0x5A1B9D61A26B22D7 }, // GetCurrentThreadId
        { 0xFB891A810F1ABF9A, 0x253BBD721EBD81F0 }, // TerminateThread
        { 0x2C36E30A5F0A762C, 0xFEB91119DD47EE23 }, // TlsAlloc
        { 0x93E44660BF1A6F09, 0x87B9005375387D3C }, // TlsFree
        { 0xB792795AB6382758, 0x5C9EFDF4B328D22C }, // CreateWaitableTimerA
        { 0x03CF410B2AD104B7, 0x4F5D3ECB5E4ECFBD }, // SetWaitableTimer
    };
#elif _WIN32
    {
        { 0xB9D69C9D, 0xCAB90EB6 }, // CreateThread
        { 0x1D1F85DD, 0x41A9BD17 }, // ExitThread
        { 0x26C71141, 0xF3C390BD }, // SuspendThread
        { 0x20FFDC31, 0x1D4EA347 }, // ResumeThread
        { 0x25EF3A63, 0xAFA67C4F }, // GetThreadContext
        { 0x2729A1C9, 0x3A57FF5D }, // SetThreadContext
        { 0xFE77EB3E, 0x81CB68B1 }, // GetThreadId
        { 0x2884E5D9, 0xA933632C }, // GetCurrentThreadId
        { 0xBA134972, 0x295F9DD2 }, // TerminateThread
        { 0x8749FD07, 0x783A2597 }, // TlsAlloc
        { 0x0B8B8434, 0xAD091548 }, // TlsFree
        { 0x86B42DFE, 0x10AA2250 }, // CreateWaitableTimerA
        { 0x9B5031CA, 0x7CD98AEF }, // SetWaitableTimer
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
    tracker->CreateThread         = list[0x00].proc;
    tracker->ExitThread           = list[0x01].proc;
    tracker->SuspendThread        = list[0x02].proc;
    tracker->ResumeThread         = list[0x03].proc;
    tracker->GetThreadContext     = list[0x04].proc;
    tracker->SetThreadContext     = list[0x05].proc;
    tracker->GetThreadID          = list[0x06].proc;
    tracker->GetCurrentThreadID   = list[0x07].proc;
    tracker->TerminateThread      = list[0x08].proc;
    tracker->TlsAlloc             = list[0x09].proc;
    tracker->TlsFree              = list[0x0A].proc;
    tracker->CreateWaitableTimerA = list[0x0B].proc;
    tracker->SetWaitableTimer     = list[0x0C].proc;

    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    tracker->DuplicateHandle     = context->DuplicateHandle;
    tracker->CloseHandle         = context->CloseHandle;
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
    HANDLE hMutex = context->CreateMutexA(NULL, false, NULL);
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
    tracker->RT_Lock   = context->lock;
    tracker->RT_Unlock = context->unlock;
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
    uint idx = 0;
    for (uint num = 0; num < threads->Len; idx++)
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
        void* fakeAddr = camouflageStartAddress(lpStartAddress);
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

static void* camouflageStartAddress(void* address)
{
#ifdef NOT_CAMOUFLAGE
    return address;
#endif // NOT_CAMOUFLAGE

    // get current process module from PEB
#ifdef _WIN64
    uintptr peb = __readgsqword(96);
    uintptr ldr = *(uintptr*)(peb + 24);
    uintptr mod = *(uintptr*)(ldr + 32);
#elif _WIN32
    uintptr peb = __readfsdword(48);
    uintptr ldr = *(uintptr*)(peb + 12);
    uintptr mod = *(uintptr*)(ldr + 20);
#endif
    // get current process module address
#ifdef _WIN64
    uintptr modAddr = *(uintptr*)(mod + 32);
#elif _WIN32
    uintptr modAddr = *(uintptr*)(mod + 16);
#endif
    // parse module information
    PE_Image image;
    ParsePEImage((byte*)modAddr, &image);
    // select a random start address
    uintptr base  = modAddr + image.TextVirtualAddress;
    uintptr begin = base + RandUintN((uint64)address, image.TextSizeOfRawData);
    uintptr end   = base + image.TextSizeOfRawData;
    for (uintptr addr = begin; addr < end; addr++)
    {
        byte b = *(byte*)addr; 
        // skip special instructions
        switch (b)
        {
        case 0x00: // NULL
            continue;
        case 0xCC: // int3
            continue;
        case 0xC3: // ret
            continue;
        case 0xC2: // ret n
            continue;
        default:
            break;
        }
        // push 
        if (b >= 0x50 && b <= 0x57)
        {
            return (void*)addr;
        }
        // mov
        if (b >= 0x88 && b <= 0x8B)
        {
            return (void*)addr;
        }
        // mov register
        if (b >= 0xB0 && b <= 0xBF)
        {
            return (void*)addr;
        }
    }
    // if not found, return the random start address
    return (void*)begin;
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

    if (tracker->RT_Lock() != NO_ERROR)
    {
        return (DWORD)(-1);
    }

    DWORD count = tracker->SuspendThread(hThread);
    if (count != (DWORD)(-1))
    {
        tracker->NumSuspend++;
    }
    dbg_log("[thread]", "SuspendThread: 0x%zX", hThread);

    if (tracker->RT_Unlock() != NO_ERROR)
    {
        return (DWORD)(-1);
    }
    return count;
}

__declspec(noinline)
DWORD TT_ResumeThread(HANDLE hThread)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (tracker->RT_Lock() != NO_ERROR)
    {
        return (DWORD)(-1);
    }

    DWORD count = tracker->ResumeThread(hThread);
    if (count != (DWORD)(-1))
    {
        tracker->NumSuspend--;
    }
    dbg_log("[thread]", "ResumeThread: 0x%zX", hThread);

    if (tracker->RT_Unlock() != NO_ERROR)
    {
        return (DWORD)(-1);
    }
    return count;
}

__declspec(noinline)
BOOL TT_GetThreadContext(HANDLE hThread, CONTEXT* lpContext)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (tracker->RT_Lock() != NO_ERROR)
    {
        return false;
    }

    BOOL success = tracker->GetThreadContext(hThread, lpContext);

    dbg_log("[thread]", "GetThreadContext: 0x%zX", hThread);

    if (tracker->RT_Unlock() != NO_ERROR)
    {
        return false;
    }
    return success;
}

__declspec(noinline)
BOOL TT_SetThreadContext(HANDLE hThread, CONTEXT* lpContext)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (tracker->RT_Lock() != NO_ERROR)
    {
        return false;
    }

    BOOL success = tracker->SetThreadContext(hThread, lpContext);

    dbg_log("[thread]", "SetThreadContext: 0x%zX", hThread);

    if (tracker->RT_Unlock() != NO_ERROR)
    {
        return false;
    }
    return success;
}

__declspec(noinline)
BOOL TT_TerminateThread(HANDLE hThread, DWORD dwExitCode)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (tracker->RT_Lock() != NO_ERROR)
    {
        return false;
    }

    DWORD threadID = tracker->GetThreadID(hThread);
    if (threadID != 0)
    {
        delThread(tracker, threadID);
    }

    dbg_log("[thread]", "TerminateThread: %d", threadID);

    if (tracker->RT_Unlock() != NO_ERROR)
    {
        return false;
    }
    return tracker->TerminateThread(hThread, dwExitCode);
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
    uint idx;
    if (!List_Find(threads, &thread, sizeof(thread.threadID), &idx))
    {
        return;
    }
    if (!List_Delete(threads, idx))
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
    errno lastErr = NO_ERROR;
    for (;;)
    {
        index = tracker->TlsAlloc();
        if (index == TLS_OUT_OF_INDEXES)
        {
            lastErr = GetLastErrno();
            break;
        }
        if (!addTLSIndex(tracker, index))
        {
            lastErr = ERR_THREAD_ADD_TLS_INDEX;
            break;
        }
        break;
    }

    dbg_log("[thread]", "TlsAlloc: %d", index);

    if (!TT_Unlock())
    {
        return TLS_OUT_OF_INDEXES;
    }

    SetLastErrno(lastErr);
    if (lastErr != NO_ERROR)
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

    BOOL  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        if (!tracker->TlsFree(dwTlsIndex))
        {
            lastErr = GetLastErrno();
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

    SetLastErrno(lastErr);
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
    HANDLE hTimer = create(NULL, false, NAME_TT_TIMER_SLEEP);
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
        uint idx;
        if (!List_Find(threads, &thd, sizeof(thd.threadID), &idx))
        {
            break;
        }
        // set thread locker
        thread* thread = List_Get(threads, idx);
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

    if (TT_Lock())
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
        lastErr = tracker->RT_Lock();
        if (lastErr != NO_ERROR)
        {
            break;
        }
        lastErr = TT_KillAll();
        errno err = tracker->RT_Unlock();
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
    errno errno = NO_ERROR;

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
        if (count == (DWORD)(-1))
        {
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
    errno errno = NO_ERROR;

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
        if (count == (DWORD)(-1))
        {
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
    errno errno = NO_ERROR;

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
    errno errno = NO_ERROR;

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
