#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_ws2_32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "list_md.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "mod_resource.h"
#include "debug.h"

// 00，，，，，， types of close function
// ，，0000，， functions about resource
// ，，，，，，00 function suffix types

#define TYPE_MASK 0xFF000000
#define FUNC_MASK 0xFFFFFF00

// function types about release handle
#define TYPE_CLOSE_HANDLE 0x01000000
#define TYPE_FIND_CLOSE   0x02000000

// major function types
#define FUNC_CREATE_MUTEX         (TYPE_CLOSE_HANDLE|0x00000100)
#define FUNC_CREATE_EVENT         (TYPE_CLOSE_HANDLE|0x00000200)
#define FUNC_CREATE_SEMAPHORE     (TYPE_CLOSE_HANDLE|0x00000300)
#define FUNC_CREATE_WAITABLETIMER (TYPE_CLOSE_HANDLE|0x00000400)
#define FUNC_CREATE_FILE          (TYPE_CLOSE_HANDLE|0x00000800)

#define FUNC_FIND_FIRST_FILE (TYPE_FIND_CLOSE|0x00000100)

// source of handles created by functions
#define SRC_CREATE_MUTEX_A    (FUNC_CREATE_MUTEX|0x01)
#define SRC_CREATE_MUTEX_W    (FUNC_CREATE_MUTEX|0x02)
#define SRC_CREATE_MUTEX_EX_A (FUNC_CREATE_MUTEX|0x03)
#define SRC_CREATE_MUTEX_EX_W (FUNC_CREATE_MUTEX|0x04)

#define SRC_CREATE_EVENT_A    (FUNC_CREATE_EVENT|0x01)
#define SRC_CREATE_EVENT_W    (FUNC_CREATE_EVENT|0x02)
#define SRC_CREATE_EVENT_EX_A (FUNC_CREATE_EVENT|0x03)
#define SRC_CREATE_EVENT_EX_W (FUNC_CREATE_EVENT|0x04)

#define SRC_CREATE_SEMAPHORE_A    (FUNC_CREATE_SEMAPHORE|0x01)
#define SRC_CREATE_SEMAPHORE_W    (FUNC_CREATE_SEMAPHORE|0x02)
#define SRC_CREATE_SEMAPHORE_EX_A (FUNC_CREATE_SEMAPHORE|0x03)
#define SRC_CREATE_SEMAPHORE_EX_W (FUNC_CREATE_SEMAPHORE|0x04)

#define SRC_CREATE_WAITABLETIMER_A    (FUNC_CREATE_WAITABLETIMER|0x01)
#define SRC_CREATE_WAITABLETIMER_W    (FUNC_CREATE_WAITABLETIMER|0x02)
#define SRC_CREATE_WAITABLETIMER_EX_A (FUNC_CREATE_WAITABLETIMER|0x03)
#define SRC_CREATE_WAITABLETIMER_EX_W (FUNC_CREATE_WAITABLETIMER|0x04)

#define SRC_CREATE_FILE_A (FUNC_CREATE_FILE|0x01)
#define SRC_CREATE_FILE_W (FUNC_CREATE_FILE|0x02)

#define SRC_FIND_FIRST_FILE_A    (FUNC_FIND_FIRST_FILE|0x01)
#define SRC_FIND_FIRST_FILE_W    (FUNC_FIND_FIRST_FILE|0x02)
#define SRC_FIND_FIRST_FILE_EX_A (FUNC_FIND_FIRST_FILE|0x03)
#define SRC_FIND_FIRST_FILE_EX_W (FUNC_FIND_FIRST_FILE|0x04)

// resource counters index
#define CTR_WSA_STARTUP 0x0000

typedef struct {
    uint32 source;
    void*  handle;
    bool   locked;
} handle;

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    CreateMutexA_t           CreateMutexA;
    CreateMutexW_t           CreateMutexW;
    CreateMutexExA_t         CreateMutexExA;
    CreateMutexExW_t         CreateMutexExW;
    CreateEventA_t           CreateEventA;
    CreateEventW_t           CreateEventW;
    CreateEventExA_t         CreateEventExA;
    CreateEventExW_t         CreateEventExW;
    CreateSemaphoreA_t       CreateSemaphoreA;
    CreateSemaphoreW_t       CreateSemaphoreW;
    CreateSemaphoreExA_t     CreateSemaphoreExA;
    CreateSemaphoreExW_t     CreateSemaphoreExW;
    CreateWaitableTimerA_t   CreateWaitableTimerA;
    CreateWaitableTimerW_t   CreateWaitableTimerW;
    CreateWaitableTimerExA_t CreateWaitableTimerExA;
    CreateWaitableTimerExW_t CreateWaitableTimerExW;
    CreateFileA_t            CreateFileA;
    CreateFileW_t            CreateFileW;
    FindFirstFileA_t         FindFirstFileA;
    FindFirstFileW_t         FindFirstFileW;
    FindFirstFileExA_t       FindFirstFileExA;
    FindFirstFileExW_t       FindFirstFileExW;
    CloseHandle_t            CloseHandle;
    FindClose_t              FindClose;
    ReleaseMutex_t           ReleaseMutex;
    WaitForSingleObject_t    WaitForSingleObject;

    // protect data
    HANDLE hMutex;

    // store all tracked Handles
    List Handles;
    byte HandlesKey[CRYPTO_KEY_SIZE];
    byte HandlesIV [CRYPTO_IV_SIZE];

    // store all resource counters
    int64 Counters[1];
} ResourceTracker;

// methods for IAT hooks
HANDLE RT_CreateMutexA(POINTER lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
HANDLE RT_CreateMutexW(POINTER lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);
HANDLE RT_CreateMutexExA(
    POINTER lpMutexAttributes, LPCSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
);
HANDLE RT_CreateMutexExW(
    POINTER lpMutexAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
);
HANDLE RT_CreateEventA(
    POINTER lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName
);
HANDLE RT_CreateEventW(
    POINTER lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName
);
HANDLE RT_CreateEventExA(
    POINTER lpEventAttributes, LPCSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
);
HANDLE RT_CreateEventExW(
    POINTER lpEventAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
);
HANDLE RT_CreateSemaphoreA(
    POINTER lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCSTR lpName
);
HANDLE RT_CreateSemaphoreW(
    POINTER lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCWSTR lpName
);
HANDLE RT_CreateSemaphoreExA(
    POINTER lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
    LPCSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
);
HANDLE RT_CreateSemaphoreExW(
    POINTER lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
    LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
);
HANDLE RT_CreateWaitableTimerA(
    POINTER lpTimerAttributes, BOOL bManualReset, LPCSTR lpTimerName
);
HANDLE RT_CreateWaitableTimerW(
    POINTER lpTimerAttributes, BOOL bManualReset, LPCWSTR lpTimerName
);
HANDLE RT_CreateWaitableTimerExA(
    POINTER lpTimerAttributes, LPWSTR lpTimerName, DWORD dwFlags, DWORD dwDesiredAccess
);
HANDLE RT_CreateWaitableTimerExW(
    POINTER lpTimerAttributes, LPCWSTR lpTimerName, DWORD dwFlags, DWORD dwDesiredAccess
);
HANDLE RT_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
);
HANDLE RT_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
);
HANDLE RT_FindFirstFileA(LPCSTR lpFileName, POINTER lpFindFileData);
HANDLE RT_FindFirstFileW(LPCWSTR lpFileName, POINTER lpFindFileData);
HANDLE RT_FindFirstFileExA(
    LPCSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
);
HANDLE RT_FindFirstFileExW(
    LPCWSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
);
BOOL RT_CloseHandle(HANDLE hObject);
BOOL RT_FindClose(HANDLE hFindFile);

// resource counters
int RT_WSAStartup(WORD wVersionRequired, POINTER lpWSAData);
int RT_WSACleanup();

// methods for user
bool RT_LockMutex(HANDLE hMutex);
bool RT_UnlockMutex(HANDLE hMutex);
bool RT_GetStatus(RT_Status* status);
bool RT_FreeAllMu();

// methods for runtime
bool  RT_Lock();
bool  RT_Unlock();
errno RT_Encrypt();
errno RT_Decrypt();
errno RT_FreeAll();
errno RT_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF111111C4
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCDC4
#endif
static ResourceTracker* getTrackerPointer();

static bool initTrackerAPI(ResourceTracker* tracker, Context* context);
static bool updateTrackerPointer(ResourceTracker* tracker);
static bool recoverTrackerPointer(ResourceTracker* tracker);
static bool initTrackerEnvironment(ResourceTracker* tracker, Context* context);
static void eraseTrackerMethods(Context* context);
static void cleanTracker(ResourceTracker* tracker);

static bool addHandle(ResourceTracker* tracker, void* hObject, uint32 source);
static void delHandle(ResourceTracker* tracker, void* hObject, uint32 type);
static bool addHandleMu(ResourceTracker* tracker, void* hObject, uint32 source);
static void delHandleMu(ResourceTracker* tracker, void* hObject, uint32 type);
static bool setHandleLocker(HANDLE hObject, uint32 func, bool lock);

static errno doWSACleanup(ResourceTracker* tracker);

ResourceTracker_M* InitResourceTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 8500 + RandUintN(address, 128);
    uintptr moduleAddr  = address + 9500 + RandUintN(address, 128);
    // initialize tracker
    ResourceTracker* tracker = (ResourceTracker*)trackerAddr;
    mem_init(tracker, sizeof(ResourceTracker));
    // store options
    tracker->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errno = ERR_RESOURCE_INIT_API;
            break;
        }
        if (!updateTrackerPointer(tracker))
        {
            errno = ERR_RESOURCE_UPDATE_PTR;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errno = ERR_RESOURCE_INIT_ENV;
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
    ResourceTracker_M* module = (ResourceTracker_M*)moduleAddr;
    // Windows API hooks
    module->CreateMutexA           = GetFuncAddr(&RT_CreateMutexA);
    module->CreateMutexW           = GetFuncAddr(&RT_CreateMutexW);
    module->CreateMutexExA         = GetFuncAddr(&RT_CreateMutexExA);
    module->CreateMutexExW         = GetFuncAddr(&RT_CreateMutexExW);
    module->CreateEventA           = GetFuncAddr(&RT_CreateEventA);
    module->CreateEventW           = GetFuncAddr(&RT_CreateEventW);
    module->CreateEventExA         = GetFuncAddr(&RT_CreateEventExA);
    module->CreateEventExW         = GetFuncAddr(&RT_CreateEventExW);
    module->CreateSemaphoreA       = GetFuncAddr(&RT_CreateSemaphoreA);
    module->CreateSemaphoreW       = GetFuncAddr(&RT_CreateSemaphoreW);
    module->CreateSemaphoreExA     = GetFuncAddr(&RT_CreateSemaphoreExA);
    module->CreateSemaphoreExW     = GetFuncAddr(&RT_CreateSemaphoreExW);
    module->CreateWaitableTimerA   = GetFuncAddr(&RT_CreateWaitableTimerA);
    module->CreateWaitableTimerW   = GetFuncAddr(&RT_CreateWaitableTimerW);
    module->CreateWaitableTimerExA = GetFuncAddr(&RT_CreateWaitableTimerExA);
    module->CreateWaitableTimerExW = GetFuncAddr(&RT_CreateWaitableTimerExW);
    module->CreateFileA            = GetFuncAddr(&RT_CreateFileA);
    module->CreateFileW            = GetFuncAddr(&RT_CreateFileW);
    module->FindFirstFileA         = GetFuncAddr(&RT_FindFirstFileA);
    module->FindFirstFileW         = GetFuncAddr(&RT_FindFirstFileW);
    module->FindFirstFileExA       = GetFuncAddr(&RT_FindFirstFileExA);
    module->FindFirstFileExW       = GetFuncAddr(&RT_FindFirstFileExW);
    module->CloseHandle            = GetFuncAddr(&RT_CloseHandle);
    module->FindClose              = GetFuncAddr(&RT_FindClose);
    module->WSAStartup             = GetFuncAddr(&RT_WSAStartup);
    module->WSACleanup             = GetFuncAddr(&RT_WSACleanup);
    // methods for user
    module->LockMutex   = GetFuncAddr(&RT_LockMutex);
    module->UnlockMutex = GetFuncAddr(&RT_UnlockMutex);
    module->GetStatus   = GetFuncAddr(&RT_GetStatus);
    module->FreeAllMu   = GetFuncAddr(&RT_FreeAllMu);
    // methods for runtime
    module->Lock    = GetFuncAddr(&RT_Lock);
    module->Unlock  = GetFuncAddr(&RT_Unlock);
    module->Encrypt = GetFuncAddr(&RT_Encrypt);
    module->Decrypt = GetFuncAddr(&RT_Decrypt);
    module->FreeAll = GetFuncAddr(&RT_FreeAll);
    module->Clean   = GetFuncAddr(&RT_Clean);
    return module;
}

__declspec(noinline)
static bool initTrackerAPI(ResourceTracker* tracker, Context* context)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xE71F5525D721E78C, 0xE11FEB9E512C3553 }, // CreateMutexA
        { 0x295624AAC9B7A9CF, 0x5E4366A9F3C3C96B }, // CreateMutexW
        { 0xCA1BEE55D503E8D3, 0x05CA734617BCB235 }, // CreateMutexExA
        { 0x235F6300B18F96FA, 0x462245D0B8E090B4 }, // CreateMutexExW
        { 0x9DD020DC005DFF26, 0x84F68DC491FB820C }, // CreateEventA
        { 0xC83FE97180E4699D, 0xF809ED9855BEB13D }, // CreateEventW
        { 0xDEAACA998C18D9CF, 0x2F9217FFF5838855 }, // CreateEventExA
        { 0x0D90DD87F8996201, 0x8775BEA3A96EE2FD }, // CreateEventExW
        { 0xF7BE10C1C1F409B6, 0x083D146ACC929A83 }, // CreateSemaphoreA
        { 0xD76E7132C31D9F7F, 0x810A5E8DF521AF8B }, // CreateSemaphoreW
        { 0x603EC9885322BE77, 0x91EBBF49FD30CD6C }, // CreateSemaphoreExA
        { 0x68A9D452BFC4E94E, 0xBDD2F8F5CE920D49 }, // CreateSemaphoreExW
        { 0xAD2659306A728E9A, 0x3D365A4A5231844C }, // CreateWaitableTimerA
        { 0x2C557505730F7644, 0x304567D9E1D3AC17 }, // CreateWaitableTimerW
        { 0x66CA41440F9FF868, 0xBE5C05614AC956F3 }, // CreateWaitableTimerExA
        { 0xD0262257462ECF54, 0x142D85B27172BAD1 }, // CreateWaitableTimerExW
        { 0x31399C47B70A8590, 0x5C59C3E176954594 }, // CreateFileA
        { 0xD1B5E30FA8812243, 0xFD9A53B98C9A437E }, // CreateFileW
        { 0x60041DBB2B0D19DF, 0x7BD2C85D702B4DDC }, // FindFirstFileA
        { 0xFE81B7989672CCE3, 0xA7FD593F0ED3E8EA }, // FindFirstFileW
        { 0xCAA3E575156CF368, 0x8A587657CB19E9BB }, // FindFirstFileExA
        { 0x7E4308DC46D7B281, 0x10C4F8ED60BC5EB5 }, // FindFirstFileExW
        { 0x98AC87F60ED8677D, 0x2DF5C74604B2E3A1 }, // FindClose
    };
#elif _WIN32
    {
        { 0x944F5EC7, 0x2006E943 }, // CreateMutexA
        { 0xC753F3A6, 0x71358A2E }, // CreateMutexW
        { 0x0E1E9EE7, 0x6E41C8B1 }, // CreateMutexExA
        { 0xF609D00D, 0x2F424452 }, // CreateMutexExW
        { 0xC974EC02, 0x4DFD8870 }, // CreateEventA
        { 0x0545121C, 0x23C575E7 }, // CreateEventW
        { 0x653BE09B, 0xDD06E20B }, // CreateEventExA
        { 0x7F51F1C0, 0xC0601496 }, // CreateEventExW
        { 0xC783748C, 0x1688B859 }, // CreateSemaphoreA
        { 0xB05FAEA3, 0xC2CC106A }, // CreateSemaphoreW
        { 0xA6C4A8F2, 0xD597C8AC }, // CreateSemaphoreExA
        { 0x80B696F0, 0x5DF96491 }, // CreateSemaphoreExW
        { 0x6EF1C038, 0x8BB752D2 }, // CreateWaitableTimerA
        { 0x20E11F8D, 0x0515A457 }, // CreateWaitableTimerW
        { 0x64CC2090, 0xFB298A53 }, // CreateWaitableTimerExA
        { 0x89FD1E78, 0xAFCC42D6 }, // CreateWaitableTimerExW
        { 0x0BB8EEBE, 0x28E70E8D }, // CreateFileA
        { 0x2CB7048A, 0x76AC9783 }, // CreateFileW
        { 0x131B6345, 0x65478818 }, // FindFirstFileA
        { 0xD57E7557, 0x50BC5D0F }, // FindFirstFileW
        { 0xADD805AF, 0xD14251F2 }, // FindFirstFileExA
        { 0x0A45496A, 0x4A4A7F36 }, // FindFirstFileExW
        { 0xE992A699, 0x8B6ED092 }, // FindClose
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
    tracker->CreateMutexA           = list[0x00].proc;
    tracker->CreateMutexW           = list[0x01].proc;
    tracker->CreateMutexExA         = list[0x02].proc;
    tracker->CreateMutexExW         = list[0x03].proc;
    tracker->CreateEventA           = list[0x04].proc;
    tracker->CreateEventW           = list[0x05].proc;
    tracker->CreateEventExA         = list[0x06].proc;
    tracker->CreateEventExW         = list[0x07].proc;
    tracker->CreateSemaphoreA       = list[0x08].proc;
    tracker->CreateSemaphoreW       = list[0x09].proc;
    tracker->CreateSemaphoreExA     = list[0x0A].proc;
    tracker->CreateSemaphoreExW     = list[0x0B].proc;
    tracker->CreateWaitableTimerA   = list[0x0C].proc;
    tracker->CreateWaitableTimerW   = list[0x0D].proc;
    tracker->CreateWaitableTimerExA = list[0x0E].proc;
    tracker->CreateWaitableTimerExW = list[0x0F].proc;
    tracker->CreateFileA            = list[0x10].proc;
    tracker->CreateFileW            = list[0x11].proc;
    tracker->FindFirstFileA         = list[0x12].proc;
    tracker->FindFirstFileW         = list[0x13].proc;
    tracker->FindFirstFileExA       = list[0x14].proc;
    tracker->FindFirstFileExW       = list[0x15].proc;
    tracker->FindClose              = list[0x16].proc;

    tracker->CloseHandle         = context->CloseHandle;
    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    return true;
}

// CANNOT merge updateTrackerPointer and recoverTrackerPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateTrackerPointer(ResourceTracker* tracker)
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
static bool recoverTrackerPointer(ResourceTracker* tracker)
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
static bool initTrackerEnvironment(ResourceTracker* tracker, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    tracker->hMutex = hMutex;
    // initialize handle list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Handles, &ctx, sizeof(handle));
    // set crypto context data
    RandBuffer(tracker->HandlesKey, CRYPTO_KEY_SIZE);
    RandBuffer(tracker->HandlesIV, CRYPTO_IV_SIZE);
    // initialize counters
    for (int i = 0; i < arrlen(tracker->Counters); i++)
    {
        tracker->Counters[i] = 0;
    }
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
static void cleanTracker(ResourceTracker* tracker)
{
    if (tracker->CloseHandle != NULL && tracker->hMutex != NULL)
    {
        tracker->CloseHandle(tracker->hMutex);
    }
    List_Free(&tracker->Handles);
    for (int i = 0; i < arrlen(tracker->Counters); i++)
    {
        tracker->Counters[i] = 0;
    }
}

// updateTrackerPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateTrackerPointer will fail.
#pragma optimize("", off)
static ResourceTracker* getTrackerPointer()
{
    uintptr pointer = TRACKER_POINTER;
    return (ResourceTracker*)(pointer);
}
#pragma optimize("", on)

// For unknown reasons, placing RT_Lock before a function call like CreateEventA
// will cause Go runtime to fail during initialization, so the lock granularity 
// can only be further reduced.
// In a normal function, the lock granularity is large, almost spanning the entire
// function, in order to reduce the impact on the context when suspending the thread.

__declspec(noinline)
HANDLE RT_CreateMutexA(POINTER lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName)
{
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hMutex  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hMutex = tracker->CreateMutexA(
            lpMutexAttributes, bInitialOwner, lpName
        );
        lastErr = GetLastErrno();
        if (hMutex == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hMutex, SRC_CREATE_MUTEX_A))
        {
            lastErr = ERR_RESOURCE_ADD_MUTEX;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateMutexA: 0x%zu", hMutex);
    return hMutex;
}

__declspec(noinline)
HANDLE RT_CreateMutexW(POINTER lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)
{
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hMutex  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hMutex = tracker->CreateMutexW(
            lpMutexAttributes, bInitialOwner, lpName
        );
        lastErr = GetLastErrno();
        if (hMutex == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hMutex, SRC_CREATE_MUTEX_W))
        {
            lastErr = ERR_RESOURCE_ADD_MUTEX;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateMutexW: 0x%zu", hMutex);    
    return hMutex;
}

__declspec(noinline)
HANDLE RT_CreateMutexExA(
    POINTER lpMutexAttributes, LPCSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hMutex  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hMutex = tracker->CreateMutexExA(
            lpMutexAttributes, lpName, dwFlags, dwDesiredAccess
        );
        lastErr = GetLastErrno();
        if (hMutex == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hMutex, SRC_CREATE_MUTEX_EX_A))
        {
            lastErr = ERR_RESOURCE_ADD_MUTEX;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateMutexExA: 0x%zu", hMutex);
    return hMutex;
}

__declspec(noinline)
HANDLE RT_CreateMutexExW(
    POINTER lpMutexAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hMutex  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hMutex = tracker->CreateMutexExW(
            lpMutexAttributes, lpName, dwFlags, dwDesiredAccess
        );
        lastErr = GetLastErrno();
        if (hMutex == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hMutex, SRC_CREATE_MUTEX_EX_W))
        {
            lastErr = ERR_RESOURCE_ADD_MUTEX;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateMutexExW: 0x%zu", hMutex);
    return hMutex;
}

__declspec(noinline)
HANDLE RT_CreateEventA(
    POINTER lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hEvent  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hEvent = tracker->CreateEventA(
            lpEventAttributes, bManualReset, bInitialState, lpName
        );
        lastErr = GetLastErrno();
        if (hEvent == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hEvent, SRC_CREATE_EVENT_A))
        {
            lastErr = ERR_RESOURCE_ADD_EVENT;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateEventA: 0x%zu", hEvent);    
    return hEvent;
}

__declspec(noinline)
HANDLE RT_CreateEventW(
    POINTER lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hEvent  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hEvent = tracker->CreateEventW(
            lpEventAttributes, bManualReset, bInitialState, lpName
        );
        lastErr = GetLastErrno();
        if (hEvent == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hEvent, SRC_CREATE_EVENT_W))
        {
            lastErr = ERR_RESOURCE_ADD_EVENT;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateEventW: 0x%zu", hEvent);
    return hEvent;
}

__declspec(noinline)
HANDLE RT_CreateEventExA(
    POINTER lpEventAttributes, LPCSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hEvent  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hEvent = tracker->CreateEventExA(
            lpEventAttributes, lpName, dwFlags, dwDesiredAccess
        );
        lastErr = GetLastErrno();
        if (hEvent == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hEvent, SRC_CREATE_EVENT_EX_A))
        {
            lastErr = ERR_RESOURCE_ADD_EVENT;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateEventExA: 0x%zu", hEvent);    
    return hEvent;
}

__declspec(noinline)
HANDLE RT_CreateEventExW(
    POINTER lpEventAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hEvent  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hEvent = tracker->CreateEventExW(
            lpEventAttributes, lpName, dwFlags, dwDesiredAccess
        );
        lastErr = GetLastErrno();
        if (hEvent == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hEvent, SRC_CREATE_EVENT_EX_W))
        {
            lastErr = ERR_RESOURCE_ADD_EVENT;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateEventExW: 0x%zu", hEvent);
    return hEvent;
}

__declspec(noinline)
HANDLE RT_CreateSemaphoreA(
    POINTER lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCSTR lpName
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hSempho = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hSempho = tracker->CreateSemaphoreA(
            lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName
        );
        lastErr = GetLastErrno();
        if (hSempho == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hSempho, SRC_CREATE_SEMAPHORE_A))
        {
            lastErr = ERR_RESOURCE_ADD_SEMAPHORE;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateSemaphoreA: 0x%zu", hSempho);
    return hSempho;
}

__declspec(noinline)
HANDLE RT_CreateSemaphoreW(
    POINTER lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCWSTR lpName
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hSempho = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hSempho = tracker->CreateSemaphoreW(
            lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName
        );
        lastErr = GetLastErrno();
        if (hSempho == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hSempho, SRC_CREATE_SEMAPHORE_W))
        {
            lastErr = ERR_RESOURCE_ADD_SEMAPHORE;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateSemaphoreW: 0x%zu", hSempho);
    return hSempho;
}

__declspec(noinline)
HANDLE RT_CreateSemaphoreExA(
    POINTER lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
    LPCSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hSempho = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hSempho = tracker->CreateSemaphoreExA(
            lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName,
            dwFlags, dwDesiredAccess
        );
        lastErr = GetLastErrno();
        if (hSempho == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hSempho, SRC_CREATE_SEMAPHORE_EX_A))
        {
            lastErr = ERR_RESOURCE_ADD_SEMAPHORE;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateSemaphoreExA: 0x%zu", hSempho);
    return hSempho;
}

__declspec(noinline)
HANDLE RT_CreateSemaphoreExW(
    POINTER lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
    LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hSempho = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hSempho = tracker->CreateSemaphoreExW(
            lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName,
            dwFlags, dwDesiredAccess
        );
        lastErr = GetLastErrno();
        if (hSempho == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hSempho, SRC_CREATE_SEMAPHORE_EX_W))
        {
            lastErr = ERR_RESOURCE_ADD_SEMAPHORE;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateSemaphoreExW: 0x%zu", hSempho);
    return hSempho;
}

__declspec(noinline)
HANDLE RT_CreateWaitableTimerA(
    POINTER lpTimerAttributes, BOOL bManualReset, LPCSTR lpTimerName
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hTimer  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hTimer = tracker->CreateWaitableTimerA(
            lpTimerAttributes, bManualReset, lpTimerName
        );
        lastErr = GetLastErrno();
        if (hTimer == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hTimer, SRC_CREATE_WAITABLETIMER_A))
        {
            lastErr = ERR_RESOURCE_ADD_WAITABLETIMER;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateWaitableTimerA: 0x%zu", hTimer);
    return hTimer;
}

__declspec(noinline)
HANDLE RT_CreateWaitableTimerW(
    POINTER lpTimerAttributes, BOOL bManualReset, LPCWSTR lpTimerName
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hTimer  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hTimer = tracker->CreateWaitableTimerW(
            lpTimerAttributes, bManualReset, lpTimerName
        );
        lastErr = GetLastErrno();
        if (hTimer == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hTimer, SRC_CREATE_WAITABLETIMER_W))
        {
            lastErr = ERR_RESOURCE_ADD_WAITABLETIMER;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateWaitableTimerW: 0x%zu", hTimer);
    return hTimer;
}

__declspec(noinline)
HANDLE RT_CreateWaitableTimerExA(
    POINTER lpTimerAttributes, LPWSTR lpTimerName, DWORD dwFlags, DWORD dwDesiredAccess
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hTimer  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hTimer = tracker->CreateWaitableTimerExA(
            lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess
        );
        lastErr = GetLastErrno();
        if (hTimer == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hTimer, SRC_CREATE_WAITABLETIMER_EX_A))
        {
            lastErr = ERR_RESOURCE_ADD_WAITABLETIMER;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateWaitableTimerExA: 0x%zu", hTimer);
    return hTimer;
}

__declspec(noinline)
HANDLE RT_CreateWaitableTimerExW(
    POINTER lpTimerAttributes, LPCWSTR lpTimerName, DWORD dwFlags, DWORD dwDesiredAccess
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hTimer  = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hTimer = tracker->CreateWaitableTimerExW(
            lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess
        );
        lastErr = GetLastErrno();
        if (hTimer == NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hTimer, SRC_CREATE_WAITABLETIMER_EX_W))
        {
            lastErr = ERR_RESOURCE_ADD_WAITABLETIMER;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateWaitableTimerExW: 0x%zu", hTimer);
    return hTimer;
}

__declspec(noinline)
HANDLE RT_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
){
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFile;

    bool  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hFile = tracker->CreateFileA(
            lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
        );
        lastErr = GetLastErrno();
        if (hFile == INVALID_HANDLE_VALUE)
        {
            break;
        }
        if (!addHandle(tracker, hFile, SRC_CREATE_FILE_A))
        {
            break;
        }
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateFileA: %s", lpFileName);

    if (!RT_Unlock())
    {
        return INVALID_HANDLE_VALUE;
    }

    if (!success)
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFile;
};

__declspec(noinline)
HANDLE RT_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
){
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFile;

    bool  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hFile = tracker->CreateFileW(
            lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
        );
        lastErr = GetLastErrno();
        if (hFile == INVALID_HANDLE_VALUE)
        {
            break;
        }
        if (!addHandle(tracker, hFile, SRC_CREATE_FILE_W))
        {
            break;
        }
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateFileW: %ls", lpFileName);

    if (!RT_Unlock())
    {
        return INVALID_HANDLE_VALUE;
    }
    if (!success)
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFile;
};

__declspec(noinline)
HANDLE RT_FindFirstFileA(LPCSTR lpFileName, POINTER lpFindFileData)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFindFile;

    bool  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hFindFile = tracker->FindFirstFileA(lpFileName, lpFindFileData);
        if (hFindFile == INVALID_HANDLE_VALUE)
        {
            break;
        }
        lastErr = GetLastErrno();
        if (!addHandle(tracker, hFindFile, SRC_FIND_FIRST_FILE_A))
        {
            break;
        }
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "FindFirstFileA: %s", lpFileName);

    if (!RT_Unlock())
    {
        return INVALID_HANDLE_VALUE;
    }
    if (!success)
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

__declspec(noinline)
HANDLE RT_FindFirstFileW(LPCWSTR lpFileName, POINTER lpFindFileData)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFindFile;

    bool  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hFindFile = tracker->FindFirstFileW(lpFileName, lpFindFileData);
        if (hFindFile == INVALID_HANDLE_VALUE)
        {
            break;
        }
        lastErr = GetLastErrno();
        if (!addHandle(tracker, hFindFile, SRC_FIND_FIRST_FILE_W))
        {
            break;
        }
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "FindFirstFileW: %ls", lpFileName);

    if (!RT_Unlock())
    {
        return INVALID_HANDLE_VALUE;
    }
    if (!success)
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

HANDLE RT_FindFirstFileExA(
    LPCSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
){
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFindFile;

    bool  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hFindFile = tracker->FindFirstFileExA(
            lpFileName, fInfoLevelId, lpFindFileData,
            fSearchOp, lpSearchFilter, dwAdditionalFlags
        );
        lastErr = GetLastErrno();
        if (hFindFile == INVALID_HANDLE_VALUE)
        {
            break;
        }
        if (!addHandle(tracker, hFindFile, SRC_FIND_FIRST_FILE_EX_A))
        {
            break;
        }
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "FindFirstFileExA: %s", lpFileName);

    if (!RT_Unlock())
    {
        return INVALID_HANDLE_VALUE;
    }
    if (!success)
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

HANDLE RT_FindFirstFileExW(
    LPCWSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
){
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFindFile;

    bool  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hFindFile = tracker->FindFirstFileExW(
            lpFileName, fInfoLevelId, lpFindFileData,
            fSearchOp, lpSearchFilter, dwAdditionalFlags
        );
        lastErr = GetLastErrno();
        if (hFindFile == INVALID_HANDLE_VALUE)
        {
            break;
        }
        if (!addHandle(tracker, hFindFile, SRC_FIND_FIRST_FILE_EX_W))
        {
            break;
        }
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "FindFirstFileExW: %ls", lpFileName);

    if (!RT_Unlock())
    {
        return INVALID_HANDLE_VALUE;
    }
    if (!success)
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

__declspec(noinline)
BOOL RT_CloseHandle(HANDLE hObject)
{
    ResourceTracker* tracker = getTrackerPointer();

    BOOL  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        if (!tracker->CloseHandle(hObject))
        {
            break;
        }
        lastErr = GetLastErrno();
        delHandleMu(tracker, hObject, TYPE_CLOSE_HANDLE);
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CloseHandle: 0x%zX", hObject);
    return success;
};

__declspec(noinline)
BOOL RT_FindClose(HANDLE hFindFile)
{
    ResourceTracker* tracker = getTrackerPointer();

    BOOL  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        if (!tracker->FindClose(hFindFile))
        {
            break;
        }
        lastErr = GetLastErrno();
        delHandleMu(tracker, hFindFile, TYPE_FIND_CLOSE);
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "FindClose: 0x%zX", hFindFile);
    return success;
};

__declspec(noinline)
static bool addHandle(ResourceTracker* tracker, void* hObject, uint32 source)
{
    List* handles = &tracker->Handles;

    handle handle = {
        .source = source,
        .handle = hObject,
        .locked = false,
    };
    if (List_Insert(handles, &handle))
    {
        return true;
    }
    switch (source & TYPE_MASK)
    {
    case TYPE_CLOSE_HANDLE:
        tracker->CloseHandle(hObject);
        break;
    case TYPE_FIND_CLOSE:
        tracker->FindClose(hObject);
        break;
    }
    return false;
};

__declspec(noinline)
static void delHandle(ResourceTracker* tracker, void* hObject, uint32 type)
{
    List* handles = &tracker->Handles;

    uint len = handles->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        handle* handle = List_Get(handles, idx);
        if (handle->source == 0)
        {
            continue;
        }
        if ((handle->source & TYPE_MASK) != type)
        {
            num++;
            continue;
        }
        if (handle->handle != hObject)
        {
            num++;
            continue;
        }
        List_Delete(handles, idx);
        return;
    }
};

__declspec(noinline)
static bool addHandleMu(ResourceTracker* tracker, void* hObject, uint32 source)
{
    bool success = false;
    for (;;)
    {
        if (!RT_Lock())
        {
            break;
        }
        bool ok = addHandle(tracker, hObject, source);
        if (!RT_Unlock())
        {
            break;
        }
        success = ok;
        break;
    }
    return success;
};

__declspec(noinline)
static void delHandleMu(ResourceTracker* tracker, void* hObject, uint32 type)
{
    for (;;)
    {
        if (!RT_Lock())
        {
            break;
        }
        delHandle(tracker, hObject, type);
        if (!RT_Unlock())
        {
            break;
        }
        break;
    }
}

__declspec(noinline)
int RT_WSAStartup(WORD wVersionRequired, POINTER lpWSAData)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return WSASYSNOTREADY;
    }

    int ret = WSASYSNOTREADY;

    errno lastErr = NO_ERROR;
    for (;;)
    {
        WSAStartup_t WSAStartup;
    #ifdef _WIN64
        WSAStartup = FindAPI(0x21A84954D72D9F93, 0xD549133F33DA137E);
    #elif _WIN32
        WSAStartup = FindAPI(0x8CD788B9, 0xA349D8A2);
    #endif
        if (WSAStartup == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        ret = WSAStartup(wVersionRequired, lpWSAData);
        if (ret == 0)
        {
            tracker->Counters[CTR_WSA_STARTUP]++;
        }
        lastErr = GetLastErrno();
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "WSAStartup is called");

    if (!RT_Unlock())
    {
        return WSASYSNOTREADY;
    }
    return ret;
}

__declspec(noinline)
int RT_WSACleanup()
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return WSAEINPROGRESS;
    }

    int ret = WSASYSNOTREADY;

    errno lastErr = NO_ERROR;
    for (;;)
    {
        WSACleanup_t WSACleanup;
    #ifdef _WIN64
        WSACleanup = FindAPI(0x324EEA09CB7B262C, 0xE64CBAD3BBD4F522);
    #elif _WIN32
        WSACleanup = FindAPI(0xBD997AF1, 0x88F10695);
    #endif
        if (WSACleanup == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        ret = WSACleanup();
        if (ret == 0)
        {
            tracker->Counters[CTR_WSA_STARTUP]--;
        }
        lastErr = GetLastErrno();
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "WSACleanup is called");

    if (!RT_Unlock())
    {
        return WSAEINPROGRESS;
    }
    return ret;
}

__declspec(noinline)
bool RT_LockMutex(HANDLE hMutex)
{
    bool success = setHandleLocker(hMutex, FUNC_CREATE_MUTEX, true);
    dbg_log("[resource]", "lock mutex: 0x%zX", hMutex);
    return success;
}

__declspec(noinline)
bool RT_UnlockMutex(HANDLE hMutex)
{
    bool success = setHandleLocker(hMutex, FUNC_CREATE_MUTEX, false);
    dbg_log("[resource]", "unlock mutex: 0x%zX", hMutex);
    return success;
}

__declspec(noinline)
static bool setHandleLocker(HANDLE hObject, uint32 func, bool lock)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return false;
    }

    List* handles = &tracker->Handles;
    bool  success = false;

    uint len = handles->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        handle* handle = List_Get(handles, idx);
        if (handle->source == 0)
        {
            continue;
        }
        if ((handle->source & FUNC_MASK) != func)
        {
            num++;
            continue;
        }
        if (handle->handle != hObject)
        {
            num++;
            continue;
        }
        handle->locked = lock;
        success = true;
        break;
    }

    if (!RT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
bool RT_GetStatus(RT_Status* status)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return false;
    }

    List* handles = &tracker->Handles;

    int64 numMutexs  = 0;
    int64 numEvents  = 0;
    int64 numSemphos = 0;
    int64 numFiles   = 0;
    int64 numDirs    = 0;

    uint len = handles->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        handle* handle = List_Get(handles, idx);
        if (handle->source == 0)
        {
            continue;
        }
        switch (handle->source & FUNC_MASK)
        {
        case FUNC_CREATE_MUTEX:
            numMutexs++;
            break;
        case FUNC_CREATE_EVENT:
            numEvents++;
            break;
        case FUNC_CREATE_SEMAPHORE:
            numSemphos++;
            break;
        case FUNC_CREATE_FILE:
            numFiles++;
            break;
        case FUNC_FIND_FIRST_FILE:
            numDirs++;
            break;
        }
        num++;
    }

    if (!RT_Lock())
    {
        return false;
    }

    status->NumMutexs     = numMutexs;
    status->NumEvents     = numEvents;
    status->NumSemaphores = numSemphos;
    status->NumFiles      = numFiles;
    status->NumDirs       = numDirs;
    return true;
}

__declspec(noinline)
bool RT_FreeAllMu()
{
    if (!RT_Lock())
    {
        return false;
    }

    errno errno = RT_FreeAll();
    dbg_log("[resource]", "FreeAll has been called");

    if (!RT_Unlock())
    {
        return false;
    }

    SetLastErrno(errno);
    return errno == NO_ERROR;
}

__declspec(noinline)
bool RT_Lock()
{
    ResourceTracker* tracker = getTrackerPointer();

    DWORD event = tracker->WaitForSingleObject(tracker->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool RT_Unlock()
{
    ResourceTracker* tracker = getTrackerPointer();

    return tracker->ReleaseMutex(tracker->hMutex);
}

__declspec(noinline)
errno RT_Encrypt()
{
    ResourceTracker* tracker = getTrackerPointer();

    List* list = &tracker->Handles;
    byte* key  = tracker->HandlesKey;
    byte* iv   = tracker->HandlesIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno RT_Decrypt()
{
    ResourceTracker* tracker = getTrackerPointer();

    List* list = &tracker->Handles;
    byte* key  = tracker->HandlesKey;
    byte* iv   = tracker->HandlesIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    dbg_log("[resource]", "handles: %zu", list->Len);
    return NO_ERROR;
}

__declspec(noinline)
errno RT_FreeAll()
{
    ResourceTracker* tracker = getTrackerPointer();

    // close all tracked handles
    List* handles = &tracker->Handles;
    errno errno   = NO_ERROR;

    uint len = handles->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        handle* handle = List_Get(handles, idx);
        if (handle->source == 0)
        {
            continue;
        }
        // skip locked handle
        if (handle->locked)
        {
            num++;
            continue;
        }
        switch (handle->source & TYPE_MASK)
        {
        case TYPE_CLOSE_HANDLE:
            if (!tracker->CloseHandle(handle->handle))
            {
                errno = ERR_RESOURCE_CLOSE_HANDLE;
            }
            break;
        case TYPE_FIND_CLOSE:
            if (!tracker->FindClose(handle->handle))
            {
                errno = ERR_RESOURCE_FIND_CLOSE;
            }
            break;
        default:
            // must cover previous errno
            errno = ERR_RESOURCE_INVALID_SRC_TYPE;
            break;
        }
        if (!List_Delete(handles, idx))
        {
            errno = ERR_RESOURCE_DELETE_HANDLE;
        }
        num++;
    }

    // about WSACleanup
    errno = doWSACleanup(tracker);

    dbg_log("[resource]", "handles: %zu", handles->Len);
    return errno;
}

__declspec(noinline)
errno RT_Clean()
{
    ResourceTracker* tracker = getTrackerPointer();

    errno err = NO_ERROR;
    
    // close all tracked handles
    List* handles = &tracker->Handles;

    uint len = handles->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        handle* handle = List_Get(handles, idx);
        if (handle->source == 0)
        {
            continue;
        }
        switch (handle->source & TYPE_MASK)
        {
        case TYPE_CLOSE_HANDLE:
            if (!tracker->CloseHandle(handle->handle) && err == NO_ERROR)
            {
                err = ERR_RESOURCE_CLOSE_HANDLE;
            }
            break;
        case TYPE_FIND_CLOSE:
            if (!tracker->FindClose(handle->handle) && err == NO_ERROR)
            {
                err = ERR_RESOURCE_FIND_CLOSE;
            }
            break;
        default:
            // must cover previous errno
            err = ERR_RESOURCE_INVALID_SRC_TYPE;
            break;
        }
        num++;
    }

    // clean handle list
    RandBuffer(handles->Data, List_Size(handles));
    if (!List_Free(handles) && err == NO_ERROR)
    {
        err = ERR_RESOURCE_FREE_HANDLE_LIST;
    }

    // about WSACleanup
    errno ewc = doWSACleanup(tracker);
    if (ewc != NO_ERROR && err == NO_ERROR)
    {
        err = ewc;
    }

    // close mutex
    if (!tracker->CloseHandle(tracker->hMutex) && err == NO_ERROR)
    {
        err = ERR_RESOURCE_CLOSE_MUTEX;
    }

    // recover instructions
    if (tracker->NotEraseInstruction)
    {
        if (!recoverTrackerPointer(tracker) && err == NO_ERROR)
        {
            err = ERR_RESOURCE_RECOVER_INST;
        }
    }

    dbg_log("[resource]", "handles: %zu", handles->Len);
    return err;
}

static errno doWSACleanup(ResourceTracker* tracker)
{
#ifdef _WIN64
    WSACleanup_t WSACleanup = FindAPI(0x2D5ED79692C593E4, 0xF65130FCB6DB3FD4);
#elif _WIN32
    WSACleanup_t WSACleanup = FindAPI(0x59F727E0, 0x156A74C5);
#endif
    if (WSACleanup == NULL)
    {
        return NO_ERROR;
    }
    errno errno = NO_ERROR;

    int64 counter = tracker->Counters[CTR_WSA_STARTUP];
    for (int64 i = 0; i < counter; i++)
    {
        if (WSACleanup() != 0)
        {
            errno = ERR_RESOURCE_WSA_CLEANUP;
        }
    }
    tracker->Counters[CTR_WSA_STARTUP] = 0;
    return errno;
}
