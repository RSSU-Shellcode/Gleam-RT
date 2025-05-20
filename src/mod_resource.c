#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_advapi32.h"
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

// 00······ types of close function
// ··0000·· functions about resource
// ······00 function suffix types

#define TYPE_MASK 0xFF000000
#define FUNC_MASK 0xFFFFFF00

// function types about release handle
#define TYPE_CLOSE_HANDLE 0x01000000
#define TYPE_FIND_CLOSE   0x02000000
#define TYPE_CLOSE_KEY    0x03000000
#define TYPE_CLOSE_SOCKET 0x04000000

// major function types
#define FUNC_CREATE_MUTEX          (TYPE_CLOSE_HANDLE|0x00000100)
#define FUNC_CREATE_EVENT          (TYPE_CLOSE_HANDLE|0x00000200)
#define FUNC_CREATE_SEMAPHORE      (TYPE_CLOSE_HANDLE|0x00000300)
#define FUNC_CREATE_WAITABLE_TIMER (TYPE_CLOSE_HANDLE|0x00000400)
#define FUNC_CREATE_FILE           (TYPE_CLOSE_HANDLE|0x00000500)
#define FUNC_CREATE_IOCP           (TYPE_CLOSE_HANDLE|0x00000600)

#define FUNC_FIND_FIRST_FILE (TYPE_FIND_CLOSE|0x00000100)

#define FUNC_REG_CREATE_KEY (TYPE_CLOSE_KEY|0x00000100)
#define FUNC_REG_OPEN_KEY   (TYPE_CLOSE_KEY|0x00000200)

#define FUNC_WSA_SOCKET (TYPE_CLOSE_SOCKET|0x00000100)
#define FUNC_SOCKET     (TYPE_CLOSE_SOCKET|0x00000200)
#define FUNC_ACCEPT     (TYPE_CLOSE_SOCKET|0x00000300)

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

#define SRC_CREATE_WAITABLE_TIMER_A    (FUNC_CREATE_WAITABLE_TIMER|0x01)
#define SRC_CREATE_WAITABLE_TIMER_W    (FUNC_CREATE_WAITABLE_TIMER|0x02)
#define SRC_CREATE_WAITABLE_TIMER_EX_A (FUNC_CREATE_WAITABLE_TIMER|0x03)
#define SRC_CREATE_WAITABLE_TIMER_EX_W (FUNC_CREATE_WAITABLE_TIMER|0x04)

#define SRC_CREATE_FILE_A (FUNC_CREATE_FILE|0x01)
#define SRC_CREATE_FILE_W (FUNC_CREATE_FILE|0x02)

#define SRC_CREATE_IOCP (FUNC_CREATE_IOCP|0x01)

#define SRC_FIND_FIRST_FILE_A    (FUNC_FIND_FIRST_FILE|0x01)
#define SRC_FIND_FIRST_FILE_W    (FUNC_FIND_FIRST_FILE|0x02)
#define SRC_FIND_FIRST_FILE_EX_A (FUNC_FIND_FIRST_FILE|0x03)
#define SRC_FIND_FIRST_FILE_EX_W (FUNC_FIND_FIRST_FILE|0x04)

#define SRC_REG_CREATE_KEY_A    (FUNC_REG_CREATE_KEY|0x01)
#define SRC_REG_CREATE_KEY_W    (FUNC_REG_CREATE_KEY|0x02)
#define SRC_REG_CREATE_KEY_EX_A (FUNC_REG_CREATE_KEY|0x03)
#define SRC_REG_CREATE_KEY_EX_W (FUNC_REG_CREATE_KEY|0x04)

#define SRC_REG_OPEN_KEY_A    (FUNC_REG_OPEN_KEY|0x01)
#define SRC_REG_OPEN_KEY_W    (FUNC_REG_OPEN_KEY|0x02)
#define SRC_REG_OPEN_KEY_EX_A (FUNC_REG_OPEN_KEY|0x03)
#define SRC_REG_OPEN_KEY_EX_W (FUNC_REG_OPEN_KEY|0x04)

#define SRC_WSA_SOCKET_A (FUNC_WSA_SOCKET|0x01)
#define SRC_WSA_SOCKET_W (FUNC_WSA_SOCKET|0x02)

#define SRC_SOCKET (FUNC_SOCKET|0x01)
#define SRC_ACCEPT (FUNC_ACCEPT|0x01)

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
    CreateIoCompletionPort_t CreateIoCompletionPort;
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
HANDLE RT_CreateIoCompletionPort(
    HANDLE FileHandle, HANDLE ExistingCompletionPort, POINTER CompletionKey,
    DWORD NumberOfConcurrentThreads
);

LSTATUS RT_RegCreateKeyA(HKEY hKey, LPCSTR lpSubKey, HKEY* phkResult);
LSTATUS RT_RegCreateKeyW(HKEY hKey, LPCWSTR lpSubKey, HKEY* phkResult);
LSTATUS RT_RegCreateKeyExA(
    HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, POINTER lpSecurityAttributes,
    HKEY* phkResult, DWORD* lpdwDisposition
);
LSTATUS RT_RegCreateKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, POINTER lpSecurityAttributes,
    HKEY* phkResult, DWORD* lpdwDisposition
);
LSTATUS RT_RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, HKEY* phkResult);
LSTATUS RT_RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, HKEY* phkResult);
LSTATUS RT_RegOpenKeyExA(
    HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, HKEY* phkResult
);
LSTATUS RT_RegOpenKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, HKEY* phkResult
);

SOCKET RT_WSASocketA(
    int af, int type, int protocol, POINTER lpProtocolInfo, POINTER g, DWORD dwFlags
);
SOCKET RT_WSASocketW(
    int af, int type, int protocol, POINTER lpProtocolInfo, POINTER g, DWORD dwFlags
);
int RT_WSAIoctl(
    SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, 
    LPVOID lpvOutBuffer, DWORD cbOutBuffer, DWORD* lpcbBytesReturned, 
    POINTER lpOverlapped, POINTER lpCompletionRoutine
);
SOCKET RT_socket(int af, int type, int protocol);
SOCKET RT_accept(SOCKET s, POINTER addr, int* addrlen);
int    RT_shutdown(SOCKET s, int how);

BOOL    RT_CloseHandle(HANDLE hObject);
BOOL    RT_FindClose(HANDLE hFindFile);
LSTATUS RT_RegCloseKey(HKEY hKey);
int     RT_closesocket(SOCKET hSocket);

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
    uintptr trackerAddr = address + 10000 + RandUintN(address, 128);
    uintptr moduleAddr  = address + 11000 + RandUintN(address, 128);
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
    module->CreateIoCompletionPort = GetFuncAddr(&RT_CreateIoCompletionPort);
    module->RegCreateKeyA          = GetFuncAddr(&RT_RegCreateKeyA);
    module->RegCreateKeyW          = GetFuncAddr(&RT_RegCreateKeyW);
    module->RegCreateKeyExA        = GetFuncAddr(&RT_RegCreateKeyExA);
    module->RegCreateKeyExW        = GetFuncAddr(&RT_RegCreateKeyExW);
    module->RegOpenKeyA            = GetFuncAddr(&RT_RegOpenKeyA);
    module->RegOpenKeyW            = GetFuncAddr(&RT_RegOpenKeyW);
    module->RegOpenKeyExA          = GetFuncAddr(&RT_RegOpenKeyExA);
    module->RegOpenKeyExW          = GetFuncAddr(&RT_RegOpenKeyExW);
    module->WSASocketA             = GetFuncAddr(&RT_WSASocketA);
    module->WSASocketW             = GetFuncAddr(&RT_WSASocketW);
    module->WSAIoctl               = GetFuncAddr(&RT_WSAIoctl);
    module->socket                 = GetFuncAddr(&RT_socket);
    module->accept                 = GetFuncAddr(&RT_accept);
    module->shutdown               = GetFuncAddr(&RT_shutdown);
    module->CloseHandle            = GetFuncAddr(&RT_CloseHandle);
    module->FindClose              = GetFuncAddr(&RT_FindClose);
    module->RegCloseKey            = GetFuncAddr(&RT_RegCloseKey);
    module->closesocket            = GetFuncAddr(&RT_closesocket);
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
    // data for sysmon
    module->hMutex = tracker->hMutex;
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
        { 0xD696B340A7E3A5ED, 0x535C420EC1129AB9 }, // CreateIoCompletionPort
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
        { 0x6A3CA941, 0xDAE6E303 }, // CreateIoCompletionPort
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
    tracker->CreateIoCompletionPort = list[0x17].proc;

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
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_RT_MUTEX_GLOBAL);
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
        if (!addHandleMu(tracker, hTimer, SRC_CREATE_WAITABLE_TIMER_A))
        {
            lastErr = ERR_RESOURCE_ADD_WAITABLE_TIMER;
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
        if (!addHandleMu(tracker, hTimer, SRC_CREATE_WAITABLE_TIMER_W))
        {
            lastErr = ERR_RESOURCE_ADD_WAITABLE_TIMER;
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
        if (!addHandleMu(tracker, hTimer, SRC_CREATE_WAITABLE_TIMER_EX_A))
        {
            lastErr = ERR_RESOURCE_ADD_WAITABLE_TIMER;
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
        if (!addHandleMu(tracker, hTimer, SRC_CREATE_WAITABLE_TIMER_EX_W))
        {
            lastErr = ERR_RESOURCE_ADD_WAITABLE_TIMER;
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

    HANDLE hFile   = INVALID_HANDLE_VALUE;
    errno  lastErr = NO_ERROR;
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
        if (!addHandleMu(tracker, hFile, SRC_CREATE_FILE_A))
        {
            lastErr = ERR_RESOURCE_ADD_FILE;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateFileA: %s", lpFileName);
    return hFile;
};

__declspec(noinline)
HANDLE RT_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hFile   = INVALID_HANDLE_VALUE;
    errno  lastErr = NO_ERROR;
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
        if (!addHandleMu(tracker, hFile, SRC_CREATE_FILE_W))
        {
            lastErr = ERR_RESOURCE_ADD_FILE;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateFileW: %ls", lpFileName);
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

    HANDLE hFindFile = INVALID_HANDLE_VALUE;
    errno  lastErr   = NO_ERROR;
    for (;;)
    {
        hFindFile = tracker->FindFirstFileA(lpFileName, lpFindFileData);
        lastErr = GetLastErrno();
        if (hFindFile == INVALID_HANDLE_VALUE)
        {
            break;
        }
        if (!addHandle(tracker, hFindFile, SRC_FIND_FIRST_FILE_A))
        {
            lastErr = ERR_RESOURCE_ADD_DIRECTORY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "FindFirstFileA: %s", lpFileName);

    if (!RT_Unlock())
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

    HANDLE hFindFile = INVALID_HANDLE_VALUE;
    errno  lastErr   = NO_ERROR;
    for (;;)
    {
        hFindFile = tracker->FindFirstFileW(lpFileName, lpFindFileData);
        lastErr = GetLastErrno();
        if (hFindFile == INVALID_HANDLE_VALUE)
        {
            break;
        }
        if (!addHandle(tracker, hFindFile, SRC_FIND_FIRST_FILE_W))
        {
            lastErr = ERR_RESOURCE_ADD_DIRECTORY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "FindFirstFileW: %ls", lpFileName);

    if (!RT_Unlock())
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

__declspec(noinline)
HANDLE RT_FindFirstFileExA(
    LPCSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
){
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFindFile = INVALID_HANDLE_VALUE;
    errno  lastErr   = NO_ERROR;
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
            lastErr = ERR_RESOURCE_ADD_DIRECTORY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "FindFirstFileExA: %s", lpFileName);

    if (!RT_Unlock())
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

__declspec(noinline)
HANDLE RT_FindFirstFileExW(
    LPCWSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
){
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFindFile = INVALID_HANDLE_VALUE;
    errno  lastErr   = NO_ERROR;
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
            lastErr = ERR_RESOURCE_ADD_DIRECTORY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "FindFirstFileExW: %ls", lpFileName);

    if (!RT_Unlock())
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

__declspec(noinline)
HANDLE RT_CreateIoCompletionPort(
    HANDLE FileHandle, HANDLE ExistingCompletionPort, POINTER CompletionKey,
    DWORD NumberOfConcurrentThreads
){
    ResourceTracker* tracker = getTrackerPointer();

    HANDLE hPort   = NULL;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        hPort = tracker->CreateIoCompletionPort(
            FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads
        );
        lastErr = GetLastErrno();
        if (hPort == NULL)
        {
            break;
        }
        if (ExistingCompletionPort != NULL)
        {
            break;
        }
        if (!addHandleMu(tracker, hPort, SRC_CREATE_IOCP))
        {
            lastErr = ERR_RESOURCE_ADD_IOCP;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "CreateIoCompletionPort: 0x%zX", FileHandle);
    return hPort;
}

__declspec(noinline)
LSTATUS RT_RegCreateKeyA(HKEY hKey, LPCSTR lpSubKey, HKEY* phkResult)
{
    ResourceTracker* tracker = getTrackerPointer();

    LSTATUS lStatus = ERROR_SUCCESS;
    errno   lastErr = NO_ERROR;
    for (;;)
    {
        RegCreateKeyA_t RegCreateKeyA;
    #ifdef _WIN64
        RegCreateKeyA = FindAPI(0xDEF562502ECFC906, 0x3F5AA82CB3098A5E);
    #elif _WIN32
        RegCreateKeyA = FindAPI(0x953DDEB4, 0xBD4C7C1F);
    #endif
        if (RegCreateKeyA == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        lStatus = RegCreateKeyA(hKey, lpSubKey, phkResult);
        if (lStatus != ERROR_SUCCESS)
        {
            break;
        }
        if (!addHandleMu(tracker, *phkResult, SRC_REG_CREATE_KEY_A))
        {
            lastErr = ERR_RESOURCE_ADD_KEY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "RegCreateKeyA: %s 0x%zX", lpSubKey, * phkResult);
    return lStatus;
}

__declspec(noinline)
LSTATUS RT_RegCreateKeyW(HKEY hKey, LPCWSTR lpSubKey, HKEY* phkResult)
{
    ResourceTracker* tracker = getTrackerPointer();

    LSTATUS lStatus = ERROR_SUCCESS;
    errno   lastErr = NO_ERROR;
    for (;;)
    {
        RegCreateKeyW_t RegCreateKeyW;
    #ifdef _WIN64
        RegCreateKeyW = FindAPI(0x44B01D3112A46809, 0x45D6EE3EFCCE4368);
    #elif _WIN32
        RegCreateKeyW = FindAPI(0x49E44B92, 0xEAD232CB);
    #endif
        if (RegCreateKeyW == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        lStatus = RegCreateKeyW(hKey, lpSubKey, phkResult);
        if (lStatus != ERROR_SUCCESS)
        {
            break;
        }
        if (!addHandleMu(tracker, *phkResult, SRC_REG_CREATE_KEY_W))
        {
            lastErr = ERR_RESOURCE_ADD_KEY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "RegCreateKeyW: %ls 0x%zX", lpSubKey, *phkResult);
    return lStatus;
}

__declspec(noinline)
LSTATUS RT_RegCreateKeyExA(
    HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, POINTER lpSecurityAttributes,
    HKEY* phkResult, DWORD* lpdwDisposition
){
    ResourceTracker* tracker = getTrackerPointer();

    LSTATUS lStatus = ERROR_SUCCESS;
    errno   lastErr = NO_ERROR;
    for (;;)
    {
        RegCreateKeyExA_t RegCreateKeyExA;
    #ifdef _WIN64
        RegCreateKeyExA = FindAPI(0xE1FEFF278289A0C6, 0x190D4FE8AC872642);
    #elif _WIN32
        RegCreateKeyExA = FindAPI(0x32BDE294, 0x3489A92B);
    #endif
        if (RegCreateKeyExA == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        lStatus = RegCreateKeyExA(
            hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
            lpSecurityAttributes, phkResult, lpdwDisposition
        );
        if (lStatus != ERROR_SUCCESS)
        {
            break;
        }
        if (!addHandleMu(tracker, *phkResult, SRC_REG_CREATE_KEY_EX_A))
        {
            lastErr = ERR_RESOURCE_ADD_KEY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "RegCreateKeyExA: %s 0x%zX", lpSubKey, *phkResult);
    return lStatus;
}

__declspec(noinline)
LSTATUS RT_RegCreateKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, POINTER lpSecurityAttributes,
    HKEY* phkResult, DWORD* lpdwDisposition
){
    ResourceTracker* tracker = getTrackerPointer();

    LSTATUS lStatus = ERROR_SUCCESS;
    errno   lastErr = NO_ERROR;
    for (;;)
    {
        RegCreateKeyExW_t RegCreateKeyExW;
    #ifdef _WIN64
        RegCreateKeyExW = FindAPI(0x94B8538578BDDBEE, 0xCC21BEDFFEB6BBDF);
    #elif _WIN32
        RegCreateKeyExW = FindAPI(0x5F5EC82E, 0x2205AD9E);
    #endif
        if (RegCreateKeyExW == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        lStatus = RegCreateKeyExW(
            hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
            lpSecurityAttributes, phkResult, lpdwDisposition
        );
        if (lStatus != ERROR_SUCCESS)
        {
            break;
        }
        if (!addHandleMu(tracker, *phkResult, SRC_REG_CREATE_KEY_EX_W))
        {
            lastErr = ERR_RESOURCE_ADD_KEY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "RegCreateKeyExW: %ls 0x%zX", lpSubKey, *phkResult);
    return lStatus;
}

__declspec(noinline)
LSTATUS RT_RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, HKEY* phkResult)
{
    ResourceTracker* tracker = getTrackerPointer();

    LSTATUS lStatus = ERROR_SUCCESS;
    errno   lastErr = NO_ERROR;
    for (;;)
    {
        RegOpenKeyA_t RegOpenKeyA;
    #ifdef _WIN64
        RegOpenKeyA = FindAPI(0x857AA6888A45F4C9, 0x4AFAFEEEC73E784C);
    #elif _WIN32
        RegOpenKeyA = FindAPI(0x5F3B549C, 0x588ACE35);
    #endif
        if (RegOpenKeyA == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        lStatus = RegOpenKeyA(hKey, lpSubKey, phkResult);
        if (lStatus != ERROR_SUCCESS)
        {
            break;
        }
        if (!addHandleMu(tracker, *phkResult, SRC_REG_OPEN_KEY_A))
        {
            lastErr = ERR_RESOURCE_ADD_KEY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "RegOpenKeyA: %s 0x%zX", lpSubKey, *phkResult);
    return lStatus;
}

__declspec(noinline)
LSTATUS RT_RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, HKEY* phkResult)
{
    ResourceTracker* tracker = getTrackerPointer();

    LSTATUS lStatus = ERROR_SUCCESS;
    errno   lastErr = NO_ERROR;
    for (;;)
    {
        RegOpenKeyW_t RegOpenKeyW;
    #ifdef _WIN64
        RegOpenKeyW = FindAPI(0x596B080727585709, 0xB6E5C5A7344C86EF);
    #elif _WIN32
        RegOpenKeyW = FindAPI(0xFE6E3A60, 0x1F3C45C5);
    #endif
        if (RegOpenKeyW == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        lStatus = RegOpenKeyW(hKey, lpSubKey, phkResult);
        if (lStatus != ERROR_SUCCESS)
        {
            break;
        }
        if (!addHandleMu(tracker, *phkResult, SRC_REG_OPEN_KEY_W))
        {
            lastErr = ERR_RESOURCE_ADD_KEY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "RegOpenKeyW: %ls 0x%zX", lpSubKey, *phkResult);
    return lStatus;
}

__declspec(noinline)
LSTATUS RT_RegOpenKeyExA(
    HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, HKEY* phkResult
){
    ResourceTracker* tracker = getTrackerPointer();

    LSTATUS lStatus = ERROR_SUCCESS;
    errno   lastErr = NO_ERROR;
    for (;;)
    {
        RegOpenKeyExA_t RegOpenKeyExA;
    #ifdef _WIN64
        RegOpenKeyExA = FindAPI(0x189F0999A7259053, 0x4C99200BFC0E770B);
    #elif _WIN32
        RegOpenKeyExA = FindAPI(0xBE726FAA, 0xEAD2E08B);
    #endif
        if (RegOpenKeyExA == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        lStatus = RegOpenKeyExA(
            hKey, lpSubKey, ulOptions, samDesired, phkResult
        );
        if (lStatus != ERROR_SUCCESS)
        {
            break;
        }
        if (!addHandleMu(tracker, *phkResult, SRC_REG_OPEN_KEY_EX_A))
        {
            lastErr = ERR_RESOURCE_ADD_KEY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "RegOpenKeyExA: %s 0x%zX", lpSubKey, *phkResult);
    return lStatus;
}

__declspec(noinline)
LSTATUS RT_RegOpenKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, HKEY* phkResult
){
    ResourceTracker* tracker = getTrackerPointer();

    LSTATUS lStatus = ERROR_SUCCESS;
    errno   lastErr = NO_ERROR;
    for (;;)
    {
        RegOpenKeyExW_t RegOpenKeyExW;
    #ifdef _WIN64
        RegOpenKeyExW = FindAPI(0xC11E19BF67DF5A0F, 0x9CC21D811EA014ED);
    #elif _WIN32
        RegOpenKeyExW = FindAPI(0x4668AB03, 0xC1931B55);
    #endif
        if (RegOpenKeyExW == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        lStatus = RegOpenKeyExW(
            hKey, lpSubKey, ulOptions, samDesired, phkResult
        );
        if (lStatus != ERROR_SUCCESS)
        {
            break;
        }
        if (!addHandleMu(tracker, *phkResult, SRC_REG_OPEN_KEY_EX_W))
        {
            lastErr = ERR_RESOURCE_ADD_KEY;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "RegOpenKeyExW: %ls 0x%zX", lpSubKey, *phkResult);
    return lStatus;
}

__declspec(noinline)
SOCKET RT_WSASocketA(
    int af, int type, int protocol, POINTER lpProtocolInfo, POINTER g, DWORD dwFlags
){
    ResourceTracker* tracker = getTrackerPointer();

    SOCKET hSocket = INVALID_SOCKET;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        WSASocketA_t WSASocketA;
    #ifdef _WIN64
        WSASocketA = FindAPI(0x9423BC8A7F7135CE, 0xBF3CF52071378ED3);
    #elif _WIN32
        WSASocketA = FindAPI(0xA853C263, 0x43B98477);
    #endif
        if (WSASocketA == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        hSocket = WSASocketA(af, type, protocol, lpProtocolInfo, g, dwFlags);
        lastErr = GetLastErrno();
        if (hSocket == INVALID_SOCKET)
        {
            break;
        }
        if (!addHandleMu(tracker, hSocket, SRC_WSA_SOCKET_A))
        {
            lastErr = ERR_RESOURCE_ADD_SOCKET;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "WSASocketA: 0x%zX", hSocket);
    return hSocket;
}

__declspec(noinline)
SOCKET RT_WSASocketW(
    int af, int type, int protocol, POINTER lpProtocolInfo, POINTER g, DWORD dwFlags
){
    ResourceTracker* tracker = getTrackerPointer();

    SOCKET hSocket = INVALID_SOCKET;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        WSASocketA_t WSASocketW;
    #ifdef _WIN64
        WSASocketW = FindAPI(0x7BCE82408C2BFF04, 0xC39F53FE566C687A);
    #elif _WIN32
        WSASocketW = FindAPI(0xE94A63DF, 0xA4F52264);
    #endif
        if (WSASocketW == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        hSocket = WSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
        lastErr = GetLastErrno();
        if (hSocket == INVALID_SOCKET)
        {
            break;
        }
        if (!addHandleMu(tracker, hSocket, SRC_WSA_SOCKET_W))
        {
            lastErr = ERR_RESOURCE_ADD_SOCKET;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "WSASocketW: 0x%zX", hSocket);
    return hSocket;
}

__declspec(noinline)
int RT_WSAIoctl(
    SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, 
    LPVOID lpvOutBuffer, DWORD cbOutBuffer, DWORD* lpcbBytesReturned, 
    POINTER lpOverlapped, POINTER lpCompletionRoutine
){
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return SOCKET_ERROR;
    }

    BOOL  success = false;
    errno lastErr = NO_ERROR;



    if (!RT_Unlock())
    {
        return SOCKET_ERROR;
    }

    if (!success)
    {
        return SOCKET_ERROR;
    }
    return 0;
}

__declspec(noinline)
SOCKET RT_socket(int af, int type, int protocol)
{
    ResourceTracker* tracker = getTrackerPointer();

    SOCKET hSocket = INVALID_SOCKET;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        socket_t socket;
    #ifdef _WIN64
        socket = FindAPI(0x2F4244FE0885F2C3, 0x3AD9A156D89CC096);
    #elif _WIN32
        socket = FindAPI(0xBC5E9C2A, 0x0148A701);
    #endif
        if (socket == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        hSocket = socket(af, type, protocol);
        lastErr = GetLastErrno();
        if (hSocket == INVALID_SOCKET)
        {
            break;
        }
        if (!addHandleMu(tracker, hSocket, SRC_SOCKET))
        {
            lastErr = ERR_RESOURCE_ADD_SOCKET;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "socket: 0x%zX", hSocket);
    return hSocket;
}

__declspec(noinline)
SOCKET RT_accept(SOCKET s, POINTER addr, int* addrlen)
{
    ResourceTracker* tracker = getTrackerPointer();

    SOCKET hSocket = INVALID_SOCKET;
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        accept_t accept;
    #ifdef _WIN64
        accept = FindAPI(0x10D963E47F6DB6B9, 0x8DD31C5FBD824AD8);
    #elif _WIN32
        accept = FindAPI(0x1F94AC37, 0x93C9AB8B);
    #endif
        if (accept == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        hSocket = accept(s, addr, addrlen);
        lastErr = GetLastErrno();
        if (hSocket == INVALID_SOCKET)
        {
            break;
        }
        if (!addHandleMu(tracker, hSocket, SRC_ACCEPT))
        {
            lastErr = ERR_RESOURCE_ADD_SOCKET;
            break;
        }
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "accept: 0x%zX", hSocket);
    return hSocket;
}

__declspec(noinline)
int RT_shutdown(SOCKET s, int how)
{
    ResourceTracker* tracker = getTrackerPointer();

    BOOL  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        closesocket_t closesocket;
    #ifdef _WIN64
        closesocket = FindAPI(0x53A87D9CE52FEC49, 0xBBC0625CD7DA8E92);
    #elif _WIN32
        closesocket = FindAPI(0x224A8165, 0x524B8D52);
    #endif
        if (closesocket == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        int ret = closesocket(hSocket);
        lastErr = GetLastErrno();
        if (ret != 0)
        {
            break;
        }
        delHandleMu(tracker, hSocket, TYPE_CLOSE_SOCKET);
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "closesocket: 0x%zX", hSocket);

    if (!success)
    {
        return SOCKET_ERROR;
    }
    return 0;
}

__declspec(noinline)
BOOL RT_CloseHandle(HANDLE hObject)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return false;
    }

    BOOL  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        bool ok = tracker->CloseHandle(hObject);
        lastErr = GetLastErrno();
        if (!ok)
        {
            break;
        }
        delHandle(tracker, hObject, TYPE_CLOSE_HANDLE);
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    if (!RT_Unlock())
    {
        return false;
    }

    dbg_log("[resource]", "CloseHandle: 0x%zX", hObject);
    return success;
};

__declspec(noinline)
BOOL RT_FindClose(HANDLE hFindFile)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return false;
    }

    BOOL  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        bool ok = tracker->FindClose(hFindFile);
        lastErr = GetLastErrno();
        if (!ok)
        {
            break;
        }
        delHandle(tracker, hFindFile, TYPE_FIND_CLOSE);
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    if (!RT_Unlock())
    {
        return false;
    }

    dbg_log("[resource]", "FindClose: 0x%zX", hFindFile);
    return success;
};

__declspec(noinline)
LSTATUS RT_RegCloseKey(HKEY hKey)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return ERROR_SUCCESS;
    }

    LSTATUS lStatus = ERROR_SUCCESS;
    errno   lastErr = NO_ERROR;
    for (;;)
    {
        RegCloseKey_t RegCloseKey;
    #ifdef _WIN64
        RegCloseKey = FindAPI(0xD73DC3457F3F2267, 0xDE79CCC293884D1C);
    #elif _WIN32
        RegCloseKey = FindAPI(0xB63BD7A6, 0x614CB75F);
    #endif
        if (RegCloseKey == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        lStatus = RegCloseKey(hKey);
        if (lStatus != ERROR_SUCCESS)
        {
            break;
        }
        delHandle(tracker, hKey, TYPE_CLOSE_KEY);
        break;
    }
    SetLastErrno(lastErr);

    if (!RT_Unlock())
    {
        return ERROR_SUCCESS;
    }

    dbg_log("[resource]", "RegCloseKey: 0x%zX", hKey);
    return lStatus;
}

__declspec(noinline)
int RT_closesocket(SOCKET hSocket)
{
    ResourceTracker* tracker = getTrackerPointer();

    BOOL  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        closesocket_t closesocket;
    #ifdef _WIN64
        closesocket = FindAPI(0x53A87D9CE52FEC49, 0xBBC0625CD7DA8E92);
    #elif _WIN32
        closesocket = FindAPI(0x224A8165, 0x524B8D52);
    #endif
        if (closesocket == NULL)
        {
            lastErr = ERR_RESOURCE_API_NOT_FOUND;
            break;
        }
        int ret = closesocket(hSocket);
        lastErr = GetLastErrno();
        if (ret != 0)
        {
            break;
        }
        delHandleMu(tracker, hSocket, TYPE_CLOSE_SOCKET);
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "closesocket: 0x%zX", hSocket);

    if (!success)
    {
        return SOCKET_ERROR;
    }
    return 0;
}

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
    case TYPE_CLOSE_KEY:
        RegCloseKey_t RegCloseKey;
    #ifdef _WIN64
        RegCloseKey = FindAPI(0xB576E6CD0F49BDB2, 0xE696272D1E3E8FE4);
    #elif _WIN32
        RegCloseKey = FindAPI(0x19D4543D, 0xC129A3D6);
    #endif
        if (RegCloseKey != NULL)
        {
            RegCloseKey(hObject);
        }
        break;
    case TYPE_CLOSE_SOCKET:
        closesocket_t closesocket;
    #ifdef _WIN64
        closesocket = FindAPI(0xBCEC2D54FA2DA0C4, 0x14359928896948A4);
    #elif _WIN32
        closesocket = FindAPI(0x8B0243F7, 0x35CA08AD);
    #endif
        if (closesocket != NULL)
        {
            closesocket(hObject);
        }
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
        return WSAEINPROGRESS;
    }

    int   retVal  = WSASYSNOTREADY;
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
        retVal = WSAStartup(wVersionRequired, lpWSAData);
        if (retVal == 0)
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
        return WSAEINPROGRESS;
    }
    return retVal;
}

__declspec(noinline)
int RT_WSACleanup()
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return SOCKET_ERROR;
    }

    int   retVal  = SOCKET_ERROR;
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
        retVal = WSACleanup();
        if (retVal == 0)
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
        return SOCKET_ERROR;
    }
    return retVal;
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

    // reset counter
    tracker->Counters[CTR_WSA_STARTUP] = 0;
    return errno;
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
    int64 numTimers  = 0;
    int64 numFiles   = 0;
    int64 numDirs    = 0;
    int64 numIOCPs   = 0;
    int64 numKeys    = 0;
    int64 numSockets = 0;

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
        case FUNC_CREATE_WAITABLE_TIMER:
            numTimers++;
            break;
        case FUNC_CREATE_FILE:
            numFiles++;
            break;
        case FUNC_FIND_FIRST_FILE:
            numDirs++;
            break;
        case FUNC_CREATE_IOCP:
            numIOCPs++;
            break;
        case FUNC_REG_CREATE_KEY: case FUNC_REG_OPEN_KEY:
            numKeys++;
            break;
        case FUNC_WSA_SOCKET: case FUNC_SOCKET: case FUNC_ACCEPT:
            numSockets++;
            break;
        }
        num++;
    }

    if (!RT_Unlock())
    {
        return false;
    }

    status->NumMutexs         = numMutexs;
    status->NumEvents         = numEvents;
    status->NumSemaphores     = numSemphos;
    status->NumWaitableTimers = numTimers;
    status->NumFiles          = numFiles;
    status->NumDirectories    = numDirs;
    status->NumIOCPs          = numIOCPs;
    status->NumKeys           = numKeys;
    status->NumSockets        = numSockets;
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

    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return false;
    }
    return true;
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

    // try to find api
    RegCloseKey_t RegCloseKey;
    CancelIoEx_t  CancelIoEx;
    shutdown_t    shutdown;
    closesocket_t closesocket;
#ifdef _WIN64
    RegCloseKey = FindAPI(0x51D9FB4FF72F1963, 0xB0265320F46E2304);
    CancelIoEx  = FindAPI(0x06F984CC96939FA7, 0xC97B2F6A0C3413D8);
    shutdown    = FindAPI(0xAB64496EF237CCA4, 0x65EDF9B76AD9A688);
    closesocket = FindAPI(0xD9DD30B81F6B58FF, 0x35D911BB33B68FD1);
#elif _WIN32
    RegCloseKey = FindAPI(0x976649E4, 0xDCEADBCD);
    CancelIoEx  = FindAPI(0x492230DB, 0xF26FEB1B);
    shutdown    = FindAPI(0x850FC0A9, 0x613BCDCB);
    closesocket = FindAPI(0x5E8F4EC0, 0x95F951E5);
#endif

    // close all tracked handles
    List* handles = &tracker->Handles;
    errno error   = NO_ERROR;

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
                error = ERR_RESOURCE_CLOSE_HANDLE;
            }
            break;
        case TYPE_FIND_CLOSE:
            if (!tracker->FindClose(handle->handle))
            {
                error = ERR_RESOURCE_FIND_CLOSE;
            }
            break;
        case TYPE_CLOSE_KEY:
            if (RegCloseKey == NULL)
            {
                break;
            }
            if (RegCloseKey(handle->handle) != ERROR_SUCCESS)
            {
                error = ERR_RESOURCE_CLOSE_KEY;
            }
            break;
        case TYPE_CLOSE_SOCKET:
            if (closesocket == NULL)
            {
                break;
            }
            // try to graceful shutdown
            if (CancelIoEx != NULL) // must after Vista
            {
                CancelIoEx(handle->handle, NULL);
            }
            shutdown(handle->handle, SD_BOTH);
            if (closesocket(handle->handle) != 0)
            {
                error = ERR_RESOURCE_CLOSE_SOCKET;
            }
            break;
        default:
            error = ERR_RESOURCE_INVALID_SRC_TYPE;
            break;
        }
        if (!List_Delete(handles, idx))
        {
            error = ERR_RESOURCE_DELETE_HANDLE;
        }
        num++;
    }

    // about WSACleanup
    errno err = doWSACleanup(tracker);
    if (err != NO_ERROR)
    {
        error = err;
    }

    dbg_log("[resource]", "handles: %zu", handles->Len);
    return error;
}

__declspec(noinline)
errno RT_Clean()
{
    ResourceTracker* tracker = getTrackerPointer();

    // try to find api
    RegCloseKey_t RegCloseKey;
    CancelIoEx_t  CancelIoEx;
    shutdown_t    shutdown;
    closesocket_t closesocket;
#ifdef _WIN64
    RegCloseKey = FindAPI(0xC7AB3649E2BE8396, 0x28F0B94509382351);
    CancelIoEx  = FindAPI(0x06F984CC96939FA7, 0xC97B2F6A0C3413D8);
    shutdown    = FindAPI(0xAB64496EF237CCA4, 0x65EDF9B76AD9A688);
    closesocket = FindAPI(0x0941CD072727D858, 0x67DD2DFFFF2ED396);
#elif _WIN32
    RegCloseKey = FindAPI(0x6370BD08, 0xF9823D25);
    CancelIoEx  = FindAPI(0x492230DB, 0xF26FEB1B);
    shutdown    = FindAPI(0x850FC0A9, 0x613BCDCB);
    closesocket = FindAPI(0x17C2486A, 0xC8ABB537);
#endif

    // close all tracked handles
    List* handles = &tracker->Handles;
    errno error   = NO_ERROR;

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
            if (!tracker->CloseHandle(handle->handle) && error == NO_ERROR)
            {
                error = ERR_RESOURCE_CLOSE_HANDLE;
            }
            break;
        case TYPE_FIND_CLOSE:
            if (!tracker->FindClose(handle->handle) && error == NO_ERROR)
            {
                error = ERR_RESOURCE_FIND_CLOSE;
            }
            break;
        case TYPE_CLOSE_KEY:
            if (RegCloseKey == NULL)
            {
                break;
            }
            if (RegCloseKey(handle->handle) != ERROR_SUCCESS && error == NO_ERROR)
            {
                error = ERR_RESOURCE_CLOSE_KEY;
            }
            break;
        case TYPE_CLOSE_SOCKET:
            if (closesocket == NULL)
            {
                break;
            }
            // try to graceful shutdown
            if (CancelIoEx != NULL) // must after Vista
            {
                CancelIoEx(handle->handle, NULL);
            }
            shutdown(handle->handle, SD_BOTH);
            if (closesocket(handle->handle) != 0 && error == NO_ERROR)
            {
                error = ERR_RESOURCE_CLOSE_SOCKET;
            }
            break;
        default:
            panic(PANIC_UNREACHABLE_CODE);
        }
        num++;
    }

    // about WSACleanup
    errno err = doWSACleanup(tracker);
    if (err != NO_ERROR && error == NO_ERROR)
    {
        error = err;
    }

    // clean handle list
    RandBuffer(handles->Data, List_Size(handles));
    if (!List_Free(handles) && error == NO_ERROR)
    {
        error = ERR_RESOURCE_FREE_HANDLE_LIST;
    }

    // close mutex
    if (!tracker->CloseHandle(tracker->hMutex) && error == NO_ERROR)
    {
        error = ERR_RESOURCE_CLOSE_MUTEX;
    }

    // recover instructions
    if (tracker->NotEraseInstruction)
    {
        if (!recoverTrackerPointer(tracker) && error == NO_ERROR)
        {
            error = ERR_RESOURCE_RECOVER_INST;
        }
    }

    dbg_log("[resource]", "handles: %zu", handles->Len);
    return error;
}
