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
#include "layout.h"
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

    // store HashAPI with spoof call
    FindAPI_t FindAPI;

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

    // Cached API addresses
    CancelIoEx_t CancelIoEx;

    RegCreateKeyA_t   RegCreateKeyA;
    RegCreateKeyW_t   RegCreateKeyW;
    RegCreateKeyExA_t RegCreateKeyExA;
    RegCreateKeyExW_t RegCreateKeyExW;
    RegOpenKeyA_t     RegOpenKeyA;
    RegOpenKeyW_t     RegOpenKeyW;
    RegOpenKeyExA_t   RegOpenKeyExA;
    RegOpenKeyExW_t   RegOpenKeyExW;
    RegCloseKey_t     RegCloseKey;

    WSAStartup_t  WSAStartup;
    WSACleanup_t  WSACleanup;
    WSASocketA_t  WSASocketA;
    WSASocketW_t  WSASocketW;
    WSAIoctl_t    WSAIoctl;
    socket_t      socket;
    accept_t      accept;
    shutdown_t    shutdown;
    closesocket_t closesocket;

    // protect data
    HANDLE hMutex;

    // store all tracked Handles
    List Handles;
    byte HandlesKey[CRYPTO_KEY_SIZE];
    byte HandlesIV [CRYPTO_IV_SIZE];

    // store all resource counters
    int64 Counters[1];
} ResourceTracker;

// methods for API redirector
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
bool RT_LockEvent(HANDLE hEvent);
bool RT_UnlockEvent(HANDLE hEvent);
bool RT_LockSemaphore(HANDLE hSemaphore);
bool RT_UnlockSemaphore(HANDLE hSemaphore);
bool RT_LockWaitableTimer(HANDLE hTimer);
bool RT_UnlockWaitableTimer(HANDLE hTimer);
bool RT_LockFile(HANDLE hFile);
bool RT_UnlockFile(HANDLE hFile);
bool RT_GetStatus(RT_Status* status);
bool RT_FreeAllMu();

// methods for runtime
bool  RT_Lock();
bool  RT_Unlock();
errno RT_Encrypt();
errno RT_Decrypt();
void  RT_Flush();
bool  RT_FlushMu();
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

static void  tryToFindAPI();
static errno doWSACleanup();

ResourceTracker_M* InitResourceTracker(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr trackerAddr = addr + LAYOUT_RT_STRUCT + RandUintN(addr, 128);
    uintptr moduleAddr  = addr + LAYOUT_RT_MODULE + RandUintN(addr, 128);
    // allocate tracker memory
    ResourceTracker* tracker = (ResourceTracker*)trackerAddr;
    mem_init(tracker, sizeof(ResourceTracker));
    // store options
    tracker->NotEraseInstruction = context->NotEraseInstruction;
    // store HashAPI method
    tracker->FindAPI = context->FindAPI;
    // initialize tracker
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
    // methods for API redirector
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
    module->LockMutex           = GetFuncAddr(&RT_LockMutex);
    module->UnlockMutex         = GetFuncAddr(&RT_UnlockMutex);
    module->LockEvent           = GetFuncAddr(&RT_LockEvent);
    module->UnlockEvent         = GetFuncAddr(&RT_UnlockEvent);
    module->LockSemaphore       = GetFuncAddr(&RT_LockSemaphore);
    module->UnlockSemaphore     = GetFuncAddr(&RT_UnlockSemaphore);
    module->LockWaitableTimer   = GetFuncAddr(&RT_LockWaitableTimer);
    module->UnlockWaitableTimer = GetFuncAddr(&RT_UnlockWaitableTimer);
    module->LockFile            = GetFuncAddr(&RT_LockFile);
    module->UnlockFile          = GetFuncAddr(&RT_UnlockFile);
    module->GetStatus           = GetFuncAddr(&RT_GetStatus);
    module->FreeAllMu           = GetFuncAddr(&RT_FreeAllMu);
    // methods for runtime
    module->Lock    = GetFuncAddr(&RT_Lock);
    module->Unlock  = GetFuncAddr(&RT_Unlock);
    module->Encrypt = GetFuncAddr(&RT_Encrypt);
    module->Decrypt = GetFuncAddr(&RT_Decrypt);
    module->Flush   = GetFuncAddr(&RT_Flush);
    module->FlushMu = GetFuncAddr(&RT_FlushMu);
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
        uint mHash; uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x18557173A3FF60DF, 0x82E2C7817D6985C2, 0x5854A1BC5CB98207 }, // CreateMutexA
        { 0xC3ADA377C4F82801, 0x0D27D1CC083E59BC, 0x64901F0A3DE7DAAD }, // CreateMutexW
        { 0x528A29C1320E4677, 0x2229D75AB9596D3B, 0x0F183BC92FF08B5B }, // CreateMutexExA
        { 0xCA930D7CB5651753, 0xAD498782299971C1, 0x809AB547A56D43DD }, // CreateMutexExW
        { 0x8FAB0277D2B5C4AD, 0x39B7648853350147, 0xD24B7D700589CAFF }, // CreateEventA
        { 0x977E44CCA46E915E, 0xCAE2C352577D8F17, 0xF10A0EEAA2A723BF }, // CreateEventW
        { 0xC265622EE8AE58E2, 0x9835563D2AD1B841, 0xC3D8C0B4B533570F }, // CreateEventExA
        { 0xEA0E4D94515ACB56, 0x479469500BC8031D, 0x80E6FCEF71BA2651 }, // CreateEventExW
        { 0x9851FFD6885CE173, 0x5B35C6E9766E9C62, 0x01874A5ADBB5A774 }, // CreateSemaphoreA
        { 0xC262E20BBEAEB68D, 0xA7AE1089ECA5067C, 0x228570F9458C9F38 }, // CreateSemaphoreW
        { 0x5CB8BBCB1EBF5E4D, 0x2BA959BCCDD4FC92, 0xDA628DB473E27500 }, // CreateSemaphoreExA
        { 0xD392AF76603A5E90, 0x64D429F55A541308, 0x59EBF327FBE86941 }, // CreateSemaphoreExW
        { 0xA0234B679FE50DF7, 0x35A80E36BDC1AC73, 0xE10894F523E4FDD5 }, // CreateWaitableTimerA
        { 0xC1D01AD9FFDBCD8A, 0x35B069801C4EE076, 0x81251C26497B0215 }, // CreateWaitableTimerW
        { 0xD0223DF928D65CF5, 0x4CAB2ACD0F728D0A, 0x813C63DABDEF833A }, // CreateWaitableTimerExA
        { 0x7B0752F23CD8963A, 0xF7903FC62374C665, 0x237967C244D53694 }, // CreateWaitableTimerExW
        { 0xAC2853EFD178E5D2, 0xB3B6BF59531820F1, 0xAEA3520EDB170379 }, // CreateFileA
        { 0x61F134B5F496B34D, 0x1BB3665A2B6EB94C, 0xD749F5B4B7A1CA87 }, // CreateFileW
        { 0x9AA3A0F999CD7815, 0x4368EC23E1BD7B7C, 0x3A04BD90C36C1D0C }, // FindFirstFileA
        { 0x3E6C94BFC8E8CEF7, 0x0F8E7447E87C3E16, 0x84BFE076C2595727 }, // FindFirstFileW
        { 0x28BC7AE1E227C488, 0xD988A68E2AA9C7B8, 0xD9AE3BCEDB9370FF }, // FindFirstFileExA
        { 0x352D40E9FCBDCA23, 0x4B3937CFBF5523D9, 0x10A5C6391A59309E }, // FindFirstFileExW
        { 0xEEE6CC777DE68F08, 0xB3D2B1E17472956B, 0xEAADF7C8131B85D2 }, // FindClose
        { 0x6DB80C3F17CB324C, 0xA9DE20B0EC6F90B4, 0xF1870B73E05CB84C }, // CreateIoCompletionPort
    };
#elif _WIN32
    {
        { 0x01941FA1, 0x8A911392, 0xCD978D9B }, // CreateMutexA
        { 0x4F8D79D5, 0x0B198EF8, 0x75914A0C }, // CreateMutexW
        { 0x439D900C, 0x827BEBBC, 0x35FA9598 }, // CreateMutexExA
        { 0x53291733, 0x569872A3, 0xD871BDF0 }, // CreateMutexExW
        { 0x01649CDF, 0x6471A6BE, 0x93C1F48F }, // CreateEventA
        { 0xF5732A91, 0x5C900A9C, 0x88C4F7C2 }, // CreateEventW
        { 0xF51D591C, 0x7C041E00, 0x489E0651 }, // CreateEventExA
        { 0xF0639836, 0x4EDE879A, 0x3935C43E }, // CreateEventExW
        { 0x0D8DA7A4, 0x8FD5542B, 0x6492CF88 }, // CreateSemaphoreA
        { 0xB73DAB34, 0x07D8C046, 0x82FD3301 }, // CreateSemaphoreW
        { 0xDCCEA139, 0x43BAC57C, 0x6CD9AB6E }, // CreateSemaphoreExA
        { 0xAA60305F, 0x97FFFDD5, 0x9AC87B47 }, // CreateSemaphoreExW
        { 0x5B220EED, 0x858B7C70, 0x7AF18636 }, // CreateWaitableTimerA
        { 0xD3637677, 0x7405A69F, 0x16C60103 }, // CreateWaitableTimerW
        { 0x86C82381, 0x78D2EDFC, 0xA28E2C09 }, // CreateWaitableTimerExA
        { 0xB90EED9A, 0xF8055853, 0x52763229 }, // CreateWaitableTimerExW
        { 0xCFDD5352, 0x395AFF95, 0xA697F6D0 }, // CreateFileA
        { 0xA27950C4, 0x5278B69C, 0x4F7DE081 }, // CreateFileW
        { 0x7790F793, 0x7F124DC1, 0xBADE79B5 }, // FindFirstFileA
        { 0x42AC967A, 0x7ABCF3F7, 0x3C6A3022 }, // FindFirstFileW
        { 0xD80C29F0, 0x2BB62EB9, 0x9F243303 }, // FindFirstFileExA
        { 0x18422147, 0x50EAC3A5, 0xBC4BC36A }, // FindFirstFileExW
        { 0x74056D09, 0xFFA89CE3, 0x6E906B38 }, // FindClose
        { 0x8692E8C4, 0x48D73CFB, 0xD525ECEE }, // CreateIoCompletionPort
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
        // try to get API address from cache
        RegCreateKeyA_t RegCreateKeyA = tracker->RegCreateKeyA;
        if (RegCreateKeyA == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x96A609C4644380C8;
            uint pHash = 0xCCA21B11ED2032A9;
            uint hhKey = 0xB712895B7F4E3137;
        #elif _WIN32
            uint mHash = 0x32484FCA;
            uint pHash = 0xF1BBFA85;
            uint hhKey = 0xB34D4A92;
        #endif
            RegCreateKeyA = tracker->FindAPI(mHash, pHash, hhKey);
            if (RegCreateKeyA == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->RegCreateKeyA = RegCreateKeyA;
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
        // try to get API address from cache
        RegCreateKeyW_t RegCreateKeyW = tracker->RegCreateKeyW;
        if (RegCreateKeyW == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x7F1EBB0B5BF08964;
            uint pHash = 0xF622574D5E02E9DB;
            uint hhKey = 0x4736E3EDE9B87BD7;
        #elif _WIN32
            uint mHash = 0x380E972A;
            uint pHash = 0xF78241FB;
            uint hhKey = 0x01A5FA89;
        #endif
            RegCreateKeyW = tracker->FindAPI(mHash, pHash, hhKey);
            if (RegCreateKeyW == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->RegCreateKeyW = RegCreateKeyW;
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
        // try to get API address from cache
        RegCreateKeyExA_t RegCreateKeyExA = tracker->RegCreateKeyExA;
        if (RegCreateKeyExA == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x10C1CC6DFBC96F56;
            uint pHash = 0x3B563DEE011D55EA;
            uint hhKey = 0x5277163B5A7EE259;
        #elif _WIN32
            uint mHash = 0xB1B2BFDB;
            uint pHash = 0x6E3FE5C2;
            uint hhKey = 0x1E21042F;
        #endif
            RegCreateKeyExA = tracker->FindAPI(mHash, pHash, hhKey);
            if (RegCreateKeyExA == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->RegCreateKeyExA = RegCreateKeyExA;
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
        // try to get API address from cache
        RegCreateKeyExW_t RegCreateKeyExW = tracker->RegCreateKeyExW;
        if (RegCreateKeyExW == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xA440EA2E6B7DA1CB;
            uint pHash = 0xFE239E0C5881EF75;
            uint hhKey = 0x8B1F06BAC9BC0FB4;
        #elif _WIN32
            uint mHash = 0xD59266B5;
            uint pHash = 0x29E2F4EF;
            uint hhKey = 0xF4DED6CA;
        #endif
            RegCreateKeyExW = tracker->FindAPI(mHash, pHash, hhKey);
            if (RegCreateKeyExW == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->RegCreateKeyExW = RegCreateKeyExW;
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
        // try to get API address from cache
        RegOpenKeyA_t RegOpenKeyA = tracker->RegOpenKeyA;
        if (RegOpenKeyA == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xFA7EA8AF31135B54;
            uint pHash = 0x22D8B65730135F58;
            uint hhKey = 0x60FDAD6E29C89B00;
        #elif _WIN32
            uint mHash = 0x5FE996AD;
            uint pHash = 0x1FADD8BD;
            uint hhKey = 0x94E3EBAE;
        #endif
            RegOpenKeyA = tracker->FindAPI(mHash, pHash, hhKey);
            if (RegOpenKeyA == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->RegOpenKeyA = RegOpenKeyA;
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
        // try to get API address from cache
        RegOpenKeyW_t RegOpenKeyW = tracker->RegOpenKeyW;
        if (RegOpenKeyW == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x38F57CDA6CA1BF80;
            uint pHash = 0x5D2DA71712AD845F;
            uint hhKey = 0xF3F6F1F37138E467;
        #elif _WIN32
            uint mHash = 0x7370A861;
            uint pHash = 0x4D8DD02E;
            uint hhKey = 0x6B7B9626;
        #endif
            RegOpenKeyW = tracker->FindAPI(mHash, pHash, hhKey);
            if (RegOpenKeyW == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->RegOpenKeyW = RegOpenKeyW;
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
        // try to get API address from cache
        RegOpenKeyExA_t RegOpenKeyExA = tracker->RegOpenKeyExA;
        if (RegOpenKeyExA == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x2AE0601CC475EB1A;
            uint pHash = 0xAAE3DFB521796E88;
            uint hhKey = 0x22106841BD214082;
        #elif _WIN32
            uint mHash = 0xF2834E35;
            uint pHash = 0x93E426ED;
            uint hhKey = 0xFAB77358;
        #endif
            RegOpenKeyExA = tracker->FindAPI(mHash, pHash, hhKey);
            if (RegOpenKeyExA == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->RegOpenKeyExA = RegOpenKeyExA;
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
        // try to get API address from cache
        RegOpenKeyExW_t RegOpenKeyExW = tracker->RegOpenKeyExW;
        if (RegOpenKeyExW == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x532BAEA98DA2BA54;
            uint pHash = 0x7509BA27645BDAD3;
            uint hhKey = 0x55CCE92A674BE515;
        #elif _WIN32
            uint mHash = 0xB68F1718;
            uint pHash = 0x57EFEFE7;
            uint hhKey = 0x7B845953;
        #endif
            RegOpenKeyExW = tracker->FindAPI(mHash, pHash, hhKey);
            if (RegOpenKeyExW == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->RegOpenKeyExW = RegOpenKeyExW;
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
        // try to get API address from cache
        WSASocketA_t WSASocketA = tracker->WSASocketA;
        if (WSASocketA == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xB424460D6D3EC693;
            uint pHash = 0x0F5D3E03A731E351;
            uint hKey  = 0x6E9AA870F2F9AC99;
        #elif _WIN32
            uint mHash = 0x1408823C;
            uint pHash = 0x9F86512A;
            uint hKey  = 0x64A5FFCA;
        #endif
            WSASocketA = tracker->FindAPI(mHash, pHash, hKey);
            if (WSASocketA == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->WSASocketA = WSASocketA;
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
        // try to get API address from cache
        WSASocketA_t WSASocketW = tracker->WSASocketW;
        if (WSASocketW == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x30A392BC95981448;
            uint pHash = 0xC43AA717D9415F71;
            uint hKey  = 0x30FB0B12069C9DFB;
        #elif _WIN32
            uint mHash = 0xAEDE20DD;
            uint pHash = 0x780CEC7E;
            uint hKey  = 0xA75A0D12;
        #endif
            WSASocketW = tracker->FindAPI(mHash, pHash, hKey);
            if (WSASocketW == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->WSASocketW = WSASocketW;
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
    for (;;)
    {
        // try to get API address from cache
        WSAIoctl_t WSAIoctl = tracker->WSAIoctl;
        if (WSAIoctl == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x90AE148F1075C6EC;
            uint pHash = 0x2CA84E695E895E24;
            uint hKey  = 0xC7DAAAC503BA2B8F;
        #elif _WIN32
            uint mHash = 0xD77C37E7;
            uint pHash = 0xC8C2BB8E;
            uint hKey  = 0x284C99AE;
        #endif
            WSAIoctl = tracker->FindAPI(mHash, pHash, hKey);
            if (WSAIoctl == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->WSAIoctl = WSAIoctl;
        }
        int ret = WSAIoctl(
            s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer,
            cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine
        );
        lastErr = GetLastErrno();
        if (ret != 0)
        {
            break;
        }
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "WSAIoctl: 0x%zX, 0x%d", s, dwIoControlCode);

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
        // try to get API address from cache
        socket_t socket = tracker->socket;
        if (socket == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xEEC793C0338C998B;
            uint pHash = 0xAFC82792DA88601D;
            uint hKey  = 0xEA9BFB6E5BB5CAA9;
        #elif _WIN32
            uint mHash = 0x7F221CDB;
            uint pHash = 0x73884599;
            uint hKey  = 0x496D9B55;
        #endif
            socket = tracker->FindAPI(mHash, pHash, hKey);
            if (socket == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->socket = socket;
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
        // try to get API address from cache
        accept_t accept = tracker->accept;
        if (accept == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x3F0E2AACEE8BCF80;
            uint pHash = 0x6BF8E08668FFE9F8;
            uint hKey  = 0x974521B6A59B3E8A;
        #elif _WIN32
            uint mHash = 0xA4B36517;
            uint pHash = 0x639BA467;
            uint hKey  = 0x37B5BE81;
        #endif
            accept = tracker->FindAPI(mHash, pHash, hKey);
            if (accept == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->accept = accept;
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

    if (!RT_Lock())
    {
        return SOCKET_ERROR;
    }

    BOOL  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        // try to get API address from cache
        shutdown_t shutdown = tracker->shutdown;
        if (shutdown == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xA37CB252069AFC45;
            uint pHash = 0x958D1BF7675DF3C6;
            uint hKey  = 0x8FB0DF6A8F4B0164;
        #elif _WIN32
            uint mHash = 0x00B6237F;
            uint pHash = 0x29BC24ED;
            uint hKey  = 0x70911362;
        #endif
            shutdown = tracker->FindAPI(mHash, pHash, hKey);
            if (shutdown == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->shutdown = shutdown;
        }
        int ret = shutdown(s, how);
        lastErr = GetLastErrno();
        if (ret != 0)
        {
            break;
        }
        success = true;
        break;
    }
    SetLastErrno(lastErr);

    dbg_log("[resource]", "shutdown: 0x%zX", s);

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
        // try to get API address from cache
        RegCloseKey_t RegCloseKey = tracker->RegCloseKey;
        if (RegCloseKey == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xBF61DC9DB58F2119;
            uint pHash = 0x634B2EA7763B50E7;
            uint hhKey = 0x1E92D01ACD546FAA;
        #elif _WIN32
            uint mHash = 0x21897061;
            uint pHash = 0x05759268;
            uint hhKey = 0x6DD08644;
        #endif
            RegCloseKey = tracker->FindAPI(mHash, pHash, hhKey);
            if (RegCloseKey == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->RegCloseKey = RegCloseKey;
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
        // try to get API address from cache
        closesocket_t closesocket = tracker->closesocket;
        if (closesocket == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xEF92E9B35ECEA6BA;
            uint pHash = 0xEE5724C40D2CCCD2;
            uint hKey  = 0xA7D1387163EE7961;
        #elif _WIN32
            uint mHash = 0x5585015C;
            uint pHash = 0xE4D20008;
            uint hKey  = 0xE6423398;
        #endif
            closesocket = tracker->FindAPI(mHash, pHash, hKey);
            if (closesocket == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->closesocket = closesocket;
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

    uint mHash;
    uint pHash;
    uint hKey; 

    switch (source & TYPE_MASK)
    {
    case TYPE_CLOSE_HANDLE:
        tracker->CloseHandle(hObject);
        break;
    case TYPE_FIND_CLOSE:
        tracker->FindClose(hObject);
        break;
    case TYPE_CLOSE_KEY:
    #ifdef _WIN64
        mHash = 0xBF61DC9DB58F2119;
        pHash = 0x634B2EA7763B50E7;
        hKey  = 0x1E92D01ACD546FAA;
    #elif _WIN32
        mHash = 0x21897061;
        pHash = 0x05759268;
        hKey  = 0x6DD08644;
    #endif
        RegCloseKey_t RegCloseKey = tracker->FindAPI(mHash, pHash, hKey);
        if (RegCloseKey != NULL)
        {
            RegCloseKey(hObject);
        }
        break;
    case TYPE_CLOSE_SOCKET:
    #ifdef _WIN64
        mHash = 0xEF92E9B35ECEA6BA;
        pHash = 0xEE5724C40D2CCCD2;
        hKey  = 0xA7D1387163EE7961;
    #elif _WIN32
        mHash = 0x5585015C;
        pHash = 0xE4D20008;
        hKey  = 0xE6423398;
    #endif
        closesocket_t closesocket = tracker->FindAPI(mHash, pHash, hKey);
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
        // try to get API address from cache
        WSAStartup_t WSAStartup = tracker->WSAStartup;
        if (WSAStartup == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xEA897E8A6C57363D;
            uint pHash = 0x2A32B9468CED7FC7;
            uint hKey  = 0xADEBF9D727119E08;
        #elif _WIN32
            uint mHash = 0xFCDD5F57;
            uint pHash = 0x6C10A1BE;
            uint hKey  = 0x36C5B1D5;
        #endif
            WSAStartup = tracker->FindAPI(mHash, pHash, hKey);
            if (WSAStartup == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->WSAStartup = WSAStartup;
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
        // try to get API address from cache
        WSACleanup_t WSACleanup = tracker->WSACleanup;
        if (WSACleanup == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x4315CA7C2DE0953F;
            uint pHash = 0xFAA60831E40346AA;
            uint hKey  = 0xEB60CFC4E8AF64CE;
        #elif _WIN32
            uint mHash = 0x3F43DBA5;
            uint pHash = 0x2F28803E;
            uint hKey  = 0xFEC6856A;
        #endif
            WSACleanup = tracker->FindAPI(mHash, pHash, hKey);
            if (WSACleanup == NULL)
            {
                lastErr = ERR_RESOURCE_API_NOT_FOUND;
                break;
            }
            tracker->WSACleanup = WSACleanup;
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
bool RT_LockEvent(HANDLE hEvent)
{
    bool success = setHandleLocker(hEvent, FUNC_CREATE_EVENT, true);
    dbg_log("[resource]", "lock event: 0x%zX", hEvent);
    return success;
}

__declspec(noinline)
bool RT_UnlockEvent(HANDLE hEvent)
{
    bool success = setHandleLocker(hEvent, FUNC_CREATE_EVENT, false);
    dbg_log("[resource]", "unlock event: 0x%zX", hEvent);
    return success;
}

__declspec(noinline)
bool RT_LockSemaphore(HANDLE hSemaphore)
{
    bool success = setHandleLocker(hSemaphore, FUNC_CREATE_SEMAPHORE, true);
    dbg_log("[resource]", "lock semaphore: 0x%zX", hSemaphore);
    return success;
}

__declspec(noinline)
bool RT_UnlockSemaphore(HANDLE hSemaphore)
{
    bool success = setHandleLocker(hSemaphore, FUNC_CREATE_SEMAPHORE, false);
    dbg_log("[resource]", "unlock semaphore: 0x%zX", hSemaphore);
    return success;
}

__declspec(noinline)
bool RT_LockWaitableTimer(HANDLE hTimer)
{
    bool success = setHandleLocker(hTimer, FUNC_CREATE_WAITABLE_TIMER, true);
    dbg_log("[resource]", "lock timer: 0x%zX", hTimer);
    return success;
}

__declspec(noinline)
bool RT_UnlockWaitableTimer(HANDLE hTimer)
{
    bool success = setHandleLocker(hTimer, FUNC_CREATE_WAITABLE_TIMER, false);
    dbg_log("[resource]", "unlock timer: 0x%zX", hTimer);
    return success;
}

__declspec(noinline)
bool RT_LockFile(HANDLE hFile)
{
    bool success = setHandleLocker(hFile, FUNC_CREATE_FILE, true);
    dbg_log("[resource]", "lock file: 0x%zX", hFile);
    return success;
}

__declspec(noinline)
bool RT_UnlockFile(HANDLE hFile)
{
    bool success = setHandleLocker(hFile, FUNC_CREATE_FILE, false);
    dbg_log("[resource]", "unlock file: 0x%zX", hFile);
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
    int64 numRegKeys = 0;
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
            numRegKeys++;
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
    status->NumRegKeys        = numRegKeys;
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
void RT_Flush()
{
    ResourceTracker* tracker = getTrackerPointer();

    tracker->CancelIoEx = NULL;

    tracker->RegCreateKeyA   = NULL;
    tracker->RegCreateKeyW   = NULL;
    tracker->RegCreateKeyExA = NULL;
    tracker->RegCreateKeyExW = NULL;
    tracker->RegOpenKeyA     = NULL;
    tracker->RegOpenKeyW     = NULL;
    tracker->RegOpenKeyExA   = NULL;
    tracker->RegOpenKeyExW   = NULL;
    tracker->RegCloseKey     = NULL;

    tracker->WSAStartup  = NULL;
    tracker->WSACleanup  = NULL;
    tracker->WSASocketA  = NULL;
    tracker->WSASocketW  = NULL;
    tracker->WSAIoctl    = NULL;
    tracker->socket      = NULL;
    tracker->accept      = NULL;
    tracker->shutdown    = NULL;
    tracker->closesocket = NULL;
}

__declspec(noinline)
bool RT_FlushMu()
{
    if (!RT_Lock())
    {
        return false;
    }

    RT_Flush();

    if (!RT_Unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
errno RT_FreeAll()
{
    ResourceTracker* tracker = getTrackerPointer();

    tryToFindAPI();
    CancelIoEx_t  CancelIoEx  = tracker->CancelIoEx;
    RegCloseKey_t RegCloseKey = tracker->RegCloseKey;
    shutdown_t    shutdown    = tracker->shutdown;
    closesocket_t closesocket = tracker->closesocket;

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
    errno err = doWSACleanup();
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

    tryToFindAPI();
    CancelIoEx_t  CancelIoEx  = tracker->CancelIoEx;
    RegCloseKey_t RegCloseKey = tracker->RegCloseKey;
    shutdown_t    shutdown    = tracker->shutdown;
    closesocket_t closesocket = tracker->closesocket;

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
            if (shutdown == NULL || closesocket == NULL)
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
    errno err = doWSACleanup();
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

static void tryToFindAPI()
{
    ResourceTracker* tracker = getTrackerPointer();

    typedef struct { 
        uint mHash; uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xC4984645B356A7CA, 0x501838FB2F515443, 0x13F9E474C15125B2 }, // CancelIoEx
        { 0x4E6024F14E9301CF, 0x54C3240233CCD66A, 0x3BF5EF169E089B09 }, // RegCloseKey
        { 0x424EA1F161C7EF34, 0x1221B341D24D8989, 0xCE263A026A2173CA }, // shutdown
        { 0xF4A81300A6A78A79, 0x9CDA1B81F057D32B, 0xB46F9B5F228665A7 }, // closesocket
    };
#elif _WIN32
    {
        { 0xBE5D22C7, 0xA935663D, 0x02DF2D58 }, // CancelIoEx
        { 0xE3B65E24, 0x5649F184, 0xAA804765 }, // RegCloseKey
        { 0xAF47C532, 0x9F18D3A7, 0xE91CDB79 }, // shutdown
        { 0x7C67CD01, 0x2B26FADD, 0xC168AE5E }, // closesocket
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item  = list[i];
        list[i].proc = tracker->FindAPI(item.mHash, item.pHash, item.hKey);
    }
    tracker->CancelIoEx  = list[0x00].proc;
    tracker->RegCloseKey = list[0x01].proc;
    tracker->shutdown    = list[0x02].proc;
    tracker->closesocket = list[0x03].proc;
}

static errno doWSACleanup()
{
    ResourceTracker* tracker = getTrackerPointer();

#ifdef _WIN64
    uint mHash = 0x4315CA7C2DE0953F;
    uint pHash = 0xFAA60831E40346AA;
    uint hKey  = 0xEB60CFC4E8AF64CE;
#elif _WIN32
    uint mHash = 0x3F43DBA5;
    uint pHash = 0x2F28803E;
    uint hKey  = 0xFEC6856A;
#endif
    WSACleanup_t WSACleanup = tracker->FindAPI(mHash, pHash, hKey);
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
