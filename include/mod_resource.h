#ifndef MOD_RESOURCE_H
#define MOD_RESOURCE_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_advapi32.h"
#include "dll_ws2_32.h"
#include "errno.h"
#include "context.h"

typedef struct {
    int64 NumMutexs;
    int64 NumEvents;
    int64 NumSemaphores;
    int64 NumWaitableTimers;
    int64 NumFiles;
    int64 NumDirectories;
    int64 NumIOCPs;
    int64 NumKeys;
    int64 NumSockets;
} RT_Status;

typedef bool (*ResLockMutex_t)(HANDLE hMutex);
typedef bool (*ResUnlockMutex_t)(HANDLE hMutex);
typedef bool (*ResLockEvent_t)(HANDLE hEvent);
typedef bool (*ResUnlockEvent_t)(HANDLE hEvent);
typedef bool (*ResLockSemaphore_t)(HANDLE hSemaphore);
typedef bool (*ResUnlockSemaphore_t)(HANDLE hSemaphore);
typedef bool (*ResLockWaitableTimer_t)(HANDLE hTimer);
typedef bool (*ResUnlockWaitableTimer_t)(HANDLE hTimer);
typedef bool (*ResLockFile_t)(HANDLE hFile);
typedef bool (*ResUnlockFile_t)(HANDLE hFile);
typedef bool (*ResGetStatus_t)(RT_Status* status);
typedef bool (*ResFreeAllMu_t)();

typedef bool  (*ResLock_t)();
typedef bool  (*ResUnlock_t)();
typedef errno (*ResEncrypt_t)();
typedef errno (*ResDecrypt_t)();
typedef void  (*ResFlush_t)();
typedef bool  (*ResFlushMu_t)();
typedef errno (*ResFreeAll_t)();
typedef errno (*ResClean_t)();

typedef struct {
    // for API redirector
    CreateMutexA_t   CreateMutexA;
    CreateMutexW_t   CreateMutexW;
    CreateMutexExA_t CreateMutexExA;
    CreateMutexExW_t CreateMutexExW;

    CreateEventA_t   CreateEventA;
    CreateEventW_t   CreateEventW;
    CreateEventExA_t CreateEventExA;
    CreateEventExW_t CreateEventExW;

    CreateSemaphoreA_t   CreateSemaphoreA;
    CreateSemaphoreW_t   CreateSemaphoreW;
    CreateSemaphoreExA_t CreateSemaphoreExA;
    CreateSemaphoreExW_t CreateSemaphoreExW;

    CreateWaitableTimerA_t   CreateWaitableTimerA;
    CreateWaitableTimerW_t   CreateWaitableTimerW;
    CreateWaitableTimerExA_t CreateWaitableTimerExA;
    CreateWaitableTimerExW_t CreateWaitableTimerExW;

    CreateFileA_t CreateFileA;
    CreateFileW_t CreateFileW;

    FindFirstFileA_t   FindFirstFileA;
    FindFirstFileW_t   FindFirstFileW;
    FindFirstFileExA_t FindFirstFileExA;
    FindFirstFileExW_t FindFirstFileExW;

    CreateIoCompletionPort_t CreateIoCompletionPort;

    // for lazy API redirector
    RegCreateKeyA_t   RegCreateKeyA;
    RegCreateKeyW_t   RegCreateKeyW;
    RegCreateKeyExA_t RegCreateKeyExA;
    RegCreateKeyExW_t RegCreateKeyExW;
    RegOpenKeyA_t     RegOpenKeyA;
    RegOpenKeyW_t     RegOpenKeyW;
    RegOpenKeyExA_t   RegOpenKeyExA;
    RegOpenKeyExW_t   RegOpenKeyExW;

    WSASocketA_t WSASocketA;
    WSASocketW_t WSASocketW;
    WSAIoctl_t   WSAIoctl;
    socket_t     socket;
    accept_t     accept;
    shutdown_t   shutdown;

    // about clean redirector
    CloseHandle_t CloseHandle;
    FindClose_t   FindClose;
    RegCloseKey_t RegCloseKey;
    closesocket_t closesocket;

    // about lazy clean redirector
    WSAStartup_t WSAStartup;
    WSACleanup_t WSACleanup;

    // for user
    ResLockMutex_t           LockMutex;
    ResUnlockMutex_t         UnlockMutex;
    ResLockEvent_t           LockEvent;
    ResUnlockEvent_t         UnlockEvent;
    ResLockSemaphore_t       LockSemaphore;
    ResUnlockSemaphore_t     UnlockSemaphore;
    ResLockWaitableTimer_t   LockWaitableTimer;
    ResUnlockWaitableTimer_t UnlockWaitableTimer;
    ResLockFile_t            LockFile;
    ResUnlockFile_t          UnlockFile;
    ResGetStatus_t           GetStatus;
    ResFreeAllMu_t           FreeAllMu;

    // for runtime internal usage
    ResLock_t    Lock;
    ResUnlock_t  Unlock;
    ResEncrypt_t Encrypt;
    ResDecrypt_t Decrypt;
    ResFlush_t   Flush;
    ResFlushMu_t FlushMu;
    ResFreeAll_t FreeAll;
    ResClean_t   Clean;

    // data for sysmon
    HANDLE hMutex;
} ResourceTracker_M;

ResourceTracker_M* InitResourceTracker(Context* context);

#endif // MOD_RESOURCE_H
