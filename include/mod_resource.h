#ifndef MOD_RESOURCE_H
#define MOD_RESOURCE_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_ws2_32.h"
#include "context.h"
#include "errno.h"

typedef bool (*ResLockMutex_t)(HANDLE hMutex);
typedef bool (*ResUnlockMutex_t)(HANDLE hMutex);

typedef bool  (*ResLock_t)();
typedef bool  (*ResUnlock_t)();
typedef errno (*ResEncrypt_t)();
typedef errno (*ResDecrypt_t)();
typedef errno (*ResFreeAll_t)();
typedef errno (*ResClean_t)();

typedef struct {
    CreateMutexA_t     CreateMutexA;
    CreateMutexW_t     CreateMutexW;
    CreateEventA_t     CreateEventA;
    CreateEventW_t     CreateEventW;
    CreateFileA_t      CreateFileA;
    CreateFileW_t      CreateFileW;
    FindFirstFileA_t   FindFirstFileA;
    FindFirstFileW_t   FindFirstFileW;
    FindFirstFileExA_t FindFirstFileExA;
    FindFirstFileExW_t FindFirstFileExW;
    CloseHandle_t      CloseHandle;
    FindClose_t        FindClose;

    WSAStartup_t WSAStartup;
    WSACleanup_t WSACleanup;

    ResLockMutex_t   LockMutex;
    ResUnlockMutex_t UnlockMutex;

    ResLock_t    Lock;
    ResUnlock_t  Unlock;
    ResEncrypt_t Encrypt;
    ResDecrypt_t Decrypt;
    ResFreeAll_t FreeAll;
    ResClean_t   Clean;
} ResourceTracker_M;

ResourceTracker_M* InitResourceTracker(Context* context);

#endif // MOD_RESOURCE_H
