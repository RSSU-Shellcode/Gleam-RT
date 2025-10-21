#ifndef MOD_LIBRARY_H
#define MOD_LIBRARY_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "errno.h"
#include "context.h"

#define HMODULE_GLEAM_RT ((HMODULE)(0x00001234))

typedef struct {
    int64 NumModules;
} LT_Status;

typedef bool (*LibLockModule_t)(HMODULE hModule);
typedef bool (*LibUnlockModule_t)(HMODULE hModule);
typedef bool (*LibGetStatus_t)(LT_Status* status);
typedef bool (*LibFreeAllMu_t)();

typedef bool  (*LibLock_t)();
typedef bool  (*LibUnlock_t)();
typedef errno (*LibEncrypt_t)();
typedef errno (*LibDecrypt_t)();
typedef errno (*LibFreeAll_t)();
typedef errno (*LibClean_t)();

typedef struct {
    // for API redirector
    LoadLibraryA_t             LoadLibraryA;
    LoadLibraryW_t             LoadLibraryW;
    LoadLibraryExA_t           LoadLibraryExA;
    LoadLibraryExW_t           LoadLibraryExW;
    FreeLibrary_t              FreeLibrary;
    FreeLibraryAndExitThread_t FreeLibraryAndExitThread;

    // for user
    LibLockModule_t   LockModule;
    LibUnlockModule_t UnlockModule;
    LibGetStatus_t    GetStatus;
    LibFreeAllMu_t    FreeAllMu;

    // for runtime internal usage
    LibLock_t    Lock;
    LibUnlock_t  Unlock;
    LibEncrypt_t Encrypt;
    LibDecrypt_t Decrypt;
    LibFreeAll_t FreeAll;
    LibClean_t   Clean;

    // data for sysmon
    HANDLE hMutex;
} LibraryTracker_M;

LibraryTracker_M* InitLibraryTracker(Context* context);

#endif // MOD_LIBRARY_H
