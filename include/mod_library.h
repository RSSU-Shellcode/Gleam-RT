#ifndef MOD_LIBRARY_H
#define MOD_LIBRARY_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "context.h"
#include "errno.h"

typedef bool (*LibLockModule_t)(HMODULE hModule);
typedef bool (*LibUnlockModule_t)(HMODULE hModule);

typedef bool  (*LibLock_t)();
typedef bool  (*LibUnlock_t)();
typedef errno (*LibEncrypt_t)();
typedef errno (*LibDecrypt_t)();
typedef errno (*LibFreeAll_t)();
typedef errno (*LibClean_t)();

typedef struct {
    LoadLibraryA_t             LoadLibraryA;
    LoadLibraryW_t             LoadLibraryW;
    LoadLibraryExA_t           LoadLibraryExA;
    LoadLibraryExW_t           LoadLibraryExW;
    FreeLibrary_t              FreeLibrary;
    FreeLibraryAndExitThread_t FreeLibraryAndExitThread;

    LibLockModule_t   LockModule;
    LibUnlockModule_t UnlockModule;

    LibLock_t    Lock;
    LibUnlock_t  Unlock;
    LibEncrypt_t Encrypt;
    LibDecrypt_t Decrypt;
    LibFreeAll_t FreeAll;
    LibClean_t   Clean;
} LibraryTracker_M;

LibraryTracker_M* InitLibraryTracker(Context* context);

#endif // MOD_LIBRARY_H
