#ifndef MOD_MEMORY_H
#define MOD_MEMORY_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_msvcrt.h"
#include "dll_ucrtbase.h"
#include "context.h"
#include "errno.h"

typedef struct {
    int64 NumGlobals;
    int64 NumLocals;
    int64 NumBlocks;
    int64 NumRegions;
    int64 NumPages;
    int64 NumHeaps;
} MT_Status;

typedef void* (*MemAlloc_t)(uint size);
typedef void* (*MemCalloc_t)(uint num, uint size);
typedef void* (*MemRealloc_t)(void* ptr, uint size);
typedef void  (*MemFree_t)(void* ptr);
typedef uint  (*MemSize_t)(void* ptr);
typedef uint  (*MemCap_t)(void* ptr);

typedef bool (*MemLockRegion_t)(LPVOID address);
typedef bool (*MemUnlockRegion_t)(LPVOID address);
typedef bool (*MemGetStatus_t)(MT_Status* status);
typedef bool (*MemFreeAllMu_t)();

typedef bool  (*MemLock_t)();
typedef bool  (*MemUnlock_t)();
typedef errno (*MemEncrypt_t)();
typedef errno (*MemDecrypt_t)();
typedef errno (*MemFreeAll_t)();
typedef errno (*MemClean_t)();

typedef struct {
    VirtualAlloc_t   VirtualAlloc;
    VirtualFree_t    VirtualFree;
    VirtualProtect_t VirtualProtect;
    VirtualQuery_t   VirtualQuery;
    HeapCreate_t     HeapCreate;
    HeapDestroy_t    HeapDestroy;
    HeapAlloc_t      HeapAlloc;
    HeapReAlloc_t    HeapReAlloc;
    HeapFree_t       HeapFree;
    HeapSize_t       HeapSize;
    GlobalAlloc_t    GlobalAlloc;
    GlobalReAlloc_t  GlobalReAlloc;
    GlobalFree_t     GlobalFree;
    LocalAlloc_t     LocalAlloc;
    LocalReAlloc_t   LocalReAlloc;
    LocalFree_t      LocalFree;

    msvcrt_malloc_t  msvcrt_malloc;
    msvcrt_calloc_t  msvcrt_calloc;
    msvcrt_realloc_t msvcrt_realloc;
    msvcrt_free_t    msvcrt_free;
    msvcrt_msize_t   msvcrt_msize;

    ucrtbase_malloc_t  ucrtbase_malloc;
    ucrtbase_calloc_t  ucrtbase_calloc;
    ucrtbase_realloc_t ucrtbase_realloc;
    ucrtbase_free_t    ucrtbase_free;
    ucrtbase_msize_t   ucrtbase_msize;

    MemAlloc_t   Alloc;
    MemCalloc_t  Calloc;
    MemRealloc_t Realloc;
    MemFree_t    Free;
    MemSize_t    Size;
    MemCap_t     Cap;

    MemLockRegion_t   LockRegion;
    MemUnlockRegion_t UnlockRegion;
    MemGetStatus_t    GetStatus;
    MemFreeAllMu_t    FreeAllMu;

    MemLock_t    Lock;
    MemUnlock_t  Unlock;
    MemEncrypt_t Encrypt;
    MemDecrypt_t Decrypt;
    MemFreeAll_t FreeAll;
    MemClean_t   Clean;
} MemoryTracker_M;

MemoryTracker_M* InitMemoryTracker(Context* context);

#endif // MOD_MEMORY_H
