#ifndef MOD_STORAGE_H
#define MOD_STORAGE_H

#include "c_types.h"
#include "errno.h"
#include "context.h"

typedef BOOL (*ImsSetValue_t)(int id, void* value, uint size);
typedef BOOL (*ImsGetValue_t)(int id, void* value, uint* size);
typedef BOOL (*ImsGetPointer_t)(int id, void** pointer, uint* size);
typedef BOOL (*ImsDelete_t)(int id);
typedef BOOL (*ImsDeleteAll_t)();

typedef bool  (*ImsLock_t)();
typedef bool  (*ImsUnlock_t)();
typedef errno (*ImsEncrypt_t)();
typedef errno (*ImsDecrypt_t)();
typedef errno (*ImsClean_t)();

typedef struct {
    // for user
    ImsSetValue_t   SetValue;
    ImsGetValue_t   GetValue;
    ImsGetPointer_t GetPointer;
    ImsDelete_t     Delete;
    ImsDeleteAll_t  DeleteAll;

    // for runtime internal usage
    ImsLock_t    Lock;
    ImsUnlock_t  Unlock;
    ImsEncrypt_t Encrypt;
    ImsDecrypt_t Decrypt;
    ImsClean_t   Clean;

    // data for sysmon
    HANDLE hMutex;
} InMemoryStorage_M;

InMemoryStorage_M* InitInMemoryStorage(Context* context);

#endif // MOD_STORAGE_H
