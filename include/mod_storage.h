#ifndef MOD_STORAGE_H
#define MOD_STORAGE_H

#include "c_types.h"
#include "context.h"
#include "errno.h"

typedef bool (*ImsSetValue_t)(int id, void* value, uint size);
typedef bool (*ImsGetValue_t)(int id, void* value, uint* size);
typedef bool (*ImsGetPointer_t)(int id, void** pointer, uint* size);
typedef bool (*ImsDelete_t)(int id);
typedef void (*ImsDeleteAll_t)();

typedef bool  (*ImsLock_t)();
typedef bool  (*ImsUnlock_t)();
typedef errno (*ImsEncrypt_t)();
typedef errno (*ImsDecrypt_t)();
typedef errno (*ImsClean_t)();

typedef struct {
    ImsSetValue_t   SetValue;
    ImsGetValue_t   GetValue;
    ImsGetPointer_t GetPointer;
    ImsDelete_t     Delete;
    ImsDeleteAll_t  DeleteAll;

    ImsLock_t    Lock;
    ImsUnlock_t  Unlock;
    ImsEncrypt_t Encrypt;
    ImsDecrypt_t Decrypt;
    ImsClean_t   Clean;
} InMemoryStorage_M;

InMemoryStorage_M* InitInMemoryStorage(Context* context);

#endif // MOD_STORAGE_H
