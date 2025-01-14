#ifndef MOD_STORAGE_H
#define MOD_STORAGE_H

#include "c_types.h"
#include "context.h"
#include "errno.h"

typedef bool (*ImsSetValue_t)(uint index, void* value, uint32 size);
typedef bool (*ImsGetValue_t)(uint index, void* value, uint32* size);
typedef bool (*ImsGetPointer_t)(uint index, void** pointer, uint32* size);
typedef bool (*ImsDelete_t)(uint index);
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
} InMemStorage_M;

InMemStorage_M* InitInMemStorage(Context* context);

#endif // MOD_STORAGE_H
