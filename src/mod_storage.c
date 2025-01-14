#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "list_md.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "mod_storage.h"
#include "debug.h"

typedef struct {
    uint  index;
    void* data;
    uint  size;

    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
} imsItem;

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    VirtualAlloc_t        VirtualAlloc;
    VirtualFree_t         VirtualFree;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;

    // protect data
    HANDLE hMutex;

    // storage data
    List Items;
    byte ItemsKey[CRYPTO_KEY_SIZE];
    byte ItemsIV [CRYPTO_IV_SIZE];
} InMemStorage;

// methods for upper module
bool IM_SetValue(uint index, void* value, uint32 size);
bool IM_GetValue(uint index, void* value, uint32* size);
bool IM_GetPointer(uint index, void** pointer, uint32* size);
bool IM_Delete(uint index);
void IM_DeleteAll();

// methods for runtime
bool  IM_Lock();
bool  IM_Unlock();
errno IM_Encrypt();
errno IM_Decrypt();
errno IM_Clean();

// hard encoded address in getStoragePointer for replacement
#ifdef _WIN64
    #define STORAGE_POINTER 0x7FABCDEF111111C6
#elif _WIN32
    #define STORAGE_POINTER 0x7FABCDC6
#endif
static InMemStorage* getStoragePointer();

static bool initStorageAPI(InMemStorage* Storage, Context* context);
static bool updateStoragePointer(InMemStorage* Storage);
static bool recoverStoragePointer(InMemStorage* Storage);
static bool initStorageEnvironment(InMemStorage* Storage, Context* context);

static void eraseStorageMethods(Context* context);
static void cleanStorage(InMemStorage* storage);

InMemStorage_M* InitInMemStorage(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr storageAddr = address + 12000 + RandUintN(address, 128);
    uintptr moduleAddr  = address + 13000 + RandUintN(address, 128);
    // initialize storage
    InMemStorage* storage = (InMemStorage*)storageAddr;
    mem_init(storage, sizeof(InMemStorage));
    // store options
    storage->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initStorageAPI(storage, context))
        {
            errno = ERR_STORAGE_INIT_API;
            break;
        }
        if (!updateStoragePointer(storage))
        {
            errno = ERR_STORAGE_UPDATE_PTR;
            break;
        }
        if (!initStorageEnvironment(storage, context))
        {
            errno = ERR_STORAGE_INIT_ENV;
            break;
        }
        break;
    }
    eraseStorageMethods(context);
    if (errno != NO_ERROR)
    {
        cleanStorage(storage);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for storage
    InMemStorage_M* module = (InMemStorage_M*)moduleAddr;
    // methods for upper module
    module->SetValue   = GetFuncAddr(&IM_SetValue);
    module->GetValue   = GetFuncAddr(&IM_GetValue);
    module->GetPointer = GetFuncAddr(&IM_GetPointer);
    module->Delete     = GetFuncAddr(&IM_Delete);
    module->DeleteAll  = GetFuncAddr(&IM_DeleteAll);
    // methods for runtime
    module->Lock    = GetFuncAddr(&IM_Lock);
    module->Unlock  = GetFuncAddr(&IM_Unlock);
    module->Encrypt = GetFuncAddr(&IM_Encrypt);
    module->Decrypt = GetFuncAddr(&IM_Decrypt);
    module->Clean   = GetFuncAddr(&IM_Clean);
    return module;
}
