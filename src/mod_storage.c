#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "list_md.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "mod_storage.h"
#include "debug.h"

// some IDs are reserved for runtime and some upper-level
// modules, and the rest are left to users.
#define NUM_RESERVED_ID 1024

typedef struct {
    int   id;
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
} InMemoryStorage;

// methods for upper module
bool IMS_SetValue(int id, void* value, uint size);
bool IMS_GetValue(int id, void* value, uint* size);
bool IMS_GetPointer(int id, void** pointer, uint* size);
bool IMS_Delete(int id);
bool IMS_DeleteAll();

// methods for runtime
bool  IMS_Lock();
bool  IMS_Unlock();
errno IMS_Encrypt();
errno IMS_Decrypt();
errno IMS_Clean();

// hard encoded address in getStoragePointer for replacement
#ifdef _WIN64
    #define STORAGE_POINTER 0x7FABCDEF111111C6
#elif _WIN32
    #define STORAGE_POINTER 0x7FABCDC6
#endif
static InMemoryStorage* getStoragePointer();

static bool initStorageAPI(InMemoryStorage* Storage, Context* context);
static bool updateStoragePointer(InMemoryStorage* Storage);
static bool recoverStoragePointer(InMemoryStorage* Storage);
static bool initStorageEnvironment(InMemoryStorage* Storage, Context* context);
static void eraseStorageMethods(Context* context);
static void cleanStorage(InMemoryStorage* storage);

static imsItem* getItem(int id);
static bool addItem(int id, void* data, uint size);
static bool setItem(imsItem* item, void* data, uint size);
static bool delItem(int id);

InMemoryStorage_M* InitInMemoryStorage(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr storageAddr = addr + LAYOUT_IS_STRUCT + RandUintN(addr, 128);
    uintptr moduleAddr  = addr + LAYOUT_IS_MODULE + RandUintN(addr, 128);
    // allocate storage memory
    InMemoryStorage* storage = (InMemoryStorage*)storageAddr;
    mem_init(storage, sizeof(InMemoryStorage));
    // store options
    storage->NotEraseInstruction = context->NotEraseInstruction;
    // initialize storage
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
    InMemoryStorage_M* module = (InMemoryStorage_M*)moduleAddr;
    // methods for upper module
    module->SetValue   = GetFuncAddr(&IMS_SetValue);
    module->GetValue   = GetFuncAddr(&IMS_GetValue);
    module->GetPointer = GetFuncAddr(&IMS_GetPointer);
    module->Delete     = GetFuncAddr(&IMS_Delete);
    module->DeleteAll  = GetFuncAddr(&IMS_DeleteAll);
    // methods for runtime
    module->Lock    = GetFuncAddr(&IMS_Lock);
    module->Unlock  = GetFuncAddr(&IMS_Unlock);
    module->Encrypt = GetFuncAddr(&IMS_Encrypt);
    module->Decrypt = GetFuncAddr(&IMS_Decrypt);
    module->Clean   = GetFuncAddr(&IMS_Clean);
    // data for sysmon
    module->hMutex = storage->hMutex;
    return module;
}

// MUST disable compiler optimize, otherwise it will
// link it to the initStoreAPI in mod_argument.c
#pragma optimize("", off)
__declspec(noinline)
static bool initStorageAPI(InMemoryStorage* storage, Context* context)
{
    storage->VirtualAlloc        = context->VirtualAlloc;
    storage->VirtualFree         = context->VirtualFree;
    storage->ReleaseMutex        = context->ReleaseMutex;
    storage->WaitForSingleObject = context->WaitForSingleObject;
    storage->CloseHandle         = context->CloseHandle;
    return true;
}
#pragma optimize("", on)

// CANNOT merge updateStoragePointer and recoverStoragePointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateStoragePointer(InMemoryStorage* storage)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getStoragePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != STORAGE_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)storage;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool recoverStoragePointer(InMemoryStorage* storage)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getStoragePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)storage)
        {
            target++;
            continue;
        }
        *pointer = STORAGE_POINTER;
        success = true;
        break;
    }
    return success;
}

static bool initStorageEnvironment(InMemoryStorage* storage, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_IS_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return false;
    }
    storage->hMutex = hMutex;
    // initialize item list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&storage->Items, &ctx, sizeof(imsItem));
    // set crypto context data
    RandBuffer(storage->ItemsKey, CRYPTO_KEY_SIZE);
    RandBuffer(storage->ItemsIV, CRYPTO_IV_SIZE);
    return true;
}

__declspec(noinline)
static void eraseStorageMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initStorageAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseStorageMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

__declspec(noinline)
static void cleanStorage(InMemoryStorage* storage)
{
    if (storage->CloseHandle != NULL && storage->hMutex != NULL)
    {
        storage->CloseHandle(storage->hMutex);
    }
    List_Free(&storage->Items);
}

// updateStoragePointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateStoragePointer will fail.
#pragma optimize("", off)
static InMemoryStorage* getStoragePointer()
{
    uintptr pointer = STORAGE_POINTER;
    return (InMemoryStorage*)(pointer);
}
#pragma optimize("", on)

// methods for upper module
__declspec(noinline)
bool IMS_SetValue(int id, void* value, uint size)
{
    if (!IMS_Lock())
    {
        return false;
    }

    errno lastErr = NO_ERROR;
    for (;;)
    {
        id += NUM_RESERVED_ID;
        if (id == 0)
        {
            lastErr = ERR_STORAGE_INVALID_ID;
            break;
        }
        imsItem* item = getItem(id);
        if (item == NULL)
        {
            if (!addItem(id, value, size))
            {
                lastErr = ERR_STORAGE_ADD_ITEM;
            }
        } else {
            if (!setItem(item, value, size))
            {
                lastErr = ERR_STORAGE_SET_ITEM;
            }
        }
        break;
    }

    if (!IMS_Unlock())
    {
        return false;
    }

    if (lastErr != NO_ERROR)
    {
        SetLastErrno(lastErr);
        return false;
    }
    return true;
}

__declspec(noinline)
bool IMS_GetValue(int id, void* value, uint* size)
{
    if (!IMS_Lock())
    {
        return false;
    }

    errno lastErr = NO_ERROR;
    for (;;)
    {
        id += NUM_RESERVED_ID;
        if (id == 0)
        {
            lastErr = ERR_STORAGE_INVALID_ID;
            break;
        }
        imsItem* item = getItem(id);
        if (item == NULL)
        {
            lastErr = ERR_STORAGE_NOT_EXISTS;
            break;
        }
        // only receive data size
        if (value == NULL)
        {
            *size = item->size;
            break;
        }
        mem_copy(value, item->data, item->size);
        if (size != NULL)
        {
            *size = item->size;
        }
        break;
    }

    if (!IMS_Unlock())
    {
        return false;
    }

    if (lastErr != NO_ERROR)
    {
        SetLastErrno(lastErr);
        return false;
    }
    return true;
}

__declspec(noinline)
bool IMS_GetPointer(int id, void** pointer, uint* size)
{
    if (!IMS_Lock())
    {
        return false;
    }

    errno lastErr = NO_ERROR;
    for (;;)
    {
        id += NUM_RESERVED_ID;
        if (id == 0)
        {
            lastErr = ERR_STORAGE_INVALID_ID;
            break;
        }
        imsItem* item = getItem(id);
        if (item == NULL)
        {
            lastErr = ERR_STORAGE_NOT_EXISTS;
            break;
        }
        *pointer = item->data;
        if (size != NULL)
        {
            *size = item->size;
        }
        break;
    }

    if (!IMS_Unlock())
    {
        return false;
    }

    if (lastErr != NO_ERROR)
    {
        SetLastErrno(lastErr);
        return false;
    }
    return true;
}

__declspec(noinline)
bool IMS_Delete(int id)
{
    if (!IMS_Lock())
    {
        return false;
    }

    errno lastErr = NO_ERROR;
    for (;;)
    {
        id += NUM_RESERVED_ID;
        if (id == 0)
        {
            lastErr = ERR_STORAGE_INVALID_ID;
            break;
        }
        if (!delItem(id))
        {
            lastErr = ERR_STORAGE_DEL_ITEM;
            break;
        }
        break;
    }

    if (!IMS_Unlock())
    {
        return false;
    }

    if (lastErr != NO_ERROR)
    {
        SetLastErrno(lastErr);
        return false;
    }
    return true;
}

__declspec(noinline)
bool IMS_DeleteAll()
{
    InMemoryStorage* storage = getStoragePointer();

    if (!IMS_Lock())
    {
        return false;
    }

    List* items   = &storage->Items;
    errno lastErr = NO_ERROR;

    uint len = items->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        imsItem* item = List_Get(items, idx);
        if (item->id == 0)
        {
            continue;
        }
        // erase and free data before delete item
        RandBuffer(item->data, item->size);
        if (!storage->VirtualFree(item->data, 0, MEM_RELEASE))
        {
            lastErr = ERR_STORAGE_FREE_ITEM;
        }
        if (!List_Delete(items, idx))
        {
            lastErr = ERR_STORAGE_REMOVE_ITEM;
        }
        num++;
    }

    if (!IMS_Unlock())
    {
        return false;
    }

    if (lastErr != NO_ERROR)
    {
        SetLastErrno(lastErr);
        return false;
    }
    return true;
}

__declspec(noinline)
static imsItem* getItem(int id)
{
    InMemoryStorage* storage = getStoragePointer();

    List* items = &storage->Items;

    uint len = items->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        imsItem* item = List_Get(items, idx);
        if (item->id == 0)
        {
            continue;
        }
        if (item->id == id)
        {
            return item;
        }
        num++;
    }
    return NULL;
}

__declspec(noinline)
static bool addItem(int id, void* data, uint size)
{
    InMemoryStorage* storage = getStoragePointer();

    void* memPage = NULL;
    bool  success = false;
    for (;;)
    {
        // allocate memory for store data
        memPage = storage->VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (memPage == NULL)
        {
            break;
        }
        mem_copy(memPage, data, size);
        // create and insert item to list 
        imsItem item = {
            .id   = id,
            .data = memPage,
            .size = size,
        };
        RandBuffer(item.key, CRYPTO_KEY_SIZE);
        RandBuffer(item.iv, CRYPTO_IV_SIZE);
        if (!List_Insert(&storage->Items, &item))
        {
            break;
        }
        success = true;
        break;
    }

    if (!success && memPage != NULL)
    {
        storage->VirtualFree(memPage, 0, MEM_RELEASE);
    }
    return success;
}

__declspec(noinline)
static bool setItem(imsItem* item, void* data, uint size)
{
    InMemoryStorage* storage = getStoragePointer();

    void* memPage = NULL;
    bool  success = false;
    for (;;)
    {
        // allocate memory for store data
        memPage = storage->VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (memPage == NULL)
        {
            break;
        }
        mem_copy(memPage, data, size);
        // erase and free data before update item
        RandBuffer(item->data, item->size);
        if (!storage->VirtualFree(item->data, 0, MEM_RELEASE))
        {
            break;
        }
        // update item
        item->data = memPage;
        item->size = size;
        success = true;
        break;
    }

    if (!success && memPage != NULL)
    {
        storage->VirtualFree(memPage, 0, MEM_RELEASE);
    }
    return success;
}

__declspec(noinline)
static bool delItem(int id)
{
    InMemoryStorage* storage = getStoragePointer();

    imsItem* target = NULL;

    List* items = &storage->Items;
    uint len = items->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        imsItem* item = List_Get(items, idx);
        if (item->id == 0)
        {
            continue;
        }
        if (item->id == id)
        {
            target = item;
            break;
        }
        num++;
    }
    if (target == NULL)
    {
        return false;
    }

    // erase and free data before delete item
    RandBuffer(target->data, target->size);
    if (!storage->VirtualFree(target->data, 0, MEM_RELEASE))
    {
        return false;
    }
    return List_Delete(items, idx);
}

__declspec(noinline)
bool IMS_Lock()
{
    InMemoryStorage* storage = getStoragePointer();

    DWORD event = storage->WaitForSingleObject(storage->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool IMS_Unlock()
{
    InMemoryStorage* storage = getStoragePointer();

    return storage->ReleaseMutex(storage->hMutex);
}

__declspec(noinline)
errno IMS_Encrypt()
{
    InMemoryStorage* storage = getStoragePointer();

    List* items = &storage->Items;

    // encrypt items
    uint len = items->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        imsItem* item = List_Get(items, idx);
        if (item->id == 0)
        {
            continue;
        }
        RandBuffer(item->key, CRYPTO_KEY_SIZE);
        RandBuffer(item->iv, CRYPTO_IV_SIZE);
        EncryptBuf(item->data, item->size, item->key, item->iv);
        num++;
    }

    // encrypt list
    byte* key = storage->ItemsKey;
    byte* iv  = storage->ItemsIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(items->Data, List_Size(items), key, iv);

    dbg_log("[storage]", "items: %zu", items->Len);
    return NO_ERROR;
}

__declspec(noinline)
errno IMS_Decrypt()
{
    InMemoryStorage* storage = getStoragePointer();

    List* items = &storage->Items;

    // decrypt list
    byte* key = storage->ItemsKey;
    byte* iv  = storage->ItemsIV;
    DecryptBuf(items->Data, List_Size(items), key, iv);

    // decrypt items
    uint len = items->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        imsItem* item = List_Get(items, idx);
        if (item->id == 0)
        {
            continue;
        }
        DecryptBuf(item->data, item->size, item->key, item->iv);
        num++;
    }

    dbg_log("[storage]", "items: %zu", items->Len);
    return NO_ERROR;
}

__declspec(noinline)
errno IMS_Clean()
{
    InMemoryStorage* storage = getStoragePointer();

    List* items = &storage->Items;
    errno errno = NO_ERROR;

    // free items data
    uint len = items->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        imsItem* item = List_Get(items, idx);
        if (item->id == 0)
        {
            continue;
        }
        // erase and free data before clean item list
        RandBuffer(item->data, item->size);
        if (!storage->VirtualFree(item->data, 0, MEM_RELEASE))
        {
            errno = ERR_STORAGE_FREE_ITEM;
        }
        num++;
    }

    // clean item list
    RandBuffer(items->Data, List_Size(items));
    if (!List_Free(items) && errno == NO_ERROR)
    {
        errno = ERR_STORAGE_FREE_MEM;
    }

    // close mutex
    if (!storage->CloseHandle(storage->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_STORAGE_CLOSE_MUTEX;
    }

    // recover instructions
    if (storage->NotEraseInstruction)
    {
        if (!recoverStoragePointer(storage) && errno == NO_ERROR)
        {
            errno = ERR_STORAGE_RECOVER_INST;
        }
    }

    dbg_log("[storage]", "items: %zu", items->Len);
    return errno;
}
