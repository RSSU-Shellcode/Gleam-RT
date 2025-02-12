#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "mod_argument.h"
#include "debug.h"

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    VirtualAlloc_t        VirtualAlloc;
    VirtualFree_t         VirtualFree;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;

    // store arguments
    byte*  Address;
    uint   Size;
    uint32 NumArgs;
    HANDLE hMutex;

    byte Key[CRYPTO_KEY_SIZE];
    byte IV [CRYPTO_IV_SIZE];
} ArgumentStore;

// methods for upper module
bool AS_GetValue(uint32 id, void* value, uint32* size);
bool AS_GetPointer(uint32 id, void** pointer, uint32* size);
bool AS_Erase(uint32 id);
void AS_EraseAll();

// methods for runtime
bool  AS_Lock();
bool  AS_Unlock();
errno AS_Encrypt();
errno AS_Decrypt();
errno AS_Clean();

// hard encoded address in getStorePointer for replacement
#ifdef _WIN64
    #define STORE_POINTER 0x7FABCDEF111111C5
#elif _WIN32
    #define STORE_POINTER 0x7FABCDC5
#endif
static ArgumentStore* getStorePointer();

static bool initStoreAPI(ArgumentStore* store, Context* context);
static bool updateStorePointer(ArgumentStore* store);
static bool recoverStorePointer(ArgumentStore* store);
static bool initStoreEnvironment(ArgumentStore* store, Context* context);
static void eraseStoreMethods(Context* context);
static void cleanStore(ArgumentStore* store);

static errno loadArguments(ArgumentStore* store, Context* context);
static byte  ror(byte value, uint8 bits);
static byte  rol(byte value, uint8 bits);

ArgumentStore_M* InitArgumentStore(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr storeAddr  = address + 10000 + RandUintN(address, 128);
    uintptr moduleAddr = address + 11000 + RandUintN(address, 128);
    // initialize store
    ArgumentStore* store = (ArgumentStore*)storeAddr;
    mem_init(store, sizeof(ArgumentStore));
    // store options
    store->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initStoreAPI(store, context))
        {
            errno = ERR_ARGUMENT_INIT_API;
            break;
        }
        if (!updateStorePointer(store))
        {
            errno = ERR_ARGUMENT_UPDATE_PTR;
            break;
        }
        if (!initStoreEnvironment(store, context))
        {
            errno = ERR_ARGUMENT_INIT_ENV;
            break;
        }
        errno = loadArguments(store, context);
        if (errno != NO_ERROR)
        {
            break;
        }
        break;
    }
    eraseStoreMethods(context);
    if (errno != NO_ERROR)
    {
        cleanStore(store);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for store
    ArgumentStore_M* module = (ArgumentStore_M*)moduleAddr;
    // methods for upper module
    module->GetValue   = GetFuncAddr(&AS_GetValue);
    module->GetPointer = GetFuncAddr(&AS_GetPointer);
    module->Erase      = GetFuncAddr(&AS_Erase);
    module->EraseAll   = GetFuncAddr(&AS_EraseAll);
    // methods for runtime
    module->Lock    = GetFuncAddr(&AS_Lock);
    module->Unlock  = GetFuncAddr(&AS_Unlock);
    module->Encrypt = GetFuncAddr(&AS_Encrypt);
    module->Decrypt = GetFuncAddr(&AS_Decrypt);
    module->Clean   = GetFuncAddr(&AS_Clean);
    return module;
}

__declspec(noinline)
static bool initStoreAPI(ArgumentStore* store, Context* context)
{
    store->VirtualAlloc        = context->VirtualAlloc;
    store->VirtualFree         = context->VirtualFree;
    store->ReleaseMutex        = context->ReleaseMutex;
    store->WaitForSingleObject = context->WaitForSingleObject;
    store->CloseHandle         = context->CloseHandle;
    return true;
}

// CANNOT merge updateStorePointer and recoverStorePointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateStorePointer(ArgumentStore* store)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getStorePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != STORE_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)store;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool recoverStorePointer(ArgumentStore* store)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getStorePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)store)
        {
            target++;
            continue;
        }
        *pointer = STORE_POINTER;
        success = true;
        break;
    }
    return success;
}

static bool initStoreEnvironment(ArgumentStore* store, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    store->hMutex = hMutex;
    // set crypto context data
    RandBuffer(store->Key, CRYPTO_KEY_SIZE);
    RandBuffer(store->IV, CRYPTO_IV_SIZE);
    return true;
}

static errno loadArguments(ArgumentStore* store, Context* context)
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    byte*   addr = (byte*)(stub + ARG_OFFSET_FIRST_ARG);
    uint32  size = *(uint32*)(stub + ARG_OFFSET_ARGS_SIZE);
    // allocate memory page for store them
    uint32 memSize = ((size / context->PageSize) + 1) * context->PageSize;
    memSize += (uint32)(1 + RandUintN(0, 16)) * context->PageSize;
    void* mem = store->VirtualAlloc(NULL, memSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (mem == NULL)
    {
        return ERR_ARGUMENT_ALLOC_MEM;
    }
    store->Address = mem;
    store->Size    = memSize;
    store->NumArgs = *(uint32*)(stub + ARG_OFFSET_NUM_ARGS);
    // copy encrypted arguments to new memory page
    mem_copy(mem, addr, size);
    // decrypted arguments
    byte* data = (byte*)mem;
    byte* key  = (byte*)(stub + ARG_OFFSET_CRYPTO_KEY);
    uint32 last = *(uint32*)(key+0);
    uint32 ctr  = *(uint32*)(key+4);
    uint keyIdx = last % ARG_CRYPTO_KEY_SIZE;
    for (uint32 i = 0; i < size; i++)
    {
        byte b = *data;
        b = rol(b, (uint8)(last % 8));
        b -= (byte)(ctr ^ last);
        b ^= *(key + keyIdx);
        b = ror(b, (uint8)(last % 8));
        b ^= (byte)last;
        *data = b;
        // update key index
        keyIdx++;
        if (keyIdx >= ARG_CRYPTO_KEY_SIZE)
        {
            keyIdx = 0;
        }
        ctr++;
        last = XORShift32(last);
        // update address
        data++;
    }
    // erase argument stub after decrypt
    if (!context->NotEraseInstruction)
    {
        RandBuffer((byte*)stub, ARG_HEADER_SIZE + size);
    }
    dbg_log("[argument]", "mem page: 0x%zX", store->Address);
    dbg_log("[argument]", "num args: %zu", store->NumArgs);
    return NO_ERROR;
}

static byte ror(byte value, uint8 bits)
{
    return value >> bits | value << (8 - bits);
}

static byte rol(byte value, uint8 bits)
{
    return value << bits | value >> (8 - bits);
}

__declspec(noinline)
static void eraseStoreMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initStoreAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseStoreMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

__declspec(noinline)
static void cleanStore(ArgumentStore* store)
{
    if (store->Address != NULL)
    {
        RandBuffer(store->Address, (int64)(store->Size));
    }
    if (store->VirtualFree != NULL && store->Address != NULL)
    {
        store->VirtualFree(store->Address, 0, MEM_RELEASE);
    }
    if (store->CloseHandle != NULL && store->hMutex != NULL)
    {
        store->CloseHandle(store->hMutex);
    }
}

// updateStorePointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateStorePointer will fail.
#pragma optimize("", off)
static ArgumentStore* getStorePointer()
{
    uintptr pointer = STORE_POINTER;
    return (ArgumentStore*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
bool AS_GetValue(uint32 id, void* value, uint32* size)
{
    ArgumentStore* store = getStorePointer();

    if (!AS_Lock())
    {
        return false;
    }

    // search the target argument with id
    byte* addr = store->Address;
    bool found = false;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        uint32 aid = *(uint32*)(addr);
        uint32 asz = *(uint32*)(addr + 4);
        if (aid != id)
        {
            // skip argument id, size and data
            addr += 4 + 4 + asz;
            continue;
        }
        // copy argument data to value pointer
        void* src = addr + 4 + 4;
        mem_copy(value, src, asz);
        // receive argument size
        if (size != NULL)
        {
            *size = asz;
        }
        found = true;
        break;
    }

    if (!AS_Unlock())
    {
        return false;
    }
    return found;
}

__declspec(noinline)
bool AS_GetPointer(uint32 id, void** pointer, uint32* size)
{
    ArgumentStore* store = getStorePointer();

    if (!AS_Lock())
    {
        return false;
    }

    // search the target argument with id
    byte* addr = store->Address;
    bool found = false;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        uint32 aid = *(uint32*)(addr);
        uint32 asz = *(uint32*)(addr + 4);
        if (aid != id)
        {
            // skip argument id, size and data
            addr += 4 + 4 + asz;
            continue;
        }
        // receive argument pointer
        if (asz != 0)
        {
            *pointer = (void*)(addr + 4 + 4);
        } else {
            *pointer = NULL;
        }
        // receive argument size
        if (size != NULL)
        {
            *size = asz;
        }
        found = true;
        break;
    }

    if (!AS_Unlock())
    {
        return false;
    }
    return found;
}

__declspec(noinline)
bool AS_Erase(uint32 id)
{
    ArgumentStore* store = getStorePointer();

    if (!AS_Lock())
    {
        return false;
    }

    // search the target argument with id
    byte* addr = store->Address;
    bool found = false;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        uint32 aid = *(uint32*)(addr);
        uint32 asz = *(uint32*)(addr + 4);
        if (aid != id)
        {
            // skip argument id, size and data
            addr += 4 + 4 + asz;
            continue;
        }
        // erase argument id and data
        RandBuffer(addr, 4);
        RandBuffer(addr + 4 + 4, (int64)asz);
        found = true;
        break;
    }

    if (!AS_Unlock())
    {
        return false;
    }
    return found;
}

__declspec(noinline)
void AS_EraseAll()
{
    ArgumentStore* store = getStorePointer();

    if (!AS_Lock())
    {
        return;
    }

    byte* addr = store->Address;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        uint32 asz = *(uint32*)(addr + 4);
        // erase argument id and data
        RandBuffer(addr, 4);
        RandBuffer(addr + 4 + 4, (int64)asz);
        addr += 4 + 4 + asz;
    }

    AS_Unlock();
}

__declspec(noinline)
bool AS_Lock()
{
    ArgumentStore* store = getStorePointer();

    DWORD event = store->WaitForSingleObject(store->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool AS_Unlock()
{
    ArgumentStore* store = getStorePointer();

    return store->ReleaseMutex(store->hMutex);
}

__declspec(noinline)
errno AS_Encrypt()
{
    ArgumentStore* store = getStorePointer();

    byte* key = store->Key;
    byte* iv  = store->IV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(store->Address, store->Size, key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno AS_Decrypt()
{
    ArgumentStore* store = getStorePointer();

    byte* key = store->Key;
    byte* iv  = store->IV;
    DecryptBuf(store->Address, store->Size, key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno AS_Clean()
{
    ArgumentStore* store = getStorePointer();

    errno errno = NO_ERROR;

    // erase all arguments
    RandBuffer(store->Address, store->Size);
    // free memory page
    if (!store->VirtualFree(store->Address, 0, MEM_RELEASE) && errno == NO_ERROR)
    {
        errno = ERR_ARGUMENT_FREE_MEM;
    }

    // close mutex
    if (!store->CloseHandle(store->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_ARGUMENT_CLOSE_MUTEX;
    }

    // recover instructions
    if (store->NotEraseInstruction)
    {
        if (!recoverStorePointer(store) && errno == NO_ERROR)
        {
            errno = ERR_ARGUMENT_RECOVER_INST;
        }
    }
    return errno;
}
