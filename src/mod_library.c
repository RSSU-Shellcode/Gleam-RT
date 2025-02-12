#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "list_md.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "mod_library.h"
#include "debug.h"

// since the essence of HMODULE is the memory address where
// the module is located, an address that cannot be assigned
// is used as a special placeholder.
#define MODULE_UNLOADED ((HMODULE)(0xFE))

typedef struct {
    HMODULE hModule;
    uint    counter;
    bool    locked;
} module;

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    LoadLibraryA_t             LoadLibraryA;
    LoadLibraryW_t             LoadLibraryW;
    LoadLibraryExA_t           LoadLibraryExA;
    LoadLibraryExW_t           LoadLibraryExW;
    FreeLibrary_t              FreeLibrary;
    FreeLibraryAndExitThread_t FreeLibraryAndExitThread;
    ReleaseMutex_t             ReleaseMutex;
    WaitForSingleObject_t      WaitForSingleObject;
    CloseHandle_t              CloseHandle;

    // protect data
    HANDLE hMutex;

    // store all modules info
    List Modules;
    byte ModulesKey[CRYPTO_KEY_SIZE];
    byte ModulesIV [CRYPTO_IV_SIZE];
} LibraryTracker;

// methods for IAT hooks
HMODULE LT_LoadLibraryA(LPCSTR lpLibFileName);
HMODULE LT_LoadLibraryW(LPCWSTR lpLibFileName);
HMODULE LT_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
HMODULE LT_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
BOOL    LT_FreeLibrary(HMODULE hLibModule);
void    LT_FreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode);

// methods for user
bool LT_LockModule(HMODULE hModule);
bool LT_UnlockModule(HMODULE hModule);
bool LT_GetStatus(LT_Status* status);
bool LT_FreeAllMu();

// methods for runtime
bool  LT_Lock();
bool  LT_Unlock();
errno LT_Encrypt();
errno LT_Decrypt();
errno LT_FreeAll();
errno LT_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF111111C1
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCDC1
#endif
static LibraryTracker* getTrackerPointer();

static bool initTrackerAPI(LibraryTracker* tracker, Context* context);
static bool updateTrackerPointer(LibraryTracker* tracker);
static bool recoverTrackerPointer(LibraryTracker* tracker);
static bool initTrackerEnvironment(LibraryTracker* tracker, Context* context);
static void eraseTrackerMethods(Context* context);
static void cleanTracker(LibraryTracker* tracker);

static bool addModule(LibraryTracker* tracker, HMODULE hModule);
static bool delModule(LibraryTracker* tracker, HMODULE hModule);
static bool setModuleLocker(HMODULE hModule, bool lock);
static bool cleanModule(LibraryTracker* tracker, module* module);

LibraryTracker_M* InitLibraryTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 4096 + RandUintN(address, 128);
    uintptr moduleAddr  = address + 5000 + RandUintN(address, 128);
    // initialize tracker
    LibraryTracker* tracker = (LibraryTracker*)trackerAddr;
    mem_init(tracker, sizeof(LibraryTracker));
    // store options
    tracker->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errno = ERR_LIBRARY_INIT_API;
            break;
        }
        if (!updateTrackerPointer(tracker))
        {
            errno = ERR_LIBRARY_UPDATE_PTR;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errno = ERR_LIBRARY_INIT_ENV;
            break;
        }
        break;
    }
    eraseTrackerMethods(context);
    if (errno != NO_ERROR)
    {
        cleanTracker(tracker);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for tracker
    LibraryTracker_M* module = (LibraryTracker_M*)moduleAddr;
    // Windows API hooks
    module->LoadLibraryA             = GetFuncAddr(&LT_LoadLibraryA);
    module->LoadLibraryW             = GetFuncAddr(&LT_LoadLibraryW);
    module->LoadLibraryExA           = GetFuncAddr(&LT_LoadLibraryExA);
    module->LoadLibraryExW           = GetFuncAddr(&LT_LoadLibraryExW);
    module->FreeLibrary              = GetFuncAddr(&LT_FreeLibrary);
    module->FreeLibraryAndExitThread = GetFuncAddr(&LT_FreeLibraryAndExitThread);
    // methods for user
    module->LockModule   = GetFuncAddr(&LT_LockModule);
    module->UnlockModule = GetFuncAddr(&LT_UnlockModule);
    module->GetStatus    = GetFuncAddr(&LT_GetStatus);
    module->FreeAllMu    = GetFuncAddr(&LT_FreeAllMu);
    // methods for runtime
    module->Lock    = GetFuncAddr(&LT_Lock);
    module->Unlock  = GetFuncAddr(&LT_Unlock);
    module->Encrypt = GetFuncAddr(&LT_Encrypt);
    module->Decrypt = GetFuncAddr(&LT_Decrypt);
    module->FreeAll = GetFuncAddr(&LT_FreeAll);
    module->Clean   = GetFuncAddr(&LT_Clean);
    return module;
}

__declspec(noinline)
static bool initTrackerAPI(LibraryTracker* tracker, Context* context)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x214DF62A80434DBF, 0xEB0FDC717FC827A5 }, // LoadLibraryW
        { 0x2F6B12D80C0B77BC, 0xDB036D7FA710BE44 }, // LoadLibraryExA
        { 0xC9297DE7F8C97F1C, 0x580EBCC7C3411C35 }, // LoadLibraryExW
        { 0x0708BC7E2C7DA370, 0x39B9AC22BC408886 }, // FreeLibraryAndExitThread
    };
#elif _WIN32
    {
        { 0xCE3D1172, 0x0FB89CC3 }, // LoadLibraryW
        { 0x46B4638A, 0x213466F9 }, // LoadLibraryExA
        { 0xDBB0F0FE, 0x516334AA }, // LoadLibraryExW
        { 0x7730C1E2, 0xF5551C66 }, // FreeLibraryAndExitThread
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    tracker->LoadLibraryW             = list[0].proc;
    tracker->LoadLibraryExA           = list[1].proc;
    tracker->LoadLibraryExW           = list[2].proc;
    tracker->FreeLibraryAndExitThread = list[3].proc;

    tracker->LoadLibraryA        = context->LoadLibraryA;
    tracker->FreeLibrary         = context->FreeLibrary;
    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    tracker->CloseHandle         = context->CloseHandle;
    return true;
}

// CANNOT merge updateTrackerPointer and recoverTrackerPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateTrackerPointer(LibraryTracker* tracker)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getTrackerPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != TRACKER_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)tracker;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool recoverTrackerPointer(LibraryTracker* tracker)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getTrackerPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)tracker)
        {
            target++;
            continue;
        }
        *pointer = TRACKER_POINTER;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool initTrackerEnvironment(LibraryTracker* tracker, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    tracker->hMutex = hMutex;
    // initialize module list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Modules, &ctx, sizeof(module));
    // set crypto context data
    RandBuffer(tracker->ModulesKey, CRYPTO_KEY_SIZE);
    RandBuffer(tracker->ModulesIV, CRYPTO_IV_SIZE);
    return true;
}

__declspec(noinline)
static void eraseTrackerMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initTrackerAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseTrackerMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

__declspec(noinline)
static void cleanTracker(LibraryTracker* tracker)
{
    if (tracker->CloseHandle != NULL && tracker->hMutex != NULL)
    {
        tracker->CloseHandle(tracker->hMutex);
    }
    List_Free(&tracker->Modules);
}

// updateTrackerPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateTrackerPointer will fail.
#pragma optimize("", off)
static LibraryTracker* getTrackerPointer()
{
    uintptr pointer = TRACKER_POINTER;
    return (LibraryTracker*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
HMODULE LT_LoadLibraryA(LPCSTR lpLibFileName)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = true;
    for (;;)
    {
        hModule = tracker->LoadLibraryA(lpLibFileName);
        if (hModule == NULL)
        {
            success = false;
            break;
        }
        if (!addModule(tracker, hModule))
        {
            success = false;
            break;
        }
        break;
    }

    dbg_log("[library]", "LoadLibraryA: %s 0x%zX", lpLibFileName, hModule);

    if (!LT_Unlock())
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
HMODULE LT_LoadLibraryW(LPCWSTR lpLibFileName)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = true;
    for (;;)
    {
        hModule = tracker->LoadLibraryW(lpLibFileName);
        if (hModule == NULL)
        {
            success = false;
            break;
        }
        if (!addModule(tracker, hModule))
        {
            success = false;
            break;
        }
        break;
    }

    dbg_log("[library]", "LoadLibraryW: %ls 0x%zX", lpLibFileName, hModule);

    if (!LT_Unlock())
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
HMODULE LT_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = true;
    for (;;)
    {
        hModule = tracker->LoadLibraryExA(lpLibFileName, hFile, dwFlags);
        if (hModule == NULL)
        {
            success = false;
            break;
        }
        if (!addModule(tracker, hModule))
        {
            success = false;
            break;
        }
        break;
    }

    dbg_log("[library]", "LoadLibraryExA: %s 0x%zX", lpLibFileName, hModule);

    if (!LT_Unlock())
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
HMODULE LT_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = true;
    for (;;)
    {
        hModule = tracker->LoadLibraryExW(lpLibFileName, hFile, dwFlags);
        if (hModule == NULL)
        {
            success = false;
            break;
        }
        if (!addModule(tracker, hModule))
        {
            success = false;
            break;
        }
        break;
    }

    dbg_log("[library]", "LoadLibraryExW: %ls 0x%zX", lpLibFileName, hModule);

    if (!LT_Unlock())
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
BOOL LT_FreeLibrary(HMODULE hLibModule)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return false;
    }

    bool success = true;
    for (;;)
    {
        if (!tracker->FreeLibrary(hLibModule))
        {
            success = false;
            break;
        }
        if (!delModule(tracker, hLibModule))
        {
            success = false;
            break;
        }
        break;
    }

    dbg_log("[library]", "FreeLibrary: 0x%zX", hLibModule);

    if (!LT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
void LT_FreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return;
    }

    delModule(tracker, hLibModule);
    dbg_log("[library]", "FreeLibraryAndExitThread: 0x%zX", hLibModule);

    if (!LT_Unlock())
    {
        return;
    }

    tracker->FreeLibraryAndExitThread(hLibModule, dwExitCode);
}

static bool addModule(LibraryTracker* tracker, HMODULE hModule)
{
    if (hModule == NULL)
    {
        return false;
    }
    List* modules = &tracker->Modules;
    // check this module is already exists
    module mod = {
        .hModule = hModule,
        .counter = 0,
        .locked  = false,
    };
    uint idx;
    if (List_Find(modules, &mod, sizeof(mod.hModule), &idx))
    {
        module* module = List_Get(modules, idx);
        module->counter++;
        return true;
    }
    // if it is not exist, add new item
    mod.counter = 1;
    if (!List_Insert(modules, &mod))
    {
        tracker->FreeLibrary(hModule);
        return false;
    }
    return true;
}

static bool delModule(LibraryTracker* tracker, HMODULE hModule)
{
    if (hModule == NULL)
    {
        return false;
    }
    List* modules = &tracker->Modules;
    // search module and decrease counter
    module mod = {
        .hModule = hModule,
    };
    uint idx;
    if (!List_Find(modules, &mod, sizeof(mod.hModule), &idx))
    {
        return false;
    }
    module* module = List_Get(modules, idx);
    module->counter--;
    // mark it is deleted and reserve space
    // for free the loaded DLL in reverse order
    if (module->counter == 0)
    {
        module->hModule = MODULE_UNLOADED;
    }
    return true;
}

__declspec(noinline)
bool LT_LockModule(HMODULE hModule)
{
    bool success = setModuleLocker(hModule, true);
    dbg_log("[library]", "lock module: 0x%zX", hModule);
    return success;
}

__declspec(noinline)
bool LT_UnlockModule(HMODULE hModule)
{
    bool success = setModuleLocker(hModule, false);
    dbg_log("[library]", "unlock module: 0x%zX", hModule);
    return success;
}

__declspec(noinline)
static bool setModuleLocker(HMODULE hModule, bool lock)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return false;
    }

    bool success = false;
    for (;;)
    {
        List* modules = &tracker->Modules;
        // search module list
        module mod = {
            .hModule = hModule,
        };
        uint idx;
        if (!List_Find(modules, &mod, sizeof(mod.hModule), &idx))
        {
            break;
        }
        // set module locker
        module* module = List_Get(modules, idx);
        module->locked = lock;
        success = true;
        break;
    }

    if (!LT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
bool LT_GetStatus(LT_Status* status)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return false;
    }

    List* modules = &tracker->Modules;
    int64 numMods = 0;
    // count the number of the tracked modules
    uint len = modules->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        module* module = List_Get(modules, idx);
        if (module->hModule == NULL)
        {
            continue;
        }
        if (module->hModule != MODULE_UNLOADED)
        {
            numMods++;
        }
        num++;
    }

    if (!LT_Unlock())
    {
        return false;
    }

    status->NumModules = numMods;
    return true;
}

__declspec(noinline)
bool LT_FreeAllMu()
{
    if (!LT_Lock())
    {
        return false;
    }

    errno errno = LT_FreeAll();
    dbg_log("[library]", "FreeAll has been called");

    if (!LT_Unlock())
    {
        return false;
    }

    SetLastErrno(errno);
    return errno == NO_ERROR;
}

__declspec(noinline)
bool LT_Lock()
{
    LibraryTracker* tracker = getTrackerPointer();

    DWORD event = tracker->WaitForSingleObject(tracker->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool LT_Unlock()
{
    LibraryTracker* tracker = getTrackerPointer();

    return tracker->ReleaseMutex(tracker->hMutex);
}

__declspec(noinline)
errno LT_Encrypt()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* list = &tracker->Modules;
    byte* key  = tracker->ModulesKey;
    byte* iv   = tracker->ModulesIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno LT_Decrypt()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* list = &tracker->Modules;
    byte* key  = tracker->ModulesKey;
    byte* iv   = tracker->ModulesIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    dbg_log("[library]", "modules: %zu", list->Len);
    return NO_ERROR;
}

__declspec(noinline)
errno LT_FreeAll()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* modules = &tracker->Modules;
    errno errno   = NO_ERROR;

    // free the loaded DLL in reverse order
    uint len = modules->Len;
    uint idx = modules->Last;
    for (uint num = 0; num < len; idx--)
    {
        module* module = List_Get(modules, idx);
        if (module->hModule == NULL)
        {
            continue;
        }
        // skip locked module
        if (module->locked)
        {
            num++;
            continue;
        }
        if (module->hModule != MODULE_UNLOADED)
        {
            if (!cleanModule(tracker, module))
            {
                errno = ERR_LIBRARY_CLEAN_MODULE;
            }            
        }
        if (!List_Delete(modules, idx))
        {
            errno = ERR_LIBRARY_DELETE_MODULE;
        }
        num++;
    }

    dbg_log("[library]", "modules: %zu", modules->Len);
    return errno;
}

__declspec(noinline)
errno LT_Clean()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* modules = &tracker->Modules;
    errno errno   = NO_ERROR;
    
    // free the loaded DLL in reverse order
    uint idx = modules->Last;
    for (uint num = 0; num < modules->Len; idx--)
    {
        module* module = List_Get(modules, idx);
        if (module->hModule == NULL)
        {
            continue;
        }
        if (module->hModule != MODULE_UNLOADED)
        {
            if (!cleanModule(tracker, module))
            {
                errno = ERR_LIBRARY_CLEAN_MODULE;
            }
        }
        num++;
    }

    // clean module list
    RandBuffer(modules->Data, List_Size(modules));
    if (!List_Free(modules) && errno == NO_ERROR)
    {
        errno = ERR_LIBRARY_FREE_LIST;
    }

    // close mutex
    if (!tracker->CloseHandle(tracker->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_LIBRARY_CLOSE_MUTEX;
    }

    // recover instructions
    if (tracker->NotEraseInstruction)
    {
        if (!recoverTrackerPointer(tracker) && errno == NO_ERROR)
        {
            errno = ERR_LIBRARY_RECOVER_INST;
        }
    }

    dbg_log("[library]", "modules: %zu", modules->Len);
    return errno;
}

static bool cleanModule(LibraryTracker* tracker, module* module)
{
    uint num = module->counter;
    for (uint i = 0; i < num; i++)
    {
        if (!tracker->FreeLibrary(module->hModule))
        {
            return false;
        }
    }
    return true;
}
