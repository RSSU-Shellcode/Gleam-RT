#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_msvcrt.h"
#include "dll_ucrtbase.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "list_md.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "mod_memory.h"
#include "debug.h"

#define BLOCK_MARK_SIZE sizeof(uint)

#define OP_WALK_HEAP_ENCRYPT 1
#define OP_WALK_HEAP_DECRYPT 2
#define OP_WALK_HEAP_ERASE   3

typedef struct {
    uintptr address;
    uint    size;
    bool    isRWX;
    bool    locked;

    // only for rwx region
    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
} memRegion;

typedef struct {
    uintptr address;
    uint32  protect;
    bool    locked;

    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
} memPage;

typedef struct {
    HANDLE hHeap;
    uint32 options;
} heapObject;

typedef struct {
    // store options
    bool NotEraseInstruction;

    // store HashAPI with spoof call
    FindAPI_t FindAPI;

    // API addresses
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    VirtualQuery_t          VirtualQuery;
    GetProcessHeap_t        GetProcessHeap;
    GetProcessHeaps_t       GetProcessHeaps;
    HeapCreate_t            HeapCreate;
    HeapDestroy_t           HeapDestroy;
    HeapAlloc_t             HeapAlloc;
    HeapReAlloc_t           HeapReAlloc;
    HeapFree_t              HeapFree;
    HeapSize_t              HeapSize;
    HeapLock_t              HeapLock;
    HeapUnlock_t            HeapUnlock;
    HeapWalk_t              HeapWalk;
    GlobalAlloc_t           GlobalAlloc;
    GlobalReAlloc_t         GlobalReAlloc;
    GlobalFree_t            GlobalFree;
    LocalAlloc_t            LocalAlloc;
    LocalReAlloc_t          LocalReAlloc;
    LocalFree_t             LocalFree;
    ReleaseMutex_t          ReleaseMutex;
    WaitForSingleObject_t   WaitForSingleObject;
    FlushInstructionCache_t FlushInstructionCache;
    CloseHandle_t           CloseHandle;

    // Cached API addresses
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

    // runtime methods
    malloc_t  RT_malloc;
    calloc_t  RT_calloc;
    realloc_t RT_realloc;
    free_t    RT_free;

    // runtime data
    uint32 PageSize;

    // protect data
    HANDLE hMutex;

    // count global/local heap block
    int64 NumGlobals;
    int64 NumLocals;

    // tracked heap block
    uint  HeapMark;
    int64 NumBlocks;
    byte  BlocksKey[CRYPTO_KEY_SIZE];
    byte  BlocksIV [CRYPTO_IV_SIZE];

    // store memory regions
    List Regions;
    byte RegionsKey[CRYPTO_KEY_SIZE];
    byte RegionsIV [CRYPTO_IV_SIZE];

    // store memory pages
    List Pages;
    byte PagesKey[CRYPTO_KEY_SIZE];
    byte PagesIV [CRYPTO_IV_SIZE];

    // store private heap objects
    List Heaps;
    byte HeapsKey[CRYPTO_KEY_SIZE];
    byte HeapsIV [CRYPTO_IV_SIZE];
} MemoryTracker;

// methods for API redirector
LPVOID MT_VirtualAlloc(LPVOID address, SIZE_T size, DWORD type, DWORD protect);
BOOL   MT_VirtualFree(LPVOID address, SIZE_T size, DWORD type);
BOOL   MT_VirtualProtect(LPVOID address, SIZE_T size, DWORD new, DWORD* old);
SIZE_T MT_VirtualQuery(LPCVOID address, POINTER buffer, SIZE_T length);

HANDLE MT_HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
BOOL   MT_HeapDestroy(HANDLE hHeap);
LPVOID MT_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
LPVOID MT_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
BOOL   MT_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
SIZE_T MT_HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);

HGLOBAL MT_GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
HGLOBAL MT_GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags);
HGLOBAL MT_GlobalFree(HGLOBAL lpMem);
HLOCAL  MT_LocalAlloc(UINT uFlags, SIZE_T dwBytes);
HLOCAL  MT_LocalReAlloc(HLOCAL hMem, SIZE_T dwBytes, UINT uFlags);
HLOCAL  MT_LocalFree(HLOCAL lpMem);

void* __cdecl MT_msvcrt_malloc(uint size);
void* __cdecl MT_msvcrt_calloc(uint num, uint size);
void* __cdecl MT_msvcrt_realloc(void* ptr, uint size);
void  __cdecl MT_msvcrt_free(void* ptr);
uint  __cdecl MT_msvcrt_msize(void* ptr);

void* __cdecl MT_ucrtbase_malloc(uint size);
void* __cdecl MT_ucrtbase_calloc(uint num, uint size);
void* __cdecl MT_ucrtbase_realloc(void* ptr, uint size);
void  __cdecl MT_ucrtbase_free(void* ptr);
uint  __cdecl MT_ucrtbase_msize(void* ptr);

// methods for user
void* MT_MemAlloc(uint size);
void* MT_MemCalloc(uint num, uint size);
void* MT_MemRealloc(void* ptr, uint size);
void  MT_MemFree(void* ptr);
uint  MT_MemSize(void* ptr);
uint  MT_MemCap(void* ptr);
bool  MT_LockRegion(LPVOID address);
bool  MT_UnlockRegion(LPVOID address);
bool  MT_GetStatus(MT_Status* status);
bool  MT_FreeAllMu();

// methods for runtime
bool  MT_Lock();
bool  MT_Unlock();
errno MT_Encrypt();
errno MT_Decrypt();
void  MT_Flush();
bool  MT_FlushMu();
errno MT_FreeAll();
errno MT_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF111111C2
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCDC2
#endif
static MemoryTracker* getTrackerPointer();

static bool initTrackerAPI(MemoryTracker* tracker, Context* context);
static bool updateTrackerPointer(MemoryTracker* tracker);
static bool recoverTrackerPointer(MemoryTracker* tracker);
static bool initTrackerEnvironment(MemoryTracker* tracker, Context* context);
static void eraseTrackerMethods(Context* context);
static void cleanTracker(MemoryTracker* tracker);

static bool allocPage(uintptr address, uint size, uint32 type, uint32 protect);
static bool reserveRegion(MemoryTracker* tracker, uintptr address, uint size);
static bool commitPage(MemoryTracker* tracker, uintptr address, uint size, uint32 protect);
static bool freePage(uintptr address, uint size, uint32 type);
static bool decommitPage(MemoryTracker* tracker, uintptr address, uint size);
static bool releaseRegion(MemoryTracker* tracker, uintptr address, uint size);
static bool deletePage(MemoryTracker* tracker, uintptr address, uint size);
static void protectPage(uintptr address, uint size, uint32 protect);
static bool addHeapObject(MemoryTracker* tracker, HANDLE hHeap, uint32 options);
static bool delHeapObject(MemoryTracker* tracker, HANDLE hHeap);
static uint calcHeapMark(MemoryTracker* tracker, uintptr addr, uint size);

static uint32 replacePageProtect(uint32 protect);
static bool   isPageTypeTrackable(uint32 type);
static bool   isPageProtectWriteable(uint32 protect);
static bool   adjustPageProtect(MemoryTracker* tracker, memPage* page);
static bool   recoverPageProtect(MemoryTracker* tracker, memPage* page);
static bool   setRegionLocker(uintptr address, bool lock);

static bool encryptPage(MemoryTracker* tracker, memPage* page);
static bool decryptPage(MemoryTracker* tracker, memPage* page);
static bool isEmptyPage(MemoryTracker* tracker, memPage* page);
static bool encryptRWXRegion(MemoryTracker* tracker, memRegion* region);
static bool decryptRWXRegion(MemoryTracker* tracker, memRegion* region);
static void deriveKey(MemoryTracker* tracker, memPage* page, byte* key);
static bool encryptHeapBlocks(HANDLE hHeap);
static bool decryptHeapBlocks(HANDLE hHeap);
static bool eraseHeapBlocks(HANDLE hHeap);
static bool walkHeapBlocks(HANDLE hHeap, int operation);
static bool cleanPage(MemoryTracker* tracker, memPage* page);

MemoryTracker_M* InitMemoryTracker(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr trackerAddr = addr + LAYOUT_MT_STRUCT + RandUintN(addr, 128);
    uintptr moduleAddr  = addr + LAYOUT_MT_MODULE + RandUintN(addr, 128);
    // allocate tracker memory
    MemoryTracker* tracker = (MemoryTracker*)trackerAddr;
    mem_init(tracker, sizeof(MemoryTracker));
    // store options
    tracker->NotEraseInstruction = context->NotEraseInstruction;
    // store HashAPI method
    tracker->FindAPI = context->FindAPI;
    // initialize tracker
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errno = ERR_MEMORY_INIT_API;
            break;
        }
        if (!updateTrackerPointer(tracker))
        {
            errno = ERR_MEMORY_UPDATE_PTR;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errno = ERR_MEMORY_INIT_ENV;
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
    MemoryTracker_M* module = (MemoryTracker_M*)moduleAddr;
    // methods for API redirector
    module->VirtualAlloc   = GetFuncAddr(&MT_VirtualAlloc);
    module->VirtualFree    = GetFuncAddr(&MT_VirtualFree);
    module->VirtualProtect = GetFuncAddr(&MT_VirtualProtect);
    module->VirtualQuery   = GetFuncAddr(&MT_VirtualQuery);
    module->HeapCreate     = GetFuncAddr(&MT_HeapCreate);
    module->HeapDestroy    = GetFuncAddr(&MT_HeapDestroy);
    module->HeapAlloc      = GetFuncAddr(&MT_HeapAlloc);
    module->HeapReAlloc    = GetFuncAddr(&MT_HeapReAlloc);
    module->HeapFree       = GetFuncAddr(&MT_HeapFree);
    module->HeapSize       = GetFuncAddr(&MT_HeapSize);
    module->GlobalAlloc    = GetFuncAddr(&MT_GlobalAlloc);
    module->GlobalReAlloc  = GetFuncAddr(&MT_GlobalReAlloc);
    module->GlobalFree     = GetFuncAddr(&MT_GlobalFree);
    module->LocalAlloc     = GetFuncAddr(&MT_LocalAlloc);
    module->LocalReAlloc   = GetFuncAddr(&MT_LocalReAlloc);
    module->LocalFree      = GetFuncAddr(&MT_LocalFree);
    // redirectors about msvcrt.dll
    module->msvcrt_malloc  = GetFuncAddr(&MT_msvcrt_malloc);
    module->msvcrt_calloc  = GetFuncAddr(&MT_msvcrt_calloc);
    module->msvcrt_realloc = GetFuncAddr(&MT_msvcrt_realloc);
    module->msvcrt_free    = GetFuncAddr(&MT_msvcrt_free);
    module->msvcrt_msize   = GetFuncAddr(&MT_msvcrt_msize);
    // redirectors about ucrtbase.dll
    module->ucrtbase_malloc  = GetFuncAddr(&MT_ucrtbase_malloc);
    module->ucrtbase_calloc  = GetFuncAddr(&MT_ucrtbase_calloc);
    module->ucrtbase_realloc = GetFuncAddr(&MT_ucrtbase_realloc);
    module->ucrtbase_free    = GetFuncAddr(&MT_ucrtbase_free);
    module->ucrtbase_msize   = GetFuncAddr(&MT_ucrtbase_msize);
    // methods for user
    module->Alloc   = GetFuncAddr(&MT_MemAlloc);
    module->Calloc  = GetFuncAddr(&MT_MemCalloc);
    module->Realloc = GetFuncAddr(&MT_MemRealloc);
    module->Free    = GetFuncAddr(&MT_MemFree);
    module->Size    = GetFuncAddr(&MT_MemSize);
    module->Cap     = GetFuncAddr(&MT_MemCap);
    module->LockRegion   = GetFuncAddr(&MT_LockRegion);
    module->UnlockRegion = GetFuncAddr(&MT_UnlockRegion);
    module->GetStatus    = GetFuncAddr(&MT_GetStatus);
    module->FreeAllMu    = GetFuncAddr(&MT_FreeAllMu);
    // methods for runtime
    module->Lock    = GetFuncAddr(&MT_Lock);
    module->Unlock  = GetFuncAddr(&MT_Unlock);
    module->Encrypt = GetFuncAddr(&MT_Encrypt);
    module->Decrypt = GetFuncAddr(&MT_Decrypt);
    module->Flush   = GetFuncAddr(&MT_Flush);
    module->FlushMu = GetFuncAddr(&MT_FlushMu);
    module->FreeAll = GetFuncAddr(&MT_FreeAll);
    module->Clean   = GetFuncAddr(&MT_Clean);
    // data for sysmon
    module->hMutex = tracker->hMutex;
    return module;
}

__declspec(noinline)
static bool initTrackerAPI(MemoryTracker* tracker, Context* context)
{
    typedef struct { 
        uint mHash; uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xC3D7F454B0F1367C, 0x29CAA1EB805BCCA9, 0xC3DD316E122A78F8 }, // GetProcessHeap
        { 0x1C65BE5C37AA95C6, 0x9D74C15113BF9588, 0x2379B99B83FE4750 }, // GetProcessHeaps
        { 0x9B753693D7581756, 0xF68CC0D9B9C7E64A, 0x47B324F64EA3ADF6 }, // HeapCreate
        { 0xD9394045734EC67B, 0x1F1628B71910002E, 0xB03D2BBD67B6E11E }, // HeapDestroy
        { 0xCBA2FFCEBBDA6311, 0x2D0E7FFC46A974FA, 0x4CCE4C0F745961A8 }, // HeapAlloc
        { 0x7648F54F09FFF6A3, 0x6926629478847770, 0x0600B5236324CF2C }, // HeapReAlloc
        { 0x7859FB6ADEDBFEB3, 0x76F24504A5AFF289, 0xB403CEDF926E940E }, // HeapFree
        { 0xEB321C1883CE223B, 0xB6A30D8BDD946A2A, 0x6597C0FBEC5BF0FF }, // HeapSize
        { 0x1B1254B5345E349A, 0xDA42A1FD792C69EF, 0x70A8A70633AB538C }, // HeapLock
        { 0x177DFB4BF6DC672F, 0x15E96139668EA7F7, 0x81CF522DADFDF307 }, // HeapUnlock
        { 0x02DBC87FF7E6B0FC, 0xBD878594F6327709, 0xF791420ABA1DD1C4 }, // HeapWalk
        { 0xCCBAD8DAFD4E4D34, 0xEC3023B51707D6B2, 0xD8EBAD02682CC5E2 }, // GlobalAlloc
        { 0x1D4619640614CC09, 0xBEA69DC6B8731125, 0x5BD8B2E77A4C988B }, // GlobalReAlloc
        { 0x715089473E4EED43, 0xB25481578CBAF063, 0x159E7D8AD37AB543 }, // GlobalFree
        { 0x2E02977F2A4BAD1D, 0xB32694F68FE8E9FC, 0x9F3BA31861DB7C02 }, // LocalAlloc
        { 0xDAFB72DF65BA28E9, 0x2361FBDA61D3BAF5, 0x44D4C7FE4EB9DD69 }, // LocalReAlloc
        { 0x52AD04FD4B6F5071, 0x29ADFEAAC6FDF166, 0xF5271D3ECF4E1834 }, // LocalFree
    };
#elif _WIN32
    {
        { 0x2B2C8947, 0x591F6D82, 0x23CCA605 }, // GetProcessHeap
        { 0xDC1F8608, 0xF9054AF4, 0x2F9DE4C9 }, // GetProcessHeaps
        { 0xC117F387, 0x89B7E7BE, 0x107ED3A3 }, // HeapCreate
        { 0x33DAD8BE, 0x4E77EB1F, 0x82826372 }, // HeapDestroy
        { 0xA94D0696, 0x3CE0326D, 0xD00D5308 }, // HeapAlloc
        { 0xC6E6CCDB, 0xFEC5B9B9, 0xFEF6F936 }, // HeapReAlloc
        { 0xD1A2B293, 0x348015B0, 0x30A9FCCE }, // HeapFree
        { 0x3135D780, 0xC6621F51, 0x10B4DDD1 }, // HeapSize
        { 0x12210591, 0x12E75344, 0x092B59BB }, // HeapLock
        { 0x007809E7, 0x5E43C9AA, 0x14D80281 }, // HeapUnlock
        { 0x9793DD33, 0xA3DC2B5E, 0x21E6D11E }, // HeapWalk
        { 0xD5B84921, 0xA8709B42, 0x7160502F }, // GlobalAlloc
        { 0x56C5336E, 0x41B8D2A6, 0x0834A19B }, // GlobalReAlloc
        { 0xACE5842C, 0xDC734542, 0x47A785C3 }, // GlobalFree
        { 0xAC5F330D, 0x37007239, 0x94F28D59 }, // LocalAlloc
        { 0xB350CABB, 0x6E32C276, 0xAEF8A48D }, // LocalReAlloc
        { 0x7F244816, 0xF9BF581E, 0x0F05B794 }, // LocalFree
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item = list[i];
        void*  proc = context->FindAPI(item.mHash, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    tracker->GetProcessHeap  = list[0x00].proc;
    tracker->GetProcessHeaps = list[0x01].proc;
    tracker->HeapCreate      = list[0x02].proc;
    tracker->HeapDestroy     = list[0x03].proc;
    tracker->HeapAlloc       = list[0x04].proc;
    tracker->HeapReAlloc     = list[0x05].proc;
    tracker->HeapFree        = list[0x06].proc;
    tracker->HeapSize        = list[0x07].proc;
    tracker->HeapLock        = list[0x08].proc;
    tracker->HeapUnlock      = list[0x09].proc;
    tracker->HeapWalk        = list[0x0A].proc;
    tracker->GlobalAlloc     = list[0x0B].proc;
    tracker->GlobalReAlloc   = list[0x0C].proc;
    tracker->GlobalFree      = list[0x0D].proc;
    tracker->LocalAlloc      = list[0x0E].proc;
    tracker->LocalReAlloc    = list[0x0F].proc;
    tracker->LocalFree       = list[0x10].proc;

    tracker->VirtualAlloc          = context->VirtualAlloc;
    tracker->VirtualFree           = context->VirtualFree;
    tracker->VirtualProtect        = context->VirtualProtect;
    tracker->VirtualQuery          = context->VirtualQuery;
    tracker->ReleaseMutex          = context->ReleaseMutex;
    tracker->WaitForSingleObject   = context->WaitForSingleObject;
    tracker->FlushInstructionCache = context->FlushInstructionCache;
    tracker->CloseHandle           = context->CloseHandle;
    return true;
}

// CANNOT merge updateTrackerPointer and recoverTrackerPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateTrackerPointer(MemoryTracker* tracker)
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
static bool recoverTrackerPointer(MemoryTracker* tracker)
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
static bool initTrackerEnvironment(MemoryTracker* tracker, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_MT_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return false;
    }
    tracker->hMutex = hMutex;
    // generate the random heap mark
    tracker->HeapMark = RandUint((uint64)hMutex);
    // initialize memory region and page list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Regions, &ctx, sizeof(memRegion));
    List_Init(&tracker->Pages,   &ctx, sizeof(memPage));
    List_Init(&tracker->Heaps,   &ctx, sizeof(heapObject));
    // set crypto context data
    RandBuffer(tracker->RegionsKey, CRYPTO_KEY_SIZE);
    RandBuffer(tracker->RegionsIV,  CRYPTO_IV_SIZE);
    RandBuffer(tracker->PagesKey,   CRYPTO_KEY_SIZE);
    RandBuffer(tracker->PagesIV,    CRYPTO_IV_SIZE);
    RandBuffer(tracker->HeapsKey,   CRYPTO_KEY_SIZE);
    RandBuffer(tracker->HeapsIV,    CRYPTO_IV_SIZE);
    RandBuffer(tracker->BlocksKey,  CRYPTO_KEY_SIZE);
    RandBuffer(tracker->BlocksIV,   CRYPTO_IV_SIZE);
    // copy runtime methods
    tracker->RT_malloc  = context->malloc;
    tracker->RT_calloc  = context->calloc;
    tracker->RT_realloc = context->realloc;
    tracker->RT_free    = context->free;
    // copy runtime context data
    tracker->PageSize = context->PageSize;
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
static void cleanTracker(MemoryTracker* tracker)
{
    if (tracker->CloseHandle != NULL && tracker->hMutex != NULL)
    {
        tracker->CloseHandle(tracker->hMutex);
    }
    List_Free(&tracker->Regions);
    List_Free(&tracker->Pages);
    List_Free(&tracker->Heaps);
}

// updateTrackerPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateTrackerPointer will fail.
#pragma optimize("", off)
static MemoryTracker* getTrackerPointer()
{
    uintptr pointer = TRACKER_POINTER;
    return (MemoryTracker*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
LPVOID MT_VirtualAlloc(LPVOID address, SIZE_T size, DWORD type, DWORD protect)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    dbg_log(
        "[memory]", "VirtualAlloc: 0x%zX, 0x%zX, 0x%X, 0x%X",
        address, size, type, protect
    );

    // adjust protect at sometime
    protect = replacePageProtect(protect);

    LPVOID page;
    bool success = false;
    for (;;)
    {
        if (type == (MEM_COMMIT|MEM_RESERVE) && protect == PAGE_EXECUTE_READWRITE)
        {
            // for make the allocation type is Read+Write
            page = tracker->VirtualAlloc(address, size, type, PAGE_READWRITE);
            if (page == NULL)
            {
                break;
            }
            DWORD old;
            if (!tracker->VirtualProtect(page, size, PAGE_EXECUTE_READWRITE, &old))
            {
                break;
            }
            memRegion region = {
                .address = (uintptr)page,
                .size    = size,
                .isRWX   = true,
                .locked  = false,
            };
            if (!List_Insert(&tracker->Regions, &region))
            {
                break;
            }
        } else {
            page = tracker->VirtualAlloc(address, size, type, protect);
            if (page == NULL)
            {
                break;
            }
            if (!allocPage((uintptr)page, size, type, protect))
            {
                break;
            }
        }
        success = true;
        break;
    }

    if (!MT_Unlock())
    {
        if (page != NULL)
        {
            tracker->VirtualFree(page, 0, MEM_RELEASE);
        }
        return NULL;
    }
    if (!success)
    {
        if (page != NULL)
        {
            tracker->VirtualFree(page, 0, MEM_RELEASE);
        }
        return NULL;
    }
    return page;
}

static bool allocPage(uintptr address, uint size, uint32 type, uint32 protect)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!isPageTypeTrackable(type))
    {
        return true;
    }
    switch (type & 0xF000)
    {
    case MEM_COMMIT:
        return commitPage(tracker, address, size, protect);
    case MEM_RESERVE:
        return reserveRegion(tracker, address, size);
    case MEM_COMMIT|MEM_RESERVE:
        if (!reserveRegion(tracker, address, size))
        {
            return false;
        }
        return commitPage(tracker, address, size, protect);
    default:
        return false;
    }
}

static bool reserveRegion(MemoryTracker* tracker, uintptr address, uint size)
{
    memRegion region = {
        .address = address,
        .size    = size,
        .isRWX   = false,
        .locked  = false,
    };
    return List_Insert(&tracker->Regions, &region);
}

#pragma optimize("t", on)
static bool commitPage(MemoryTracker* tracker, uintptr address, uint size, uint32 protect)
{
    // copy memory to register for improve performance
    register uint pageSize = tracker->PageSize;
    register uint numPage  = size / pageSize;
    if ((size % pageSize) != 0)
    {
        numPage++;
    }
    register List* pages = &tracker->Pages;
    memPage page = {
        .protect = protect,
        .locked  = false,
    };
    for (uint i = 0; i < numPage; i++)
    {
        page.address = address + i * pageSize;
        if (!List_Insert(pages, &page))
        {
            return false;
        }
    }
    return true;
}
#pragma optimize("t", off)

__declspec(noinline)
BOOL MT_VirtualFree(LPVOID address, SIZE_T size, DWORD type)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    dbg_log(
        "[memory]", "VirtualFree: 0x%zX, 0x%zX, 0x%X",
        address, size, type
    );

    BOOL success = false;
    for (;;)
    {
        if (!tracker->VirtualFree(address, size, type))
        {
            break;
        }
        if (!freePage((uintptr)address, size, type))
        {
            break;
        }
        success = true;
        break;
    }

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

static bool freePage(uintptr address, uint size, uint32 type)
{
    MemoryTracker* tracker = getTrackerPointer();

    switch (type & 0xF000)
    {
    case MEM_DECOMMIT:
        return decommitPage(tracker, address, size);
    case MEM_RELEASE:
        return releaseRegion(tracker, address, size);
    default:
        return false;
    }
}

static bool decommitPage(MemoryTracker* tracker, uintptr address, uint size)
{
    if (size != 0)
    {
        return deletePage(tracker, address, size);
    }
    // search memory regions list
    register List* regions = &tracker->Regions;
    register uint len = regions->Len;
    register uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memRegion* region = List_Get(regions, idx);
        if (region->address == 0)
        {
            continue;
        }
        if (region->address != address)
        {
            num++;
            continue;
        }
        return deletePage(tracker, region->address, region->size);
    }
    return false;
}

static bool releaseRegion(MemoryTracker* tracker, uintptr address, uint size)
{
    if (size != 0)
    {
        return false;
    }
    // search memory regions list
    register List* regions = &tracker->Regions;
    register uint len = regions->Len;
    register uint idx = 0;
    register memRegion* region;
    bool found = false;
    for (uint num = 0; num < len; idx++)
    {
        region = List_Get(regions, idx);
        if (region->address == 0)
        {
            continue;
        }
        if (region->address != address)
        {
            num++;
            continue;
        }
        if (!deletePage(tracker, region->address, region->size))
        {
            return false;
        }
        if (!List_Delete(regions, idx))
        {
            return false;
        }
        found = true;
        // maybe exist same region, so need continue
        num++;
    }
    return found;
}

#pragma optimize("t", on)
static bool deletePage(MemoryTracker* tracker, uintptr address, uint size)
{
    register uint  pageSize = tracker->PageSize;
    register List* pages    = &tracker->Pages;

    register uint len = pages->Len;
    register uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memPage* page = List_Get(pages, idx);
        if (page->address == 0)
        {
            continue;
        }
        if ((page->address + pageSize <= address) || (page->address >= address + size))
        {
            num++;
            continue;
        }
        // remove page in list
        if (!List_Delete(pages, idx))
        {
            return false;
        }
        num++;
    }
    return true;
}
#pragma optimize("t", off)

__declspec(noinline)
BOOL MT_VirtualProtect(LPVOID address, SIZE_T size, DWORD new, DWORD* old)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    dbg_log(
        "[memory]", "VirtualProtect: 0x%zX, 0x%zX, 0x%X", 
        address, size, new
    );

    BOOL success = false;
    for (;;)
    {
        if (!tracker->VirtualProtect(address, size, new, old))
        {
            break;
        }
        protectPage((uintptr)address, size, new);
        success = true;
        break;
    }

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

static void protectPage(uintptr address, uint size, uint32 protect)
{
    MemoryTracker* tracker = getTrackerPointer();

    register uint  pageSize = tracker->PageSize;
    register List* pages    = &tracker->Pages;

    register uint len = pages->Len;
    register uint idx = 0;
    register memPage* page;
    for (uint num = 0; num < len; idx++)
    {
        page = List_Get(pages, idx);
        if (page->address == 0)
        {
            continue;
        }
        if ((page->address + pageSize <= address) || (page->address >= address + size))
        {
            num++;
            continue;
        }
        page->protect = protect;
        num++;
    }
}

__declspec(noinline)
SIZE_T MT_VirtualQuery(LPCVOID address, POINTER buffer, SIZE_T length)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return 0;
    }

    dbg_log("[memory]", "VirtualQuery: 0x%zX", address);

    uint size = tracker->VirtualQuery(address, buffer, length);

    if (!MT_Unlock())
    {
        return 0;
    }
    return size;
}

__declspec(noinline)
HANDLE MT_HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    HANDLE hHeap;

    bool success = false;
    for (;;)
    {
        hHeap = tracker->HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
        if (hHeap == NULL)
        {
            break;
        }
        if (!addHeapObject(tracker, hHeap, flOptions))
        {
            break;
        }
        success = true;
        break;
    }

    dbg_log(
        "[memory]", "HeapCreate: 0x%X, 0x%zX, 0x%zX",
        flOptions, dwInitialSize, dwMaximumSize
    );

    if (!MT_Unlock())
    {
        return NULL;
    }

    if (!success)
    {
        return NULL;
    }
    return hHeap;
}

static bool addHeapObject(MemoryTracker* tracker, HANDLE hHeap, uint32 options)
{
    heapObject heap = {
        .hHeap   = hHeap,
        .options = options,
    };
    if (!List_Insert(&tracker->Heaps, &heap))
    {
        tracker->HeapDestroy(hHeap);
        return false;
    }
    return true;
}

__declspec(noinline)
BOOL MT_HeapDestroy(HANDLE hHeap)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    BOOL success = false;
    for (;;)
    {
        if (!tracker->HeapDestroy(hHeap))
        {
            break;
        }
        if (!delHeapObject(tracker, hHeap))
        {
            break;
        }
        success = true;
        break;
    }

    dbg_log("[memory]", "HeapDestroy: 0x%X", hHeap);

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

static bool delHeapObject(MemoryTracker* tracker, HANDLE hHeap)
{
    List* heaps = &tracker->Heaps;
    heapObject heap = {
        .hHeap = hHeap,
    };
    uint index;
    if (!List_Find(heaps, &heap, sizeof(heap.hHeap), &index))
    {
        return false;
    }
    if (!List_Delete(heaps, index))
    {
        return false;
    }
    return true;
}

// +-------------+-------------+-------------+
// | heap header | user buffer | random mark |
// +-------------+-------------+-------------+
// |     var     |     var     |     uint    |
// +-------------+-------------+-------------+

__declspec(noinline)
LPVOID MT_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    LPVOID address;
    for (;;)
    {
        address = tracker->HeapAlloc(hHeap, dwFlags, dwBytes + BLOCK_MARK_SIZE);
        if (address == NULL)
        {
            break;
        }
        // write heap block mark
        uint* tail = (uint*)((uintptr)address + dwBytes);
        *tail = calcHeapMark(tracker, (uintptr)address, dwBytes);
        // update counter
        tracker->NumBlocks++;
        break;
    }

    dbg_log("[memory]", "HeapAlloc: 0x%zX, 0x%zX", address, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }
    return address;
}

__declspec(noinline)
LPVOID MT_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    LPVOID address = NULL;
    for (;;)
    {
        if (lpMem == NULL)
        {
            break;
        }
        SIZE_T size = tracker->HeapSize(hHeap, dwFlags, lpMem);
        if (size == (SIZE_T)(-1))
        {
            break;
        }
        // erase old block mark before realloc
        bool marked = false;
        if (size >= BLOCK_MARK_SIZE)
        {
            uintptr block = (uintptr)lpMem;
            uint  bSize = size - BLOCK_MARK_SIZE;
            uint* mark  = (uint*)(block + bSize);
            if (calcHeapMark(tracker, block, bSize) == *mark)
            {
                mem_init(mark, BLOCK_MARK_SIZE);
                marked = true;
            }
        }
        address = tracker->HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes + BLOCK_MARK_SIZE);
        if (address == NULL)
        {
            break;
        }
        // write new heap block mark
        uint* tail = (uint*)((uintptr)address + dwBytes);
        *tail = calcHeapMark(tracker, (uintptr)address, dwBytes);
        // update counter
        if (!marked)
        {
            tracker->NumBlocks++;
        }
        break;
    }

    dbg_log("[memory]", "HeapReAlloc: 0x%zX, 0x%zX", address, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }
    return address;
}

__declspec(noinline)
BOOL MT_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    BOOL success = false;
    for (;;)
    {
        // special case
        if (lpMem == NULL)
        {
            success = tracker->HeapFree(hHeap, dwFlags, lpMem);
            break;
        }
        // check it is a marked block before free
        SIZE_T size = tracker->HeapSize(hHeap, dwFlags, lpMem);
        if (size == (SIZE_T)(-1))
        {
            break;
        }
        bool marked = false;
        if (size >= BLOCK_MARK_SIZE)
        {
            uintptr block = (uintptr)lpMem;
            uint bSize = size - BLOCK_MARK_SIZE;
            uint mark  = *(uint*)(block + bSize);
            if (calcHeapMark(tracker, block, bSize) == mark)
            {
                marked = true;
            }
        }
        // erase heap block data and mark before free
        mem_init(lpMem, size);
        if (!tracker->HeapFree(hHeap, dwFlags, lpMem))
        {
            break;
        }
        // update counter
        if (marked)
        {
            tracker->NumBlocks--;
        }
        success = true;
        break;
    }

    dbg_log("[memory]", "HeapFree: 0x%zX", lpMem);

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
SIZE_T MT_HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return (SIZE_T)(-1);
    }

    SIZE_T size = (SIZE_T)(-1);
    for (;;)
    {
        if (lpMem == NULL)
        {
            break;
        }
        size = tracker->HeapSize(hHeap, dwFlags, lpMem);
        if (size < BLOCK_MARK_SIZE)
        {
            break;
        }
        // check it is a marked block and adjust the return size
        uintptr block = (uintptr)lpMem;
        uint bSize = size - BLOCK_MARK_SIZE;
        uint mark  = *(uint*)(block + bSize);
        if (calcHeapMark(tracker, block, bSize) == mark)
        {
            size -= BLOCK_MARK_SIZE;
        }
        break;
    }

    dbg_log("[memory]", "HeapSize: %zu, addr: 0x%zX", size, lpMem);

    if (!MT_Unlock())
    {
        return (SIZE_T)(-1);
    }
    return size;
}

__declspec(noinline)
HGLOBAL MT_GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    HGLOBAL hGlobal;
    for (;;)
    {
        hGlobal = tracker->GlobalAlloc(uFlags, dwBytes);
        if (hGlobal == NULL)
        {
            break;
        }
        // update counter
        tracker->NumGlobals++;
        break;
    }

    dbg_log("[memory]", "GlobalAlloc: 0x%zX, 0x%zX", hGlobal, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }
    return hGlobal;
}

__declspec(noinline)
HGLOBAL MT_GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    HGLOBAL hGlobal = tracker->GlobalReAlloc(hMem, dwBytes, uFlags);

    dbg_log("[memory]", "GlobalReAlloc: 0x%zX, 0x%zX", hGlobal, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }
    return hGlobal;
}

__declspec(noinline)
HGLOBAL MT_GlobalFree(HGLOBAL lpMem)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    HGLOBAL hGlobal;
    for (;;)
    {
        hGlobal = tracker->GlobalFree(lpMem);
        if (hGlobal != NULL)
        {
            break;
        }
        if (lpMem != NULL)
        {
            tracker->NumGlobals--;
        }
        break;
    }

    dbg_log("[memory]", "GlobalFree: 0x%zX", lpMem);

    if (!MT_Unlock())
    {
        return false;
    }
    return hGlobal;
}

__declspec(noinline)
HLOCAL MT_LocalAlloc(UINT uFlags, SIZE_T dwBytes)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    HLOCAL hLocal;
    for (;;)
    {
        hLocal = tracker->LocalAlloc(uFlags, dwBytes);
        if (hLocal == NULL)
        {
            break;
        }
        // update counter
        tracker->NumLocals++;
        break;
    }

    dbg_log("[memory]", "LocalAlloc: 0x%zX, 0x%zX", hLocal, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }
    return hLocal;
}

__declspec(noinline)
HLOCAL MT_LocalReAlloc(HLOCAL hMem, SIZE_T dwBytes, UINT uFlags)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    HLOCAL hLocal = tracker->LocalReAlloc(hMem, dwBytes, uFlags);

    dbg_log("[memory]", "LocalReAlloc: 0x%zX, 0x%zX", hLocal, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }
    return hLocal;
}

__declspec(noinline)
HLOCAL MT_LocalFree(HLOCAL lpMem)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    HLOCAL hLocal;
    for (;;)
    {
        hLocal = tracker->LocalFree(lpMem);
        if (hLocal != NULL)
        {
            break;
        }
        if (lpMem != NULL)
        {
            tracker->NumLocals--;
        }
        break;
    }

    dbg_log("[memory]", "LocalFree: 0x%zX", lpMem);

    if (!MT_Unlock())
    {
        return false;
    }
    return hLocal;
}

__declspec(noinline) 
void* __cdecl MT_msvcrt_malloc(uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        // try to get API address from cache
        msvcrt_malloc_t malloc = tracker->msvcrt_malloc;
        if (malloc == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x136CB071EF4DA0EF;
            uint pHash = 0xA4E537E24F07D662;
            uint hKey  = 0x329B6DA8E90118ED;
        #elif _WIN32
            uint mHash = 0x485F281D;
            uint pHash = 0xBBEC7575;
            uint hKey  = 0x1AECAE06;
        #endif
            malloc = tracker->FindAPI(mHash, pHash, hKey);
            if (malloc == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->msvcrt_malloc = malloc;
        }
        // call malloc
        address = malloc(size + BLOCK_MARK_SIZE);
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        // write heap block mark
        uint* tail = (uint*)((uintptr)address + size);
        *tail = calcHeapMark(tracker, (uintptr)address, size);
        // update counter
        tracker->NumBlocks++;
        lastErr = GetLastErrno();
        break;
    }

    dbg_log("[memory]", "msvcrt.malloc: 0x%zX, size: %zu", address, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void* __cdecl MT_msvcrt_calloc(uint num, uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        // try to get API address from cache
        msvcrt_calloc_t calloc = tracker->msvcrt_calloc;
        if (calloc == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x24BEF2B1B592657B;
            uint pHash = 0x63F6205AAA82CF4E;
            uint hKey  = 0xC5BAF8FCBD2172F4;
        #elif _WIN32
            uint mHash = 0x486DC33E;
            uint pHash = 0x1EF14D6E;
            uint hKey  = 0x9E9C4BA5;
        #endif
            calloc = tracker->FindAPI(mHash, pHash, hKey);
            if (calloc == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->msvcrt_calloc = calloc;
        }
        // call calloc
        address = calloc(num + BLOCK_MARK_SIZE, size);
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        if (num == 0 || size == 0)
        {
            lastErr = GetLastErrno();
            break;
        }
        // write heap block mark
        uint total = (num + BLOCK_MARK_SIZE) * size - BLOCK_MARK_SIZE;
        uint* tail = (uint*)((uintptr)address + total);
        *tail = calcHeapMark(tracker, (uintptr)address, total);
        // update counter
        tracker->NumBlocks++;
        lastErr = GetLastErrno();
        break;
    }

    dbg_log("[memory]", "msvcrt.calloc: 0x%zX, num: %zu size: %zu", num, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void* __cdecl MT_msvcrt_realloc(void* ptr, uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        // try to get API address from cache
        msvcrt_realloc_t realloc = tracker->msvcrt_realloc;
        if (realloc == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x135AAA35D376EF41;
            uint pHash = 0x51A8F630FC8E67C4;
            uint hKey  = 0xFF7BCB0F578542FA;
        #elif _WIN32
            uint mHash = 0x4E56C9CF;
            uint pHash = 0xBE2BFEFB;
            uint hKey  = 0xCF70F7F3;
        #endif
            realloc = tracker->FindAPI(mHash, pHash, hKey);
            if (realloc == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->msvcrt_realloc = realloc;
        }
        msvcrt_msize_t msize = tracker->msvcrt_msize;
        if (msize == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xFF919BD0F407C246;
            uint pHash = 0x5E0B85F02E4FEC22;
            uint hKey  = 0x9855E214CD9310A8;
        #elif _WIN32
            uint mHash = 0x3DD7996A;
            uint pHash = 0x845CB2FD;
            uint hKey  = 0x9591B59B;
        #endif
            msize = tracker->FindAPI(mHash, pHash, hKey);
            if (msize == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->msvcrt_msize = msize;
        }
        // get old size about heap block
        SIZE_T oSize = 0;
        if (ptr != NULL)
        {
            oSize = msize(ptr);
            if (oSize == (SIZE_T)(-1))
            {
                lastErr = GetLastErrno();
                break;
            }
        }
        // erase old block mark before realloc
        bool marked = false;
        if (oSize >= BLOCK_MARK_SIZE)
        {
            uintptr block = (uintptr)ptr;
            uint  bSize = oSize - BLOCK_MARK_SIZE;
            uint* mark  = (uint*)(block + bSize);
            if (calcHeapMark(tracker, block, bSize) == *mark)
            {
                mem_init(mark, BLOCK_MARK_SIZE);
                marked = true;
            }
        }
        address = realloc(ptr, size + BLOCK_MARK_SIZE);
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        // write heap block mark
        uint* tail = (uint*)((uintptr)address + size);
        *tail = calcHeapMark(tracker, (uintptr)address, size);
        // update counter
        if (!marked)
        {
            tracker->NumBlocks++;
        }
        lastErr = GetLastErrno();
        break;
    }

    dbg_log("[memory]", "msvcrt.realloc: 0x%zX, ptr: 0x%zX size: %zu", address, ptr, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void __cdecl MT_msvcrt_free(void* ptr)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return;
    }

    errno lastErr = NO_ERROR;
    for (;;)
    {
        // try to get API address from cache
        msvcrt_free_t free = tracker->msvcrt_free;
        if (free == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xDE6C9ADEF3C34189;
            uint pHash = 0x0E9B5E427C74F4E4;
            uint hKey  = 0xA57ED0DE75FBF6D8;
        #elif _WIN32
            uint mHash = 0x14AC52AA;
            uint pHash = 0xA5B6E022;
            uint hKey  = 0x626D1BC5;
        #endif
            free = tracker->FindAPI(mHash, pHash, hKey);
            if (free == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->msvcrt_free = free;
        }
        msvcrt_msize_t msize = tracker->msvcrt_msize;
        if (msize == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xFF919BD0F407C246;
            uint pHash = 0x5E0B85F02E4FEC22;
            uint hKey  = 0x9855E214CD9310A8;
        #elif _WIN32
            uint mHash = 0x3DD7996A;
            uint pHash = 0x845CB2FD;
            uint hKey  = 0x9591B59B;
        #endif
            msize = tracker->FindAPI(mHash, pHash, hKey);
            if (msize == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->msvcrt_msize = msize;
        }
        // special case
        if (ptr == NULL)
        {
            free(ptr);
            lastErr = GetLastErrno();
            break;
        }
        // get old size about heap block
        SIZE_T oSize = msize(ptr);
        if (oSize == (SIZE_T)(-1))
        {
            lastErr = GetLastErrno();
            break;
        }
        // check it is a marked block before free
        bool marked = false;
        if (oSize >= BLOCK_MARK_SIZE)
        {
            uintptr block = (uintptr)ptr;
            uint bSize = oSize - BLOCK_MARK_SIZE;
            uint mark  = *(uint*)(block + bSize);
            if (calcHeapMark(tracker, block, bSize) == mark)
            {
                marked = true;
            }
        }
        mem_init(ptr, oSize);
        free(ptr);
        // update counter
        if (marked)
        {
            tracker->NumBlocks--;
        }
        lastErr = GetLastErrno();
        break;
    }

    dbg_log("[memory]", "msvcrt.free, ptr: 0x%zX", ptr);

    if (!MT_Unlock())
    {
        return;
    }

    SetLastErrno(lastErr);
}

__declspec(noinline)
uint __cdecl MT_msvcrt_msize(void* ptr)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return (SIZE_T)(-1);
    }

    SIZE_T memSize = (SIZE_T)(-1);
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        if (ptr == NULL)
        {
            lastErr = MSVCRT_EINVAL;
            break;
        }
        // try to get API address from cache
        msvcrt_msize_t msize = tracker->msvcrt_msize;
        if (msize == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xFF919BD0F407C246;
            uint pHash = 0x5E0B85F02E4FEC22;
            uint hKey  = 0x9855E214CD9310A8;
        #elif _WIN32
            uint mHash = 0x3DD7996A;
            uint pHash = 0x845CB2FD;
            uint hKey  = 0x9591B59B;
        #endif
            msize = tracker->FindAPI(mHash, pHash, hKey);
            if (msize == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->msvcrt_msize = msize;
        }
        // call msize
        memSize = msize(ptr);
        if (memSize < BLOCK_MARK_SIZE)
        {
            lastErr = GetLastErrno();
            break;
        }
        // check it is a marked block and adjust the return size
        uintptr block = (uintptr)ptr;
        uint bSize = memSize - BLOCK_MARK_SIZE;
        uint mark  = *(uint*)(block + bSize);
        if (calcHeapMark(tracker, block, bSize) == mark)
        {
            memSize -= BLOCK_MARK_SIZE;
        }
        lastErr = GetLastErrno();
        break;
    }

    dbg_log("[memory]", "msvcrt.msize: %zu, ptr: 0x%zX", memSize, ptr);

    if (!MT_Unlock())
    {
        return (SIZE_T)(-1);
    }

    SetLastErrno(lastErr);
    return memSize;
}

__declspec(noinline) 
void* __cdecl MT_ucrtbase_malloc(uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        // try to get API address from cache
        ucrtbase_malloc_t malloc = tracker->ucrtbase_malloc;
        if (malloc == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xC8979D68FC153E63;
            uint pHash = 0xC3ED093E867586EE;
            uint hKey  = 0x843D1732A8C40E00;
        #elif _WIN32
            uint mHash = 0xE116757B;
            uint pHash = 0xF402BD57;
            uint hKey  = 0x4B5196C8;
        #endif
            malloc = tracker->FindAPI(mHash, pHash, hKey);
            if (malloc == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->ucrtbase_malloc = malloc;
        }
        // call malloc
        address = malloc(size + BLOCK_MARK_SIZE);
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        // write heap block mark
        uint* tail = (uint*)((uintptr)address + size);
        *tail = calcHeapMark(tracker, (uintptr)address, size);
        // update counter
        tracker->NumBlocks++;
        lastErr = GetLastErrno();
        break;
    }

    dbg_log("[memory]", "ucrtbase.malloc: 0x%zX, size: %zu", address, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void* __cdecl MT_ucrtbase_calloc(uint num, uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        // try to get API address from cache
        ucrtbase_calloc_t calloc = tracker->ucrtbase_calloc;
        if (calloc == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xBA11B584C0E2C354;
            uint pHash = 0xB567215A4B430B3F;
            uint hKey  = 0xBF71AC304E763DD9;
        #elif _WIN32
            uint mHash = 0x65389226;
            uint pHash = 0x21A8EDB6;
            uint hKey  = 0x83A98C6F;
        #endif
            calloc = tracker->FindAPI(mHash, pHash, hKey);
            if (calloc == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->ucrtbase_calloc = calloc;
        }
        // call calloc
        address = calloc(num + BLOCK_MARK_SIZE, size);
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        if (num == 0 || size == 0)
        {
            lastErr = GetLastErrno();
            break;
        }
        // write heap block mark
        uint total = (num + BLOCK_MARK_SIZE) * size - BLOCK_MARK_SIZE;
        uint* tail = (uint*)((uintptr)address + total);
        *tail = calcHeapMark(tracker, (uintptr)address, total);
        // update counter
        tracker->NumBlocks++;
        lastErr = GetLastErrno();
        break;
    }

    dbg_log("[memory]", "ucrtbase.calloc: 0x%zX, num: %zu size: %zu", num, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void* __cdecl MT_ucrtbase_realloc(void* ptr, uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        // try to get API address from cache
        ucrtbase_realloc_t realloc = tracker->ucrtbase_realloc;
        if (realloc == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x11B0889A6084A30F;
            uint pHash = 0x438FC396E49E76F1;
            uint hKey  = 0x2147D0F4BBF0BF25;
        #elif _WIN32
            uint mHash = 0x611CB923;
            uint pHash = 0xADA4F1A3;
            uint hKey  = 0x964B5F08;
        #endif
            realloc = tracker->FindAPI(mHash, pHash, hKey);
            if (realloc == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->ucrtbase_realloc = realloc;
        }
        ucrtbase_msize_t msize = tracker->ucrtbase_msize;
        if (msize == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x1831D75A4DDFA430;
            uint pHash = 0x14374030484BEBDD;
            uint hKey  = 0xE5F0D94E0ED9AC76;
        #elif _WIN32
            uint mHash = 0xDBC9F2B0;
            uint pHash = 0xB8CB06F0;
            uint hKey  = 0xFF1B4883;
        #endif
            msize = tracker->FindAPI(mHash, pHash, hKey);
            if (msize == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->ucrtbase_msize = msize;
        }
        // get old size about heap block
        SIZE_T oSize = 0;
        if (ptr != NULL)
        {
            oSize = msize(ptr);
            if (oSize == (SIZE_T)(-1))
            {
                lastErr = GetLastErrno();
                break;
            }
        }
        // erase old block mark before realloc
        bool marked = false;
        if (oSize >= BLOCK_MARK_SIZE)
        {
            uintptr block = (uintptr)ptr;
            uint  bSize = oSize - BLOCK_MARK_SIZE;
            uint* mark  = (uint*)(block + bSize);
            if (calcHeapMark(tracker, block, bSize) == *mark)
            {
                mem_init(mark, BLOCK_MARK_SIZE);
                marked = true;
            }
        }
        address = realloc(ptr, size + BLOCK_MARK_SIZE);
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        // write heap block mark
        uint* tail = (uint*)((uintptr)address + size);
        *tail = calcHeapMark(tracker, (uintptr)address, size);
        // update counter
        if (!marked)
        {
            tracker->NumBlocks++;
        }
        lastErr = GetLastErrno();
        break;
    }

    dbg_log("[memory]", "ucrtbase.realloc: 0x%zX, ptr: 0x%zX size: %zu", address, ptr, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void __cdecl MT_ucrtbase_free(void* ptr)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return;
    }

    errno lastErr = NO_ERROR;
    for (;;)
    {
        // try to get API address from cache
        ucrtbase_free_t free = tracker->ucrtbase_free;
        if (free == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0xCE9C8798388A6DA3;
            uint pHash = 0x474EAF96B49B242D;
            uint hKey  = 0x4664A17DDAE0B020;
        #elif _WIN32
            uint mHash = 0xE42F7591;
            uint pHash = 0x49DCB887;
            uint hKey  = 0xA1753154;
        #endif
            free = tracker->FindAPI(mHash, pHash, hKey);
            if (free == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->ucrtbase_free = free;
        }
        ucrtbase_msize_t msize = tracker->ucrtbase_msize;
        if (msize == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x1831D75A4DDFA430;
            uint pHash = 0x14374030484BEBDD;
            uint hKey  = 0xE5F0D94E0ED9AC76;
        #elif _WIN32
            uint mHash = 0xDBC9F2B0;
            uint pHash = 0xB8CB06F0;
            uint hKey  = 0xFF1B4883;
        #endif
            msize = tracker->FindAPI(mHash, pHash, hKey);
            if (msize == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->ucrtbase_msize = msize;
        }
        // special case
        if (ptr == NULL)
        {
            free(ptr);
            lastErr = GetLastErrno();
            break;
        }
        // get old size about heap block
        SIZE_T oSize = msize(ptr);
        if (oSize == (SIZE_T)(-1))
        {
            lastErr = GetLastErrno();
            break;
        }
        // check it is a marked block before free
        bool marked = false;
        if (oSize >= BLOCK_MARK_SIZE)
        {
            uintptr block = (uintptr)ptr;
            uint bSize = oSize - BLOCK_MARK_SIZE;
            uint mark  = *(uint*)(block + bSize);
            if (calcHeapMark(tracker, block, bSize) == mark)
            {
                marked = true;
            }
        }
        mem_init(ptr, oSize);
        free(ptr);
        // update counter
        if (marked)
        {
            tracker->NumBlocks--;
        }
        lastErr = GetLastErrno();
        break;
    }

    dbg_log("[memory]", "ucrtbase.free, ptr: 0x%zX", ptr);

    if (!MT_Unlock())
    {
        return;
    }

    SetLastErrno(lastErr);
}

__declspec(noinline)
uint __cdecl MT_ucrtbase_msize(void* ptr)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return (SIZE_T)(-1);
    }

    SIZE_T memSize = (SIZE_T)(-1);
    errno  lastErr = NO_ERROR;
    for (;;)
    {
        if (ptr == NULL)
        {
            lastErr = UCRTBASE_EINVAL;
            break;
        }
        // try to get API address from cache
        ucrtbase_msize_t msize = tracker->ucrtbase_msize;
        if (msize == NULL)
        {
        #ifdef _WIN64
            uint mHash = 0x1831D75A4DDFA430;
            uint pHash = 0x14374030484BEBDD;
            uint hKey  = 0xE5F0D94E0ED9AC76;
        #elif _WIN32
            uint mHash = 0xDBC9F2B0;
            uint pHash = 0xB8CB06F0;
            uint hKey  = 0xFF1B4883;
        #endif
            msize = tracker->FindAPI(mHash, pHash, hKey);
            if (msize == NULL)
            {
                lastErr = ERR_MEMORY_API_NOT_FOUND;
                break;
            }
            tracker->ucrtbase_msize = msize;
        }
        // call msize
        memSize = msize(ptr);
        lastErr = GetLastErrno();
        if (memSize < BLOCK_MARK_SIZE)
        {
            break;
        }
        // check it is a marked block and adjust the return size
        uintptr block = (uintptr)ptr;
        uint bSize = memSize - BLOCK_MARK_SIZE;
        uint mark  = *(uint*)(block + bSize);
        if (calcHeapMark(tracker, block, bSize) == mark)
        {
            memSize -= BLOCK_MARK_SIZE;
        }
        break;
    }

    dbg_log("[memory]", "ucrtbase.msize: %zu, ptr: 0x%zX", memSize, ptr);

    if (!MT_Unlock())
    {
        return (SIZE_T)(-1);
    }

    SetLastErrno(lastErr);
    return memSize;
}

__declspec(noinline)
static uint calcHeapMark(MemoryTracker* tracker, uintptr addr, uint size)
{
    uint mark = tracker->HeapMark;
    mark = XORShift(mark ^ addr);
    mark = XORShift(mark);
    return mark + size;
}

// replacePageProtect is used to make sure all the page are readable.
// avoid inadvertently using sensitive permissions.
static uint32 replacePageProtect(uint32 protect)
{
    switch (protect & 0xFF)
    {
    case PAGE_NOACCESS:
        return (protect & 0xFFFFFF00) + PAGE_READONLY;
    case PAGE_EXECUTE:
        return (protect & 0xFFFFFF00) + PAGE_EXECUTE_READ;
    default:
        return protect;
    }
}

__declspec(noinline)
static bool isPageTypeTrackable(uint32 type)
{
    switch (type & 0xF000)
    {
    case MEM_COMMIT:
    case MEM_RESERVE:
    case MEM_COMMIT|MEM_RESERVE:
        return true;
    default:
        return false;
    }
}

__declspec(noinline)
static bool isPageProtectWriteable(uint32 protect)
{
    switch (protect)
    {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

// adjustPageProtect is used to make sure this page is writeable.
static bool adjustPageProtect(MemoryTracker* tracker, memPage* page)
{
    if (isPageProtectWriteable(page->protect))
    {
        return true;
    }
    LPVOID address = (LPVOID)(page->address);
    SIZE_T size    = (SIZE_T)(tracker->PageSize);
    uint32 old;
    return tracker->VirtualProtect(address, size, PAGE_READWRITE, &old);
}

// recoverPageProtect is used to recover to prevent protect.
static bool recoverPageProtect(MemoryTracker* tracker, memPage* page)
{
    if (isPageProtectWriteable(page->protect))
    {
        return true;
    }
    LPVOID address = (LPVOID)(page->address);
    SIZE_T size    = (SIZE_T)(tracker->PageSize);
    uint32 old;
    return tracker->VirtualProtect(address, size, page->protect, &old);
}

// +---------+----------+-------------+
// |  size   | capacity | user buffer |
// +---------+----------+-------------+
// |  uint   |   uint   |     var     |
// +---------+----------+-------------+

__declspec(noinline)
void* MT_MemAlloc(uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (size == 0)
    {
        return NULL;
    }
    // ensure the size is a multiple of memory page size.
    // it also for prevent track the special page size.
    uint pageSize = (((size + 16) / tracker->PageSize) + 1) * tracker->PageSize;
    void* addr = MT_VirtualAlloc(NULL, pageSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    // store the size at the head of the memory page
    // ensure the memory address is 16 bytes aligned
    byte* address = (byte*)addr;
    RandBuffer(address, 16);
    // record user input size
    mem_copy(address, &size, sizeof(size));
    // record buffer capacity
    uint cap = pageSize - 16;
    mem_copy(address + sizeof(size), &cap, sizeof(cap));
    dbg_log("[memory]", "malloc size: %zu", size);
    return (void*)(address + 16);
}

__declspec(noinline)
void* MT_MemCalloc(uint num, uint size)
{
    uint total = num * size;
    if (total == 0)
    {
        return NULL;
    }
    void* addr = MT_MemAlloc(total);
    if (addr == NULL)
    {
        return NULL;
    }
    mem_init(addr, total);
    dbg_log("[memory]", "calloc num: %zu, size: %zu", num, size);
    return addr;
}

__declspec(noinline)
void* MT_MemRealloc(void* ptr, uint size)
{
    if (ptr == NULL)
    {
        return MT_MemAlloc(size);
    }
    if (size == 0)
    {
        MT_MemFree(ptr);
        return NULL;
    }
    // check need expand capacity
    uint cap = MT_MemCap(ptr);
    if (size <= cap)
    {
        *(uint*)((uintptr)(ptr)-16) = size;
        return ptr;
    }
    // allocate new memory
    if (size < 65536)
    {
        cap = size * 2;
    } else {
        cap = size * 5 / 4; // size *= 1.25
    }
    void* newPtr = MT_MemAlloc(cap);
    if (newPtr == NULL)
    {
        return NULL;
    }
    // copy data to new memory
    uint oldSize = *(uint*)((uintptr)(ptr)-16);
    mem_copy(newPtr, ptr, oldSize);
    // free old memory
    MT_MemFree(ptr);
    dbg_log("[memory]", "realloc ptr: 0x%zX, size: %zu", ptr, size);
    return newPtr;
}

__declspec(noinline)
void MT_MemFree(void* ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    // clean the buffer data before call VirtualFree.
    void* addr = (LPVOID)((uintptr)(ptr)-16);
    uint  size = *(uint*)addr;
    mem_init((byte*)addr, size);
    if (MT_VirtualFree(addr, 0, MEM_RELEASE))
    {
        dbg_log("[memory]", "free ptr: 0x%zX", ptr);
        return;
    }
    dbg_log("[memory]", "failed to call VirtualFree: 0x%X", GetLastErrno());
}

__declspec(noinline)
uint MT_MemSize(void* ptr)
{
    if (ptr == NULL)
    {
        return 0;
    }
    return *(uint*)((uintptr)(ptr)-16);
}

__declspec(noinline)
uint MT_MemCap(void* ptr)
{
    if (ptr == NULL)
    {
        return 0;
    }
    return *(uint*)((uintptr)(ptr)-16+sizeof(uint));
}

__declspec(noinline)
bool MT_LockRegion(LPVOID address)
{
    if (!MT_Lock())
    {
        return false;
    }

    bool success = setRegionLocker((uintptr)address, true);
    dbg_log("[memory]", "lock region: 0x%zX", address);

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
bool MT_UnlockRegion(LPVOID address)
{
    if (!MT_Lock())
    {
        return false;
    }

    bool success = setRegionLocker((uintptr)address, false);
    dbg_log("[memory]", "unlock region: 0x%zX", address);

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

#pragma optimize("t", on)
static bool setRegionLocker(uintptr address, bool lock)
{
    MemoryTracker* tracker = getTrackerPointer();

    List* regions = &tracker->Regions;
    List* pages   = &tracker->Pages;

    // search memory regions list
    memRegion* region = NULL;
    uint len = regions->Len;
    uint idx = 0;
    bool found = false;
    for (uint num = 0; num < len; idx++)
    {
        region = List_Get(regions, idx);
        if (region->address == 0)
        {
            continue;
        }
        if (region->address != address)
        {
            num++;
            continue;
        }
        region->locked = lock;
        found = true;
        break;
    }
    if (!found || region == NULL)
    {
        return false;
    }
    // skip rwx region
    if (region->isRWX)
    {
        return true;
    }
    // set memory page locker
    uint regionSize = region->size;
    uint pageSize   = tracker->PageSize;
    len = pages->Len;
    idx = 0;
    found = false;
    for (uint num = 0; num < len; idx++)
    {
        memPage* page = List_Get(pages, idx);
        if (page->address == 0)
        {
            continue;
        }
        if ((page->address + pageSize <= address) || (page->address >= address + regionSize))
        {
            num++;
            continue;
        }
        page->locked = lock;
        found = true;
        num++;
    }
    return found;
}
#pragma optimize("t", off)

__declspec(noinline)
bool MT_GetStatus(MT_Status* status)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    status->NumGlobals = (int64)(tracker->NumGlobals);
    status->NumLocals  = (int64)(tracker->NumLocals);
    status->NumBlocks  = (int64)(tracker->NumBlocks);
    status->NumRegions = (int64)(tracker->Regions.Len);
    status->NumPages   = (int64)(tracker->Pages.Len);
    status->NumHeaps   = (int64)(tracker->Heaps.Len);

    if (!MT_Unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
bool MT_FreeAllMu()
{
    if (!MT_Lock())
    {
        return false;
    }

    errno errno = MT_FreeAll();
    dbg_log("[memory]", "FreeAll has been called");

    if (!MT_Unlock())
    {
        return false;
    }

    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return false;
    }
    return true;
}

__declspec(noinline)
bool MT_Lock()
{
    MemoryTracker* tracker = getTrackerPointer();

    DWORD event = tracker->WaitForSingleObject(tracker->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool MT_Unlock()
{
    MemoryTracker* tracker = getTrackerPointer();

    return tracker->ReleaseMutex(tracker->hMutex);
}

__declspec(noinline)
errno MT_Encrypt()
{
    MemoryTracker* tracker = getTrackerPointer();

    List* pages   = &tracker->Pages;
    List* regions = &tracker->Regions;

    // encrypt memory pages
    uint len = pages->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memPage* page = List_Get(pages, idx);
        if (page->address == 0)
        {
            continue;
        }
        if (!encryptPage(tracker, page))
        {
            return ERR_MEMORY_ENCRYPT_PAGE;
        }
        num++;
    }

    // encrypt RWX memory regions
    len = regions->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memRegion* region = List_Get(regions, idx);
        if (region->address == 0)
        {
            continue;
        }
        if (!region->isRWX)
        {
            num++;
            continue;
        }
        if (!encryptRWXRegion(tracker, region))
        {
            return ERR_MEMORY_ENCRYPT_REGION;
        }
        num++;
    }

    // encrypt heap blocks
    if (tracker->NumBlocks != 0)
    {
        // get the number of heaps
        HANDLE padding;
        DWORD  numHeaps = tracker->GetProcessHeaps(0, &padding);
        // get heap handles
        HANDLE* hHeaps = tracker->RT_calloc(numHeaps, sizeof(HANDLE));
        if (tracker->GetProcessHeaps(numHeaps, hHeaps) != 0)
        {
            HANDLE* hHeap = hHeaps;
            // walk and encrypt heap blocks
            for (uint32 i = 0; i < numHeaps; i++)
            {
                if (!encryptHeapBlocks(*hHeap))
                {
                    return ERR_MEMORY_ENCRYPT_BLOCK;
                }
                hHeap++;
            }
        }
        tracker->RT_free(hHeaps);
    }

    // encrypt lists
    List* list = &tracker->Regions;
    byte* key  = tracker->RegionsKey;
    byte* iv   = tracker->RegionsIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);

    list = &tracker->Pages;
    key  = tracker->PagesKey;
    iv   = tracker->PagesIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);

    list = &tracker->Heaps;
    key  = tracker->HeapsKey;
    iv   = tracker->HeapsIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno MT_Decrypt()
{
    MemoryTracker* tracker = getTrackerPointer();

    // decrypt lists
    List* list = &tracker->Regions;
    byte* key  = tracker->RegionsKey;
    byte* iv   = tracker->RegionsIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    list = &tracker->Pages;
    key  = tracker->PagesKey;
    iv   = tracker->PagesIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    list = &tracker->Heaps;
    key  = tracker->HeapsKey;
    iv   = tracker->HeapsIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    List* pages   = &tracker->Pages;
    List* regions = &tracker->Regions;

    // reverse order traversal is used to deal with the problem
    // that some memory pages may be encrypted twice, like use
    // VirtualAlloc to allocate multiple times to the same address
    uint len = pages->Len;
    uint idx = pages->Last;
    for (uint num = 0; num < len; idx--)
    {
        memPage* page = List_Get(pages, idx);
        if (page->address == 0)
        {
            continue;
        }
        if (!decryptPage(tracker, page))
        {
            return ERR_MEMORY_DECRYPT_PAGE;
        }
        num++;
    }

    // decrypt RWX memory regions
    len = regions->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memRegion* region = List_Get(regions, idx);
        if (region->address == 0)
        {
            continue;
        }
        if (!region->isRWX)
        {
            num++;
            continue;
        }
        if (!decryptRWXRegion(tracker, region))
        {
            return ERR_MEMORY_DECRYPT_REGION;
        }
        num++;
    }

    // decrypt heap blocks
    if (tracker->NumBlocks != 0)
    {
        // get the number of heaps
        HANDLE padding;
        DWORD  numHeaps = tracker->GetProcessHeaps(0, &padding);
        // get heap handles
        HANDLE* hHeaps = tracker->RT_calloc(numHeaps, sizeof(HANDLE));
        if (tracker->GetProcessHeaps(numHeaps, hHeaps) != 0)
        {
            HANDLE* hHeap = hHeaps;
            // walk and decrypt heap blocks
            for (uint32 i = 0; i < numHeaps; i++)
            {
                if (!decryptHeapBlocks(*hHeap))
                {
                    return ERR_MEMORY_DECRYPT_BLOCK;
                }
                hHeap++;
            }
        }
        tracker->RT_free(hHeaps);
    }

    dbg_log("[memory]", "regions: %zu", tracker->Regions.Len);
    dbg_log("[memory]", "pages:   %zu", tracker->Pages.Len);
    dbg_log("[memory]", "heaps:   %zu", tracker->Heaps.Len);
    return NO_ERROR;
}

static bool encryptPage(MemoryTracker* tracker, memPage* page)
{
    if (isEmptyPage(tracker, page))
    {
        return true;
    }
    if (!adjustPageProtect(tracker, page))
    {
        return false;
    }
    // generate new key and IV
    RandBuffer(page->key, CRYPTO_KEY_SIZE);
    RandBuffer(page->iv, CRYPTO_IV_SIZE);
    byte key[CRYPTO_KEY_SIZE];
    deriveKey(tracker, page, key);
    EncryptBuf((byte*)(page->address), tracker->PageSize, key, page->iv);
    return true;
}

static bool decryptPage(MemoryTracker* tracker, memPage* page)
{
    if (isEmptyPage(tracker, page))
    {
        return true;
    }
    byte key[CRYPTO_KEY_SIZE];
    deriveKey(tracker, page, key);
    DecryptBuf((byte*)(page->address), tracker->PageSize, key, page->iv);
    if (!recoverPageProtect(tracker, page))
    {
        return false;
    }
    return true;
}

static bool isEmptyPage(MemoryTracker* tracker, memPage* page)
{
    register uint*  addr = (uint*)(page->address);
    register uint32 num  = tracker->PageSize/sizeof(uint*);
    for (uint32 i = 0; i < num; i++)
    {
        if (*addr != 0)
        {
            return false;
        }
        addr++;
    }
    return true;
}

static bool encryptRWXRegion(MemoryTracker* tracker, memRegion* region)
{
    RandBuffer(region->key, CRYPTO_KEY_SIZE);
    RandBuffer(region->iv, CRYPTO_IV_SIZE);
    void* addr = (void*)(region->address);
    EncryptBuf(addr, region->size, region->key, region->iv);
    DWORD old;
    return tracker->VirtualProtect(addr, region->size, PAGE_READWRITE, &old);
}

static bool decryptRWXRegion(MemoryTracker* tracker, memRegion* region)
{
    void* addr = (void*)(region->address);
    DecryptBuf(addr, region->size, region->key, region->iv);
    DWORD old;
    return tracker->VirtualProtect(addr, region->size, PAGE_EXECUTE_READWRITE, &old);
}

static void deriveKey(MemoryTracker* tracker, memPage* page, byte* key)
{
    // copy original key
    mem_copy(key, page->key, CRYPTO_KEY_SIZE);
    // cover some bytes
    uintptr addr = (uintptr)page;
    addr += ((uintptr)tracker) << (sizeof(addr) / 2);
    addr += ((uintptr)tracker->VirtualAlloc) >> 4;
    addr += ((uintptr)tracker->VirtualFree)  >> 6;
    mem_copy(key + 4, &addr, sizeof(addr));
}

static bool encryptHeapBlocks(HANDLE hHeap)
{
    return walkHeapBlocks(hHeap, OP_WALK_HEAP_ENCRYPT);
}

static bool decryptHeapBlocks(HANDLE hHeap)
{
    return walkHeapBlocks(hHeap, OP_WALK_HEAP_DECRYPT);
}

static bool eraseHeapBlocks(HANDLE hHeap)
{
    return walkHeapBlocks(hHeap, OP_WALK_HEAP_ERASE);
}

static bool walkHeapBlocks(HANDLE hHeap, int operation)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!tracker->HeapLock(hHeap))
    {
        return false;
    }

    HEAP_ENTRY entry = {
        .lpData = NULL,
    };

    PVOID* blocks = NULL;
    uint numFound = 0;
    for (;;)
    {
        if (!tracker->HeapWalk(hHeap, &entry))
        {
            break;
        }
        // skip too small block that not contain mark
        if (entry.cbData < BLOCK_MARK_SIZE)
        {
            continue;
        }
        // skip block that not used
        if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) == 0)
        {
            continue;
        }
        // skip empty block
        if (mem_is_zero(entry.lpData, entry.cbData))
        {
            continue;
        }
        // check is marked block
        uintptr block = (uintptr)(entry.lpData);
        uint size = entry.cbData - BLOCK_MARK_SIZE;
        uint mark = *(uint*)(block + size);
        if (calcHeapMark(tracker, block, size) != mark)
        {
            continue;
        }
        // encrypt/decrypt heap block
        byte* buf = (byte*)(entry.lpData);
        byte* key = tracker->BlocksKey;
        byte* iv  = tracker->BlocksIV;
        switch (operation)
        {
        case OP_WALK_HEAP_ENCRYPT:
            EncryptBuf(buf, size, key, iv);
            break;
        case OP_WALK_HEAP_DECRYPT:
            DecryptBuf(buf, size, key, iv);
            break;
        case OP_WALK_HEAP_ERASE:
            mem_init(buf, entry.cbData);
            // record marked heap block address
            uint ms = (numFound + 1) * sizeof(PVOID);
            blocks = tracker->RT_realloc(blocks, ms);
            if (blocks == NULL)
            {
                break;
            }
            blocks[numFound] = entry.lpData;
            break;
        default:
            panic(PANIC_UNREACHABLE_CODE);
        }
        numFound++;
    }
    errno lastErr = GetLastErrno();

    // free marked heap block
    if (blocks != NULL)
    {
        for (uint i = 0; i < numFound; i++)
        {
            if (!tracker->HeapFree(hHeap, HEAP_NO_SERIALIZE, blocks[i]))
            {
                lastErr = GetLastErrno();
            }
        }
        tracker->RT_free(blocks);
    }

    if (!tracker->HeapUnlock(hHeap))
    {
        return false;
    }

    dbg_log("[memory]", "heap block: 0x%zX %zu/%d", hHeap, numFound, tracker->NumBlocks);

    bool success = lastErr == ERROR_NO_MORE_ITEMS;
    if (success)
    {
        SetLastErrno(NO_ERROR);
    } else {
        SetLastErrno(lastErr);
    }
    return success;
}

__declspec(noinline)
void MT_Flush()
{
    MemoryTracker* tracker = getTrackerPointer();

   tracker->msvcrt_malloc  = NULL;
   tracker->msvcrt_calloc  = NULL;
   tracker->msvcrt_realloc = NULL;
   tracker->msvcrt_free    = NULL;
   tracker->msvcrt_msize   = NULL;

   tracker->ucrtbase_malloc  = NULL;
   tracker->ucrtbase_calloc  = NULL;
   tracker->ucrtbase_realloc = NULL;
   tracker->ucrtbase_free    = NULL;
   tracker->ucrtbase_msize   = NULL;
}

__declspec(noinline)
bool MT_FlushMu()
{
    if (!MT_Lock())
    {
        return false;
    }

    MT_Flush();

    if (!MT_Unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
errno MT_FreeAll()
{
    MemoryTracker* tracker = getTrackerPointer();

    List* regions = &tracker->Regions;
    List* pages   = &tracker->Pages;
    List* heaps   = &tracker->Heaps;
    errno errno   = NO_ERROR;

    // cover memory page data
    uint len = pages->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memPage* page = List_Get(pages, idx);
        if (page->address == 0)
        {
            continue;
        }
        // skip locked memory page
        if (page->locked)
        {
            num++;
            continue;
        }
        // cover memory page
        if (isPageProtectWriteable(page->protect))
        {
            RandBuffer((byte*)(page->address), tracker->PageSize);
        }
        num++;
    }

    // cover RWX memory region data
    len = regions->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memRegion* region = List_Get(regions, idx);
        if (region->address == 0)
        {
            continue;
        }
        // skip locked memory region
        if (region->locked)
        {
            num++;
            continue;
        }
        if (!region->isRWX)
        {
            num++;
            continue;
        }
        // cover memory region
        RandBuffer((byte*)(region->address), region->size);
        num++;
    }

    // decommit memory pages
    len = pages->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memPage* page = List_Get(pages, idx);
        if (page->address == 0)
        {
            continue;
        }
        // skip locked memory page
        if (page->locked)
        {
            num++;
            continue;
        }
        // free memory page
        if (!cleanPage(tracker, page))
        {
            errno = ERR_MEMORY_CLEAN_PAGE;
        }
        if (!List_Delete(pages, idx))
        {
            errno = ERR_MEMORY_DELETE_PAGE;
        }
        num++;
    }

    // release reserved memory region
    len = regions->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memRegion* region = List_Get(regions, idx);
        if (region->address == 0)
        {
            continue;
        }
        // skip locked memory region
        if (region->locked)
        {
            num++;
            continue;
        }
        // release memory region
        if (!tracker->VirtualFree((LPVOID)(region->address), 0, MEM_RELEASE))
        {
            errno = ERR_MEMORY_CLEAN_REGION;
        }
        if (!List_Delete(regions, idx))
        {
            errno = ERR_MEMORY_DELETE_REGION;
        }
        num++;
    }

    // erase heap blocks
    if (tracker->NumBlocks != 0)
    {
        // get the number of heaps
        HANDLE padding;
        DWORD  numHeaps = tracker->GetProcessHeaps(0, &padding);
        // get heap handles
        HANDLE* hHeaps = tracker->RT_calloc(numHeaps, sizeof(HANDLE));
        if (tracker->GetProcessHeaps(numHeaps, hHeaps) != 0)
        {
            HANDLE* hHeap = hHeaps;
            // walk and encrypt heap blocks
            for (uint32 i = 0; i < numHeaps; i++)
            {
                if (!eraseHeapBlocks(*hHeap))
                {
                    errno = ERR_MEMORY_ERASE_BLOCK;
                }
                hHeap++;
            }
        }
        tracker->RT_free(hHeaps);
    }

    // release private heaps
    len = heaps->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        heapObject* heap = List_Get(heaps, idx);
        if (heap->hHeap == NULL)
        {
            continue;
        }
        if (!tracker->HeapDestroy(heap->hHeap))
        {
            errno = ERR_MEMORY_CLEAN_HEAP;
        }
        if (!List_Delete(heaps, idx))
        {
            errno = ERR_MEMORY_DELETE_HEAP;
        }
        num++;
    }

    dbg_log("[memory]", "regions: %zu", tracker->Regions.Len);
    dbg_log("[memory]", "pages:   %zu", tracker->Pages.Len);
    dbg_log("[memory]", "heaps:   %zu", tracker->Heaps.Len);
    dbg_log("[memory]", "blocks:  %d",  tracker->NumBlocks);
    dbg_log("[memory]", "globals: %d",  tracker->NumGlobals);
    dbg_log("[memory]", "locals:  %d",  tracker->NumLocals);

    // generate the new random heap mark
    tracker->HeapMark = RandUint(tracker->HeapMark);

    // reset the counters about track heap
    tracker->NumBlocks  = 0;
    tracker->NumGlobals = 0;
    tracker->NumLocals  = 0;
    return errno;
}

__declspec(noinline)
errno MT_Clean()
{
    MemoryTracker* tracker = getTrackerPointer();

    List* regions = &tracker->Regions;
    List* pages   = &tracker->Pages;
    List* heaps   = &tracker->Heaps;
    errno errno   = NO_ERROR;

    // cover memory page data
    uint len = pages->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memPage* page = List_Get(pages, idx);
        if (page->address == 0)
        {
            continue;
        }
        // cover memory page
        if (isPageProtectWriteable(page->protect))
        {
            RandBuffer((byte*)(page->address), tracker->PageSize);
        }
        num++;
    }

    // cover RWX memory region data
    len = regions->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memRegion* region = List_Get(regions, idx);
        if (region->address == 0)
        {
            continue;
        }
        if (!region->isRWX)
        {
            num++;
            continue;
        }
        // cover memory region
        RandBuffer((byte*)(region->address), region->size);
        num++;
    }

    // decommit memory pages
    len = pages->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memPage* page = List_Get(pages, idx);
        if (page->address == 0)
        {
            continue;
        }
        if (!cleanPage(tracker, page) && errno == NO_ERROR)
        {
            errno = ERR_MEMORY_CLEAN_PAGE;
        }
        num++;
    }

    // release reserved memory region
    len = regions->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memRegion* region = List_Get(regions, idx);
        if (region->address == 0)
        {
            continue;
        }
        if (!tracker->VirtualFree((LPVOID)(region->address), 0, MEM_RELEASE))
        {
            if (errno == NO_ERROR)
            {
                errno = ERR_MEMORY_CLEAN_REGION;
            }
        }
        num++;
    }

    // erase heap blocks
    if (tracker->NumBlocks != 0)
    {
        // get the number of heaps
        HANDLE padding;
        DWORD  numHeaps = tracker->GetProcessHeaps(0, &padding);
        // get heap handles
        HANDLE* hHeaps = tracker->RT_calloc(numHeaps, sizeof(HANDLE));
        if (tracker->GetProcessHeaps(numHeaps, hHeaps) != 0)
        {
            HANDLE* hHeap = hHeaps;
            // walk and encrypt heap blocks
            for (uint32 i = 0; i < numHeaps; i++)
            {
                if (!eraseHeapBlocks(*hHeap))
                {
                    if (errno == NO_ERROR)
                    {
                        errno = ERR_MEMORY_ERASE_BLOCK;
                    }
                }
                hHeap++;
            }
        }
        tracker->RT_free(hHeaps);
    }

    // release private heaps
    len = heaps->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        heapObject* heap = List_Get(heaps, idx);
        if (heap->hHeap == NULL)
        {
            continue;
        }
        if (!tracker->HeapDestroy(heap->hHeap))
        {
            if (errno == NO_ERROR)
            {
                errno = ERR_MEMORY_CLEAN_HEAP;
            }
        }
        num++;
    }

    // clean memory region and page list
    RandBuffer(regions->Data, List_Size(regions));
    RandBuffer(pages->Data, List_Size(pages));
    RandBuffer(heaps->Data, List_Size(heaps));
    if (!List_Free(regions) && errno == NO_ERROR)
    {
        errno = ERR_MEMORY_FREE_PAGE_LIST;
    }
    if (!List_Free(pages) && errno == NO_ERROR)
    {
        errno = ERR_MEMORY_FREE_REGION_LIST;
    }
    if (!List_Free(heaps) && errno == NO_ERROR)
    {
        errno = ERR_MEMORY_FREE_HEAP_LIST;
    }

    // close mutex
    if (!tracker->CloseHandle(tracker->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_MEMORY_CLOSE_MUTEX;
    }

    // recover instructions
    if (tracker->NotEraseInstruction)
    {
        if (!recoverTrackerPointer(tracker) && errno == NO_ERROR)
        {
            errno = ERR_MEMORY_RECOVER_INST;
        }
    }

    dbg_log("[memory]", "regions: %zu", tracker->Regions.Len);
    dbg_log("[memory]", "pages:   %zu", tracker->Pages.Len);
    dbg_log("[memory]", "heaps:   %zu", tracker->Heaps.Len);
    dbg_log("[memory]", "blocks:  %d",  tracker->NumBlocks);
    dbg_log("[memory]", "globals: %d",  tracker->NumGlobals);
    dbg_log("[memory]", "locals:  %d",  tracker->NumLocals);
    return errno;
}

static bool cleanPage(MemoryTracker* tracker, memPage* page)
{
    LPVOID addr = (LPVOID)(page->address);
    DWORD  size = (DWORD)(tracker->PageSize);
    return tracker->VirtualFree(addr, size, MEM_DECOMMIT);
}
