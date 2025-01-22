#include "build.h"
#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "crypto.h"
#include "compress.h"
#include "win_api.h"
#include "errno.h"
#include "context.h"
#include "mod_library.h"
#include "mod_memory.h"
#include "mod_thread.h"
#include "mod_resource.h"
#include "mod_argument.h"
#include "mod_storage.h"
#include "win_base.h"
#include "win_file.h"
#include "win_http.h"
#include "shield.h"
#include "runtime.h"
#include "debug.h"

// +--------------+--------------------+-------------------+
// |    0-4096    |     4096-16384     |    16384-32768    |
// +--------------+--------------------+-------------------+
// | runtime core | runtime submodules | high-level module |
// +--------------+--------------------+-------------------+
#define MAIN_MEM_PAGE_SIZE (8*4096)

#define EVENT_TYPE_SLEEP 0x01
#define EVENT_TYPE_STOP  0x02

// about IAT hooks
typedef struct {
    void* Proc;
    void* Hook;
} Hook;

typedef struct {
    // store options from argument
    Runtime_Opts Options;

    // API addresses
    GetSystemInfo_t         GetSystemInfo;
    LoadLibraryA_t          LoadLibraryA;
    FreeLibrary_t           FreeLibrary;
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    FlushInstructionCache_t FlushInstructionCache;
    ExitProcess_t           ExitProcess;
    SetCurrentDirectoryA_t  SetCurrentDirectoryA;
    SetCurrentDirectoryW_t  SetCurrentDirectoryW;
    CreateMutexA_t          CreateMutexA;
    ReleaseMutex_t          ReleaseMutex;
    CreateEventA_t          CreateEventA;
    SetEvent_t              SetEvent;
    ResetEvent_t            ResetEvent;
    CreateWaitableTimerW_t  CreateWaitableTimerW;
    SetWaitableTimer_t      SetWaitableTimer;
    SleepEx_t               SleepEx;
    WaitForSingleObject_t   WaitForSingleObject;
    DuplicateHandle_t       DuplicateHandle;
    CloseHandle_t           CloseHandle;
    GetProcAddress_t        GetProcAddress;

    // runtime data
    void*  MainMemPage; // store all structures
    void*  Epilogue;    // store shellcode epilogue
    uint32 PageSize;    // for memory management
    HANDLE hMutex;      // global method mutex

    // about event handler
    HANDLE hMutexSleep;  // sleep method mutex
    HANDLE hEventArrive; // arrive event
    HANDLE hEventDone;   // finish event
    uint32 EventType;    // store event type
    uint32 SleepTime;    // store sleep argument
    errno  ReturnErrno;  // store error number
    HANDLE hMutexEvent;  // event data mutex
    HANDLE hThreadEvent; // event handler thread

    // IAT hooks about GetProcAddress
    Hook IATHooks[53];

    // runtime submodules
    LibraryTracker_M*  LibraryTracker;
    MemoryTracker_M*   MemoryTracker;
    ThreadTracker_M*   ThreadTracker;
    ResourceTracker_M* ResourceTracker;
    ArgumentStore_M*   ArgumentStore;
    InMemoryStorage_M* InMemoryStorage;

    // high-level modules
    WinBase_M* WinBase;
    WinFile_M* WinFile;
    WinHTTP_M* WinHTTP;
} Runtime;

// export methods and IAT hooks about Runtime
void* RT_FindAPI(uint hash, uint key);
void* RT_FindAPI_A(byte* module, byte* function);
void* RT_FindAPI_W(uint16* module, byte* function);

void* RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
void* RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool hook);
void* RT_GetProcAddressByHash(uint hash, uint key, bool hook);
void* RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName);

BOOL  RT_SetCurrentDirectoryA(LPSTR lpPathName);
BOOL  RT_SetCurrentDirectoryW(LPWSTR lpPathName);
void  RT_Sleep(DWORD dwMilliseconds);
DWORD RT_SleepEx(DWORD dwMilliseconds, BOOL bAlertable);
void  RT_ExitProcess(UINT uExitCode);

errno RT_SleepHR(DWORD dwMilliseconds);
errno RT_Hide();
errno RT_Recover();
errno RT_Metrics(Runtime_Metrics* metrics);
errno RT_Cleanup();
errno RT_Exit();

// internal methods for Runtime submodules
void* RT_malloc(uint size);
void* RT_calloc(uint num, uint size);
void* RT_realloc(void* ptr, uint size);
bool  RT_free(void* ptr);
uint  RT_msize(void* ptr);
uint  RT_mcap(void* ptr);

errno RT_lock_mods();
errno RT_unlock_mods();

// hard encoded address in getRuntimePointer for replacement
#ifdef _WIN64
    #define RUNTIME_POINTER 0x7FABCDEF111111FF
#elif _WIN32
    #define RUNTIME_POINTER 0x7FAB11FF
#endif
static Runtime* getRuntimePointer();

static bool rt_lock();
static bool rt_unlock();

static bool  isValidArgumentStub();
static void* allocRuntimeMemPage();
static void* calculateEpilogue();
static bool  initRuntimeAPI(Runtime* runtime);
static bool  adjustPageProtect(Runtime* runtime, DWORD* old);
static bool  recoverPageProtect(Runtime* runtime, DWORD protect);
static bool  updateRuntimePointer(Runtime* runtime);
static bool  recoverRuntimePointer(Runtime* runtime);
static errno initRuntimeEnvironment(Runtime* runtime);
static errno initSubmodules(Runtime* runtime);
static errno initLibraryTracker(Runtime* runtime, Context* context);
static errno initMemoryTracker(Runtime* runtime, Context* context);
static errno initThreadTracker(Runtime* runtime, Context* context);
static errno initResourceTracker(Runtime* runtime, Context* context);
static errno initArgumentStore(Runtime* runtime, Context* context);
static errno initInMemoryStorage(Runtime* runtime, Context* context);
static errno initWinBase(Runtime* runtime, Context* context);
static errno initWinFile(Runtime* runtime, Context* context);
static errno initWinHTTP(Runtime* runtime, Context* context);
static bool  initIATHooks(Runtime* runtime);
static bool  flushInstructionCache(Runtime* runtime);
static void  eraseRuntimeMethods(Runtime* runtime);
static errno cleanRuntime(Runtime* runtime);

static void* getRuntimeMethods(LPCWSTR module, LPCSTR lpProcName);
static void* getIATHook(Runtime* runtime, void* proc);
static void* getLazyAPIHook(Runtime* runtime, void* proc);

static void  eventHandler();
static errno processEvent(Runtime* runtime, bool* exit);
static errno sleepHR(Runtime* runtime, uint32 milliseconds);
static errno sleep(Runtime* runtime, HANDLE hTimer);
static errno hide(Runtime* runtime);
static errno recover(Runtime* runtime);

static errno exitEventHandler(Runtime* runtime);
static errno closeHandles(Runtime* runtime);
static void  eraseMemory(uintptr address, uintptr size);
static void  rt_epilogue();

Runtime_M* InitRuntime(Runtime_Opts* opts)
{
    if (!InitDebugger())
    {
        SetLastErrno(ERR_RUNTIME_INIT_DEBUGGER);
        return NULL;
    }
    // check argument stub for calculate Epilogue
    if (!isValidArgumentStub())
    {
        SetLastErrno(ERR_RUNTIME_INVALID_ARGS_STUB);
        return NULL;
    }
    // alloc memory for store runtime structure
    void* memPage = allocRuntimeMemPage();
    if (memPage == NULL)
    {
        SetLastErrno(ERR_RUNTIME_ALLOC_MEMORY);
        return NULL;
    }
    // set structure address
    uintptr address = (uintptr)memPage;
    uintptr runtimeAddr = address + 1000 + RandUintN(address, 128);
    uintptr moduleAddr  = address + 3000 + RandUintN(address, 128);
    // initialize structure
    Runtime* runtime = (Runtime*)runtimeAddr;
    mem_init(runtime, sizeof(Runtime));
    // store runtime options
    if (opts == NULL)
    {
        Runtime_Opts opt = {
            .BootInstAddress     = NULL,
            .NotEraseInstruction = false,
            .NotAdjustProtect    = false,
            .TrackCurrentThread  = false,
        };
        opts = &opt;
    }
    runtime->Options = *opts;
    // set runtime data
    runtime->MainMemPage = memPage;
    runtime->Epilogue    = calculateEpilogue();
    // initialize runtime
    DWORD oldProtect = 0;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initRuntimeAPI(runtime))
        {
            errno = ERR_RUNTIME_INIT_API;
            break;
        }
        if (!adjustPageProtect(runtime, &oldProtect))
        {
            errno = ERR_RUNTIME_ADJUST_PROTECT;
            break;
        }
        if (!updateRuntimePointer(runtime))
        {
            errno = ERR_RUNTIME_UPDATE_PTR;
            break;
        }
        errno = initRuntimeEnvironment(runtime);
        if (errno != NO_ERROR)
        {
            break;
        }
        errno = initSubmodules(runtime);
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!initIATHooks(runtime))
        {
            errno = ERR_RUNTIME_INIT_IAT_HOOKS;
            break;
        }
        break;
    }
    if (errno == NO_ERROR || errno > ERR_RUNTIME_ADJUST_PROTECT)
    {
        eraseRuntimeMethods(runtime);
    }
    if (oldProtect != 0)
    {
        if (!recoverPageProtect(runtime, oldProtect) && errno == NO_ERROR)
        {
            errno = ERR_RUNTIME_RECOVER_PROTECT;
        }
    }
    if (errno == NO_ERROR && !flushInstructionCache(runtime))
    {
        errno = ERR_RUNTIME_FLUSH_INST;
    }
    // start event handler
    if (errno == NO_ERROR)
    {
        void* addr = GetFuncAddr(&eventHandler);
        runtime->hThreadEvent = runtime->ThreadTracker->New(addr, NULL, false);
        if (runtime->hThreadEvent == NULL)
        {
            errno = ERR_RUNTIME_START_EVENT_HANDLER;
        }
    }
    if (errno != NO_ERROR)
    {
        cleanRuntime(runtime);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for Runtime
    Runtime_M* module = (Runtime_M*)moduleAddr;
    // about hash api
    module->HashAPI.FindAPI   = GetFuncAddr(&RT_FindAPI);
    module->HashAPI.FindAPI_A = GetFuncAddr(&RT_FindAPI_A);
    module->HashAPI.FindAPI_W = GetFuncAddr(&RT_FindAPI_W);
    // library tracker
    module->Library.LoadA   = runtime->LibraryTracker->LoadLibraryA;
    module->Library.LoadW   = runtime->LibraryTracker->LoadLibraryW;
    module->Library.LoadExA = runtime->LibraryTracker->LoadLibraryExA;
    module->Library.LoadExW = runtime->LibraryTracker->LoadLibraryExW;
    module->Library.Free    = runtime->LibraryTracker->FreeLibrary;
    module->Library.GetProc = GetFuncAddr(&RT_GetProcAddress);
    module->Library.Lock    = runtime->LibraryTracker->LockModule;
    module->Library.Unlock  = runtime->LibraryTracker->UnlockModule;
    module->Library.Status  = runtime->LibraryTracker->GetStatus;
    module->Library.FreeAll = runtime->LibraryTracker->FreeAllMu;
    // memory tracker
    module->Memory.Alloc   = runtime->MemoryTracker->Alloc;
    module->Memory.Calloc  = runtime->MemoryTracker->Calloc;
    module->Memory.Realloc = runtime->MemoryTracker->Realloc;
    module->Memory.Free    = runtime->MemoryTracker->Free;
    module->Memory.Size    = runtime->MemoryTracker->Size;
    module->Memory.Cap     = runtime->MemoryTracker->Cap;
    module->Memory.Lock    = runtime->MemoryTracker->LockRegion;
    module->Memory.Unlock  = runtime->MemoryTracker->UnlockRegion;
    module->Memory.Status  = runtime->MemoryTracker->GetStatus;
    module->Memory.FreeAll = runtime->MemoryTracker->FreeAllMu;
    // thread tracker
    module->Thread.New     = runtime->ThreadTracker->New;
    module->Thread.Exit    = runtime->ThreadTracker->Exit;
    module->Thread.Sleep   = GetFuncAddr(&RT_Sleep);
    module->Thread.Lock    = runtime->ThreadTracker->LockThread;
    module->Thread.Unlock  = runtime->ThreadTracker->UnlockThread;
    module->Thread.Status  = runtime->ThreadTracker->GetStatus;
    module->Thread.KillAll = runtime->ThreadTracker->KillAllMu;
    // resource tracker
    module->Resource.LockMutex   = runtime->ResourceTracker->LockMutex;
    module->Resource.UnlockMutex = runtime->ResourceTracker->UnlockMutex;
    module->Resource.Status      = runtime->ResourceTracker->GetStatus;
    module->Resource.FreeAll     = runtime->ResourceTracker->FreeAllMu;
    // argument store
    module->Argument.GetValue   = runtime->ArgumentStore->GetValue;
    module->Argument.GetPointer = runtime->ArgumentStore->GetPointer;
    module->Argument.Erase      = runtime->ArgumentStore->Erase;
    module->Argument.EraseAll   = runtime->ArgumentStore->EraseAll;
    // in-memory storage
    module->Storage.SetValue   = runtime->InMemoryStorage->SetValue;
    module->Storage.GetValue   = runtime->InMemoryStorage->GetValue;
    module->Storage.GetPointer = runtime->InMemoryStorage->GetPointer;
    module->Storage.Delete     = runtime->InMemoryStorage->Delete;
    module->Storage.DeleteAll  = runtime->InMemoryStorage->DeleteAll;
    // WinBase
    module->WinBase.ANSIToUTF16  = runtime->WinBase->ANSIToUTF16;
    module->WinBase.UTF16ToANSI  = runtime->WinBase->UTF16ToANSI;
    module->WinBase.ANSIToUTF16N = runtime->WinBase->ANSIToUTF16N;
    module->WinBase.UTF16ToANSIN = runtime->WinBase->UTF16ToANSIN;
    // WinFile
    module->WinFile.ReadFileA  = runtime->WinFile->ReadFileA;
    module->WinFile.ReadFileW  = runtime->WinFile->ReadFileW;
    module->WinFile.WriteFileA = runtime->WinFile->WriteFileA;
    module->WinFile.WriteFileW = runtime->WinFile->WriteFileW;
    // WinHTTP
    module->WinHTTP.Get  = runtime->WinHTTP->Get;
    module->WinHTTP.Post = runtime->WinHTTP->Post;
    module->WinHTTP.Do   = runtime->WinHTTP->Do;
    module->WinHTTP.Free = runtime->WinHTTP->Free;
    // WinCrypto

    // random module
    module->Random.Buffer  = GetFuncAddr(&RandBuffer);
    module->Random.Bool    = GetFuncAddr(&RandBool);
    module->Random.Int64   = GetFuncAddr(&RandInt64);
    module->Random.Uint64  = GetFuncAddr(&RandUint64);
    module->Random.Int64N  = GetFuncAddr(&RandInt64N);
    module->Random.Uint64N = GetFuncAddr(&RandUint64N);
    // crypto module
    module->Crypto.Encrypt = GetFuncAddr(&EncryptBuf);
    module->Crypto.Decrypt = GetFuncAddr(&DecryptBuf);
    // compress module
    module->Compressor.Compress   = GetFuncAddr(&Compress);
    module->Compressor.Decompress = GetFuncAddr(&Decompress);
    // runtime IAT
    module->IAT.GetProcByName   = GetFuncAddr(&RT_GetProcAddressByName);
    module->IAT.GetProcByHash   = GetFuncAddr(&RT_GetProcAddressByHash);
    module->IAT.GetProcOriginal = GetFuncAddr(&RT_GetProcAddressOriginal);
    // runtime core methods
    module->Core.Sleep   = GetFuncAddr(&RT_SleepHR);
    module->Core.Hide    = GetFuncAddr(&RT_Hide);
    module->Core.Recover = GetFuncAddr(&RT_Recover);
    module->Core.Metrics = GetFuncAddr(&RT_Metrics);
    module->Core.Cleanup = GetFuncAddr(&RT_Cleanup);
    module->Core.Exit    = GetFuncAddr(&RT_Exit);
    // runtime core data
    module->Data.Mutex = runtime->hMutex;
    // [THE END OF THE WORLD] :(
    module->ExitProcess = GetFuncAddr(&RT_ExitProcess);
    return module;
}

static bool isValidArgumentStub()
{
    uintptr stubAddr = (uintptr)(GetFuncAddr(&Argument_Stub));
    // calculate header checksum
    uint32 checksum = 0;
    for (uintptr i = 0; i < ARG_OFFSET_CHECKSUM; i++)
    {
        byte b = *(byte*)(stubAddr + i);
        checksum += checksum << 1;
        checksum += b;
    }
    uint32 expected = *(uint32*)(stubAddr + ARG_OFFSET_CHECKSUM);
    return checksum == expected;
}

static void* allocRuntimeMemPage()
{
#ifdef _WIN64
    uint hash = 0xB6A1D0D4A275D4B6;
    uint key  = 0x64CB4D66EC0BEFD9;
#elif _WIN32
    uint hash = 0xC3DE112E;
    uint key  = 0x8D9EA74F;
#endif
    VirtualAlloc_t virtualAlloc = FindAPI(hash, key);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }
    SIZE_T size = MAIN_MEM_PAGE_SIZE + (1 + RandUintN(0, 32)) * 1024;
    LPVOID addr = virtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    RandBuffer(addr, (int64)size);
    dbg_log("[runtime]", "Main Memory Page: 0x%zX", addr);
    return addr;
}

static void* calculateEpilogue()
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    uint32  size = *(uint32*)(stub + ARG_OFFSET_ARGS_SIZE);
    size += ARG_OFFSET_FIRST_ARG;
    return (void*)(stub + size);
}

static bool initRuntimeAPI(Runtime* runtime)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x2A9C7D79595F39B2, 0x11FB7144E3CF94BD }, // GetSystemInfo
        { 0x92CC6AD999858810, 0x4D23806992FC0259 }, // LoadLibraryA
        { 0x18AF23D87980A16C, 0xE3380ADD44CA22C7 }, // FreeLibrary
        { 0x6AC498DF641A4FCB, 0xFF3BB21B9BA46CEA }, // VirtualAlloc
        { 0xAC150252A6CA3960, 0x12EFAEA421D60C3E }, // VirtualFree
        { 0xEA5B0C76C7946815, 0x8846C203C35DE586 }, // VirtualProtect
        { 0x8172B49F66E495BA, 0x8F0D0796223B56C2 }, // FlushInstructionCache
        { 0xB8D0B91323A24997, 0xBC36CA6282477A43 }, // EXitProcess
        { 0x94EC785163801E26, 0xCBF66516D38443F0 }, // SetCurrentDirectoryA
        { 0x7A6FB9987CB1DB85, 0xF6A56D0FD43D9096 }, // SetCurrentDirectoryW
        { 0x31FE697F93D7510C, 0x77C8F05FE04ED22D }, // CreateMutexA
        { 0xEEFDEA7C0785B561, 0xA7B72CC8CD55C1D4 }, // ReleaseMutex
        { 0xDDB64F7D0952649B, 0x7F49C6179CD1D05C }, // CreateEventA
        { 0x4A7C9AD08B398C90, 0x4DA8D0C65ECE8AB5 }, // SetEvent
        { 0xDCC7DDE90F8EF5E5, 0x779EBCBF154A323E }, // ResetEvent
        { 0xA793213B60B4651D, 0x4CB3588ECF3B0A12 }, // CreateWaitableTimerW
        { 0x1C438D7C33D36592, 0xB8818ECC97728D1F }, // SetWaitableTimer
        { 0xC0B2A3A0E0136020, 0xFCD8552BA93BD07E }, // SleepEx
        { 0xA524CD56CF8DFF7F, 0x5519595458CD47C8 }, // WaitForSingleObject
        { 0xF7A5A49D19409FFC, 0x6F23FAA4C20FF4D3 }, // DuplicateHandle
        { 0xA25F7449D6939A01, 0x85D37F1D89B30D2E }, // CloseHandle
        { 0x7C1C9D36D30E0B75, 0x1ACD25CE8A87875A }, // GetProcAddress
    };
#elif _WIN32
    {
        { 0xD7792A53, 0x6DDE32BA }, // GetSystemInfo
        { 0xC4B3F4F2, 0x71C983EF }, // LoadLibraryA
        { 0xBB6DAE22, 0xADCBE537 }, // FreeLibrary
        { 0xB47741D5, 0x8034C451 }, // VirtualAlloc
        { 0xF76A2ADE, 0x4D8938BD }, // VirtualFree
        { 0xB2AC456D, 0x2A690F63 }, // VirtualProtect
        { 0x87A2CEE8, 0x42A3C1AF }, // FlushInstructionCache
        { 0xB6CEC366, 0xA0CF5E10 }, // EXitProcess
        { 0xBCCEAFB1, 0x99C565BD }, // SetCurrentDirectoryA
        { 0x499657EA, 0x7D23F113 }, // SetCurrentDirectoryW
        { 0x8F5BAED2, 0x43487DC7 }, // CreateMutexA
        { 0xFA42E55C, 0xEA9F1081 }, // ReleaseMutex
        { 0x013C9D2B, 0x5A4D045A }, // CreateEventA
        { 0x1F65B288, 0x8502DDE2 }, // SetEvent
        { 0xCB15B6B4, 0x6D95B453 }, // ResetEvent
        { 0x7AAC7586, 0xB30E1315 }, // CreateWaitableTimerW
        { 0x3F987BDE, 0x01C8C945 }, // SetWaitableTimer
        { 0xF1994D1A, 0xDFA78EB5 }, // SleepEx
        { 0xC21AB03D, 0xED3AAF22 }, // WaitForSingleObject
        { 0x0E7ED8B9, 0x025067E9 }, // DuplicateHandle
        { 0x60E108B2, 0x3C2DFF52 }, // CloseHandle
        { 0x1CE92A4E, 0xBFF4B241 }, // GetProcAddress
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

    runtime->GetSystemInfo         = list[0x00].proc;
    runtime->LoadLibraryA          = list[0x01].proc;
    runtime->FreeLibrary           = list[0x02].proc;
    runtime->VirtualAlloc          = list[0x03].proc;
    runtime->VirtualFree           = list[0x04].proc;
    runtime->VirtualProtect        = list[0x05].proc;
    runtime->FlushInstructionCache = list[0x06].proc;
    runtime->ExitProcess           = list[0x07].proc;
    runtime->SetCurrentDirectoryA  = list[0x08].proc;
    runtime->SetCurrentDirectoryW  = list[0x09].proc;
    runtime->CreateMutexA          = list[0x0A].proc;
    runtime->ReleaseMutex          = list[0x0B].proc;
    runtime->CreateEventA          = list[0x0C].proc;
    runtime->SetEvent              = list[0x0D].proc;
    runtime->ResetEvent            = list[0x0E].proc;
    runtime->CreateWaitableTimerW  = list[0x0F].proc;
    runtime->SetWaitableTimer      = list[0x10].proc;
    runtime->SleepEx               = list[0x11].proc;
    runtime->WaitForSingleObject   = list[0x12].proc;
    runtime->DuplicateHandle       = list[0x13].proc;
    runtime->CloseHandle           = list[0x14].proc;
    runtime->GetProcAddress        = list[0x15].proc;
    return true;
}

// CANNOT merge updateRuntimePointer and recoverRuntimePointer 
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

static bool updateRuntimePointer(Runtime* runtime)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getRuntimePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != RUNTIME_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)runtime;
        success = true;
        break;
    }
    return success;
}

static bool recoverRuntimePointer(Runtime* runtime)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getRuntimePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)runtime)
        {
            target++;
            continue;
        }
        *pointer = RUNTIME_POINTER;
        success = true;
        break;
    }
    return success;
}

static errno initRuntimeEnvironment(Runtime* runtime)
{
    // get memory page size
    SYSTEM_INFO sysInfo;
    runtime->GetSystemInfo(&sysInfo);
    runtime->PageSize = sysInfo.PageSize;
    // create global mutex
    HANDLE hMutex = runtime->CreateMutexA(NULL, false, NAME_RT_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return ERR_RUNTIME_CREATE_GLOBAL_MUTEX;
    }
    runtime->hMutex = hMutex;
    // create sleep method mutex
    HANDLE hMutexSleep = runtime->CreateMutexA(NULL, false, NAME_RT_MUTEX_SLEEP);
    if (hMutexSleep == NULL)
    {
        return ERR_RUNTIME_CREATE_SLEEP_MUTEX;
    }
    runtime->hMutexSleep = hMutexSleep;
    // create arrive and done events
    HANDLE hEventArrive = runtime->CreateEventA(NULL, true, false, NAME_RT_EVENT_ARRIVE);
    if (hEventArrive == NULL)
    {
        return ERR_RUNTIME_CREATE_EVENT_ARRIVE;
    }
    runtime->hEventArrive = hEventArrive;
    HANDLE hEventDone = runtime->CreateEventA(NULL, true, false, NAME_RT_EVENT_DONE);
    if (hEventDone == NULL)
    {
        return ERR_RUNTIME_CREATE_EVENT_DONE;
    }
    runtime->hEventDone = hEventDone;
    // create event type mutex
    HANDLE hMutexEvent = runtime->CreateMutexA(NULL, false, NAME_RT_MUTEX_EVENT);
    if (hMutexEvent == NULL)
    {
        return ERR_RUNTIME_CREATE_EVENT_MUTEX;
    }
    runtime->hMutexEvent = hMutexEvent;
    return NO_ERROR;
}

static errno initSubmodules(Runtime* runtime)
{
    // create context data for initialize other modules
    Context context = {
        .NotEraseInstruction = runtime->Options.NotEraseInstruction,
        .TrackCurrentThread  = runtime->Options.TrackCurrentThread,

        .MainMemPage = (uintptr)(runtime->MainMemPage),
        .PageSize    = runtime->PageSize,

        .malloc  = GetFuncAddr(&RT_malloc),
        .calloc  = GetFuncAddr(&RT_calloc),
        .realloc = GetFuncAddr(&RT_realloc),
        .free    = GetFuncAddr(&RT_free),
        .msize   = GetFuncAddr(&RT_msize),
        .mcap    = GetFuncAddr(&RT_mcap),

        .lock   = GetFuncAddr(&RT_lock_mods),
        .unlock = GetFuncAddr(&RT_unlock_mods),

        .LoadLibraryA          = runtime->LoadLibraryA,
        .FreeLibrary           = runtime->FreeLibrary,
        .VirtualAlloc          = runtime->VirtualAlloc,
        .VirtualFree           = runtime->VirtualFree,
        .VirtualProtect        = runtime->VirtualProtect,
        .CreateMutexA          = runtime->CreateMutexA,
        .ReleaseMutex          = runtime->ReleaseMutex,
        .WaitForSingleObject   = runtime->WaitForSingleObject,
        .FlushInstructionCache = runtime->FlushInstructionCache,
        .DuplicateHandle       = runtime->DuplicateHandle,
        .CloseHandle           = runtime->CloseHandle,
        .Sleep                 = GetFuncAddr(&RT_Sleep),
    };

    typedef errno (*module_t)(Runtime* runtime, Context* context);

    // initialize runtime submodules
    module_t submodules[] = 
    {
        GetFuncAddr(&initLibraryTracker),
        GetFuncAddr(&initMemoryTracker),
        GetFuncAddr(&initThreadTracker),
        GetFuncAddr(&initResourceTracker),
        GetFuncAddr(&initArgumentStore),
        GetFuncAddr(&initInMemoryStorage),
    };
    for (int i = 0; i < arrlen(submodules); i++)
    {
        errno errno = submodules[i](runtime, &context);
        if (errno != NO_ERROR)
        {
            return errno;
        }
    }

    // update context about runtime submodules
    context.mt_malloc  = runtime->MemoryTracker->Alloc;
    context.mt_calloc  = runtime->MemoryTracker->Calloc;
    context.mt_realloc = runtime->MemoryTracker->Realloc;
    context.mt_free    = runtime->MemoryTracker->Free;
    context.mt_msize   = runtime->MemoryTracker->Size;
    context.mt_mcap    = runtime->MemoryTracker->Cap;

    // initialize high-level modules
    module_t hl_modules[] = 
    {
        GetFuncAddr(&initWinBase),
        GetFuncAddr(&initWinFile),
        GetFuncAddr(&initWinHTTP),
    };
    for (int i = 0; i < arrlen(hl_modules); i++)
    {
        errno errno = hl_modules[i](runtime, &context);
        if (errno != NO_ERROR)
        {
            return errno;
        }
    }

    // clean useless API functions in runtime structure
    RandBuffer((byte*)(&runtime->GetSystemInfo), sizeof(uintptr));
    RandBuffer((byte*)(&runtime->CreateMutexA),  sizeof(uintptr));
    RandBuffer((byte*)(&runtime->CreateEventA),  sizeof(uintptr));
    return NO_ERROR;
}

static errno initLibraryTracker(Runtime* runtime, Context* context)
{
    LibraryTracker_M* tracker = InitLibraryTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->LibraryTracker = tracker;
    return NO_ERROR;
}

static errno initMemoryTracker(Runtime* runtime, Context* context)
{
    MemoryTracker_M* tracker = InitMemoryTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->MemoryTracker = tracker;
    return NO_ERROR;
}

static errno initThreadTracker(Runtime* runtime, Context* context)
{
    ThreadTracker_M* tracker = InitThreadTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->ThreadTracker = tracker;
    return NO_ERROR;
}

static errno initResourceTracker(Runtime* runtime, Context* context)
{
    ResourceTracker_M* tracker = InitResourceTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->ResourceTracker = tracker;
    return NO_ERROR;
}

static errno initArgumentStore(Runtime* runtime, Context* context)
{
    ArgumentStore_M* store = InitArgumentStore(context);
    if (store == NULL)
    {
        return GetLastErrno();
    }
    runtime->ArgumentStore = store;
    return NO_ERROR;
}

static errno initInMemoryStorage(Runtime* runtime, Context* context)
{
    InMemoryStorage_M* storage = InitInMemoryStorage(context);
    if (storage == NULL)
    {
        return GetLastErrno();
    }
    runtime->InMemoryStorage = storage;
    return NO_ERROR;
}

static errno initWinBase(Runtime* runtime, Context* context)
{
    WinBase_M* winBase = InitWinBase(context);
    if (winBase == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinBase = winBase;
    return NO_ERROR;
}

static errno initWinFile(Runtime* runtime, Context* context)
{
    WinFile_M* winFile = InitWinFile(context);
    if (winFile == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinFile = winFile;
    return NO_ERROR;
}

static errno initWinHTTP(Runtime* runtime, Context* context)
{
    WinHTTP_M* winHTTP = InitWinHTTP(context);
    if (winHTTP == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinHTTP = winHTTP;
    return NO_ERROR;
}

static bool initIATHooks(Runtime* runtime)
{
    LibraryTracker_M*  libraryTracker  = runtime->LibraryTracker;
    MemoryTracker_M*   memoryTracker   = runtime->MemoryTracker;
    ThreadTracker_M*   threadTracker   = runtime->ThreadTracker;
    ResourceTracker_M* resourceTracker = runtime->ResourceTracker;

    typedef struct {
        uint hash; uint key; void* hook;
    } item;
    item items[] =
#ifdef _WIN64
    {
        { 0xCAA4843E1FC90287, 0x2F19F60181B5BFE3, GetFuncAddr(&RT_GetProcAddress) },
        { 0x2619069D6D00AC17, 0xA12815DB2311C3C0, GetFuncAddr(&RT_SetCurrentDirectoryA) },
        { 0x6A8F6B893B3E7468, 0x1C4D6ABB7E274A8A, GetFuncAddr(&RT_SetCurrentDirectoryW) },
        { 0xCED5CC955152CD43, 0xAA22C83C068CB037, GetFuncAddr(&RT_SleepHR) },
        { 0xF8AFE6686E40E6E7, 0xE461B3ED286DAF92, GetFuncAddr(&RT_SleepEx) },
        { 0xD823D640CA9D87C3, 0x15821AE3463EFBE8, libraryTracker->LoadLibraryA },
        { 0xDE75B0371B7500C0, 0x2A1CF678FC737D0F, libraryTracker->LoadLibraryW },
        { 0x448751B1385751E8, 0x3AE522A4E9435111, libraryTracker->LoadLibraryExA },
        { 0x7539E619D8B4166E, 0xE52EE8B2C2D15D9B, libraryTracker->LoadLibraryExW },
        { 0x80B0A97C97E9FE79, 0x675B0BA55C1758F9, libraryTracker->FreeLibrary },
        { 0x66F288FB8CF6CADD, 0xC48D2119FF3ADC6A, libraryTracker->FreeLibraryAndExitThread },
        { 0x18A3895F35B741C8, 0x96C9890F48D55E7E, memoryTracker->VirtualAlloc },
        { 0xDB54AA6683574A8B, 0x3137DE2D71D3FF3E, memoryTracker->VirtualFree },
        { 0xF5469C21B43D23E5, 0xF80028997F625A05, memoryTracker->VirtualProtect },
        { 0xE9ECDC63F6D3DC53, 0x815C2FDFE640307E, memoryTracker->VirtualQuery },
        { 0xFFDAAC40C9760BF6, 0x75E3BCA6D545E130, memoryTracker->HeapCreate },
        { 0xF2B10CAD6B4626E6, 0x14D21E0224A81F33, memoryTracker->HeapDestroy },
        { 0x2D5BD20546A9F7FF, 0xD1569863116D78AA, memoryTracker->HeapAlloc },
        { 0x622C7DF56116553C, 0x4545A260B5B4EE4F, memoryTracker->HeapReAlloc },
        { 0xEB6C5AC538D9CB88, 0x31C1AE2150C892FA, memoryTracker->HeapFree },
        { 0xF07CA2BE1E1D44B0, 0xF5D1D9ACFCC34F21, memoryTracker->HeapSize },
        { 0xDD0B1C33C5E8DE6B, 0x8E5C390C6FA06475, memoryTracker->GlobalAlloc },
        { 0x96EA754ECF447CB9, 0xB041E8B71EC6E6AE, memoryTracker->GlobalReAlloc },
        { 0x402039178195F587, 0x31AC6524EF5DB181, memoryTracker->GlobalFree },
        { 0xD5213AB31B1D5943, 0xC33F3C38A13B501E, memoryTracker->LocalAlloc },
        { 0x2E12831CCA966749, 0x4EAC960E9A01E99A, memoryTracker->LocalReAlloc },
        { 0xC62EFD9A11EB91B7, 0x926374B4CE1B1737, memoryTracker->LocalFree },
        { 0x1E8B0246BF18CA97, 0xC131B02374BDDB50, memoryTracker->HeapAlloc },   // ntdll.RtlAllocateHeap
        { 0x3E96C8D55DF611FB, 0x9BD65CE3AABE9404, memoryTracker->HeapReAlloc }, // ntdll.RtlReAllocateHeap
        { 0xCB9C04169B2FE6A6, 0xFE277A3C4C7E6B27, memoryTracker->HeapFree },    // ntdll.RtlFreeHeap
        { 0x0AA12F40EDAD881E, 0x3C699B9AB31D2007, memoryTracker->HeapSize },    // ntdll.RtlSizeHeap
        { 0x84AC57FA4D95DE2E, 0x5FF86AC14A334443, threadTracker->CreateThread },
        { 0xA6E10FF27A1085A8, 0x24815A68A9695B16, threadTracker->ExitThread },
        { 0x82ACE4B5AAEB22F1, 0xF3132FCE3AC7AD87, threadTracker->SuspendThread },
        { 0x226860209E13A99A, 0xE1BD9D8C64FAF97D, threadTracker->ResumeThread },
        { 0x374E149C710B1006, 0xE5D0E3FA417FA6CF, threadTracker->GetThreadContext },
        { 0xCFE3FFD5F0023AE3, 0x9044E42F1C020CF5, threadTracker->SetThreadContext },
        { 0x248E1CDD11AB444F, 0x195932EA70030929, threadTracker->TerminateThread },
        { 0xFA78B22F20F4A6AE, 0xBE9C88DB7A69D0FA, threadTracker->TlsAlloc },
        { 0x04ACE48652C6FABB, 0x19401007C082388D, threadTracker->TlsFree },
        { 0xEE9B49D8A9AFB57E, 0xB241162E988541ED, threadTracker->ExitThread }, // ntdll.RtlExitUserThread
        { 0x58926BA5F71CBB5B, 0x1E1F604F6035248A, resourceTracker->CreateMutexA },
        { 0x95A1D6B96343624E, 0xA7C4DE10EA2DA12F, resourceTracker->CreateMutexW },
        { 0x7875DE52EC02CD8B, 0xB95F39E380958D5E, resourceTracker->CreateEventA },
        { 0xE116F3576A0D31F5, 0x3E535616ED1E31A4, resourceTracker->CreateEventW },
        { 0x94DAFAE03484102D, 0x300F881516DC2FF5, resourceTracker->CreateFileA },
        { 0xC3D28B35396A90DA, 0x8BA6316E5F5DC86E, resourceTracker->CreateFileW },
        { 0x4015A18370E27D65, 0xA5B47007B7B8DD26, resourceTracker->FindFirstFileA },
        { 0x7C520EB61A85181B, 0x933C760F029EF1DD, resourceTracker->FindFirstFileW },
        { 0xFB272B44E7E9CFC6, 0xB5F76233869E347D, resourceTracker->FindFirstFileExA },
        { 0x1C30504D9D6BC5E5, 0xF5C232B8DEEC41C8, resourceTracker->FindFirstFileExW },
        { 0x78AEE64CADBBC72F, 0x480A328AEFFB1A39, resourceTracker->CloseHandle },
        { 0x3D3A73632A3BCEDA, 0x72E6CA3A0850F779, resourceTracker->FindClose },
    };
#elif _WIN32
    {
        { 0x5E5065D4, 0x63CDAD01, GetFuncAddr(&RT_GetProcAddress) },
        { 0x04A35C23, 0xF841E05C, GetFuncAddr(&RT_SetCurrentDirectoryA) },
        { 0xCA170DA2, 0x73683646, GetFuncAddr(&RT_SetCurrentDirectoryA) },
        { 0x705D4FAD, 0x94CF33BF, GetFuncAddr(&RT_SleepHR) },
        { 0x57601363, 0x0F03636B, GetFuncAddr(&RT_SleepEx) },
        { 0x0149E478, 0x86A603D3, libraryTracker->LoadLibraryA },
        { 0x90E21596, 0xEBEA7D19, libraryTracker->LoadLibraryW },
        { 0xD6C482CE, 0xC6063014, libraryTracker->LoadLibraryExA },
        { 0x158D5700, 0x24540418, libraryTracker->LoadLibraryExW },
        { 0x5CDBC79F, 0xA1B99CF2, libraryTracker->FreeLibrary },
        { 0x929869F4, 0x7D668185, libraryTracker->FreeLibraryAndExitThread },
        { 0xD5B65767, 0xF3A27766, memoryTracker->VirtualAlloc },
        { 0x4F0FC063, 0x182F3CC6, memoryTracker->VirtualFree },
        { 0xEBD60441, 0x280A4A9F, memoryTracker->VirtualProtect },
        { 0xD17B0461, 0xFB4E5DB5, memoryTracker->VirtualQuery },
        { 0xDEBEFC7A, 0x5430728E, memoryTracker->HeapCreate },
        { 0x939FB28D, 0x2A9F34C6, memoryTracker->HeapDestroy },
        { 0x05810867, 0xF2ABDB50, memoryTracker->HeapAlloc },
        { 0x7A3662A9, 0x71FAAA63, memoryTracker->HeapReAlloc },
        { 0xDB3AEF73, 0x380DB39D, memoryTracker->HeapFree },
        { 0x7CD7678E, 0x7004C8D0, memoryTracker->HeapSize },
        { 0x7B033FBA, 0x35363CF6, memoryTracker->GlobalAlloc },
        { 0x7DFE57A5, 0x8119A6D8, memoryTracker->GlobalReAlloc },
        { 0x08756F00, 0x7111FC71, memoryTracker->GlobalFree },
        { 0x2B3437C8, 0x7574CBE1, memoryTracker->LocalAlloc },
        { 0x8F9470A1, 0xCC687C1A, memoryTracker->LocalReAlloc },
        { 0xAA325FF1, 0x895CDAFC, memoryTracker->LocalFree },
        { 0x92E5F4A5, 0xA3F5C520, memoryTracker->HeapAlloc },   // ntdll.RtlAllocateHeap
        { 0x51FDFBBA, 0x4DBA4387, memoryTracker->HeapReAlloc }, // ntdll.RtlReAllocateHeap
        { 0xD59A6BA8, 0x1B0A7768, memoryTracker->HeapFree },    // ntdll.RtlFreeHeap
        { 0xEDFA2017, 0x9F4BDE59, memoryTracker->HeapSize },    // ntdll.RtlSizeHeap
        { 0x20744CA1, 0x4FA1647D, threadTracker->CreateThread },
        { 0xED42C0F0, 0xC59EBA39, threadTracker->ExitThread },
        { 0x133B00D5, 0x48E02627, threadTracker->SuspendThread },
        { 0xA02B4251, 0x5287173F, threadTracker->ResumeThread },
        { 0xCF0EC7B7, 0xBAC33715, threadTracker->GetThreadContext },
        { 0xC59EF832, 0xEF75D2EA, threadTracker->SetThreadContext },
        { 0x6EF0E2AA, 0xE014E29F, threadTracker->TerminateThread },
        { 0x52598AD3, 0xD7C6183F, threadTracker->TlsAlloc },
        { 0x218DD96E, 0x05FED0A2, threadTracker->TlsFree },
        { 0x74B3E012, 0xA73A6B97, threadTracker->ExitThread }, // ntdll.RtlExitUserThread
        { 0xC6B5D6DD, 0x36010787, resourceTracker->CreateMutexA },
        { 0x144D7209, 0xB789D747, resourceTracker->CreateMutexW },
        { 0x5E43201A, 0xFE7C8A22, resourceTracker->CreateEventA },
        { 0x15746F79, 0x83C4C211, resourceTracker->CreateEventW },
        { 0x79796D6E, 0x6DBBA55C, resourceTracker->CreateFileA },
        { 0x0370C4B8, 0x76254EF3, resourceTracker->CreateFileW },
        { 0x629ADDFA, 0x749D1CC9, resourceTracker->FindFirstFileA },
        { 0x612273CD, 0x563EDF55, resourceTracker->FindFirstFileW },
        { 0x8C692AD6, 0xB63ECE85, resourceTracker->FindFirstFileExA },
        { 0xE52EE07C, 0x6C2F10B6, resourceTracker->FindFirstFileExW },
        { 0xCB5BD447, 0x49A6FC78, resourceTracker->CloseHandle },
        { 0x6CD807C4, 0x812C40E9, resourceTracker->FindClose },
    };
#endif
    for (int i = 0; i < arrlen(items); i++)
    {
        void* proc = FindAPI(items[i].hash, items[i].key);
        if (proc == NULL)
        {
            return false;
        }
        runtime->IATHooks[i].Proc = proc;
        runtime->IATHooks[i].Hook = items[i].hook;
    }
    return true;
}

__declspec(noinline)
static void eraseRuntimeMethods(Runtime* runtime)
{
    if (runtime->Options.NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&allocRuntimeMemPage));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseRuntimeMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

// ======================== these instructions will not be erased ========================

// change memory protect for dynamic update pointer that hard encode.
__declspec(noinline)
static bool adjustPageProtect(Runtime* runtime, DWORD* old)
{
    if (runtime->Options.NotAdjustProtect)
    {
        return true;
    }
    void* init = GetFuncAddr(&InitRuntime);
    void* addr = runtime->Options.BootInstAddress;
    if (addr == NULL || (uintptr)addr > (uintptr)init)
    {
        addr = init;
    }
    uintptr begin = (uintptr)(addr);
    uintptr end   = (uintptr)(runtime->Epilogue);
    uint    size  = end - begin;
    if (old == NULL)
    {
        DWORD oldProtect = 0;
        old = &oldProtect;
    }
    return runtime->VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, old);
}

__declspec(noinline)
static bool recoverPageProtect(Runtime* runtime, DWORD protect)
{
    if (runtime->Options.NotAdjustProtect)
    {
        return true;
    }
    void* init = GetFuncAddr(&InitRuntime);
    void* addr = runtime->Options.BootInstAddress;
    if (addr == NULL || (uintptr)addr > (uintptr)init)
    {
        addr = init;
    }
    uintptr begin = (uintptr)(addr);
    uintptr end   = (uintptr)(runtime->Epilogue);
    uint    size  = end - begin;
    DWORD   old;
    return runtime->VirtualProtect(addr, size, protect, &old);
}

__declspec(noinline)
static bool flushInstructionCache(Runtime* runtime)
{
    void* init = GetFuncAddr(&InitRuntime);
    void* addr = runtime->Options.BootInstAddress;
    if (addr == NULL || (uintptr)addr > (uintptr)init)
    {
        addr = init;
    }
    uintptr begin = (uintptr)(addr);
    uintptr end   = (uintptr)(runtime->Epilogue);
    uint    size  = end - begin;
    return runtime->FlushInstructionCache(CURRENT_PROCESS, addr, size);
}

static errno cleanRuntime(Runtime* runtime)
{
    errno err = NO_ERROR;
    // exit event handler
    errno enetg = exitEventHandler(runtime);
    if (enetg != NO_ERROR && err == NO_ERROR)
    {
        err = enetg;
    }
    // close all handles in runtime
    errno enchd = closeHandles(runtime);
    if (enchd != NO_ERROR && err == NO_ERROR)
    {
        err = enchd;
    }
    // must copy variables in Runtime before call RandBuf
    VirtualFree_t virtualFree = runtime->VirtualFree;
    void* memPage = runtime->MainMemPage;
    // release main memory page
    RandBuffer(memPage, MAIN_MEM_PAGE_SIZE);
    if (virtualFree != NULL)
    {
        if (!virtualFree(memPage, 0, MEM_RELEASE) && err == NO_ERROR)
        {
            err = ERR_RUNTIME_CLEAN_FREE_MEM;
        }
    }
    return err;
}

static errno exitEventHandler(Runtime* runtime)
{
    if (runtime->hThreadEvent == NULL)
    {
        return NO_ERROR;
    }
    errno errno = NO_ERROR;
    for (;;)
    {
        // set event type
        if (runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE) != WAIT_OBJECT_0)
        {
            errno = ERR_RUNTIME_LOCK_EVENT;
            break;
        }
        runtime->EventType = EVENT_TYPE_STOP;
        if (!runtime->ReleaseMutex(runtime->hMutexEvent))
        {
            errno = ERR_RUNTIME_UNLOCK_EVENT;
            break;
        }
        // notice event handler
        if (!runtime->SetEvent(runtime->hEventArrive))
        {
            errno = ERR_RUNTIME_NOTICE_EVENT_HANDLER;
            break;
        }
        // wait handler process event
        if (runtime->WaitForSingleObject(runtime->hEventDone, INFINITE) != WAIT_OBJECT_0)
        {
            errno = ERR_RUNTIME_WAIT_EVENT_HANDLER;
            break;
        }
        // receive errno
        if (runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE) != WAIT_OBJECT_0)
        {
            errno = ERR_RUNTIME_LOCK_EVENT;
            break;
        }
        errno = runtime->ReturnErrno;
        if (!runtime->ReleaseMutex(runtime->hMutexEvent))
        {
            errno = ERR_RUNTIME_UNLOCK_EVENT;
            break;
        }
        // reset event
        if (!runtime->ResetEvent(runtime->hEventDone))
        {
            errno = ERR_RUNTIME_RESET_EVENT;
            break;
        }
        break;
    }
    if (errno != NO_ERROR)
    {
        return errno;
    }
    // wait event handler thread exit
    if (runtime->WaitForSingleObject(runtime->hThreadEvent, INFINITE) != WAIT_OBJECT_0)
    {
        if (errno == NO_ERROR)
        {
            errno = ERR_RUNTIME_EXIT_EVENT_HANDLER;
        }
    }
    return errno;
}

static errno closeHandles(Runtime* runtime)
{
    if (runtime->CloseHandle == NULL)
    {
        return NO_ERROR;
    }
    typedef struct { 
        HANDLE handle; errno errno;
    } handle;
    handle list[] = 
    {
        { runtime->hMutex,       ERR_RUNTIME_CLEAN_H_MUTEX         },
        { runtime->hMutexSleep,  ERR_RUNTIME_CLEAN_H_MUTEX_SLEEP   },
        { runtime->hEventArrive, ERR_RUNTIME_CLEAN_H_EVENT_ARRIVE  },
        { runtime->hEventDone,   ERR_RUNTIME_CLEAN_H_EVENT_DONE    },
        { runtime->hMutexEvent,  ERR_RUNTIME_CLEAN_H_MUTEX_EVENT   },
        { runtime->hThreadEvent, ERR_RUNTIME_CLEAN_H_EVENT_HANDLER },
    };
    errno errno = NO_ERROR;
    for (int i = 0; i < arrlen(list); i++)
    {
        if (list[i].handle == NULL)
        {
            continue;
        }
        if (!runtime->CloseHandle(list[i].handle) && errno == NO_ERROR)
        {
            errno = list[i].errno;
        }
    }
    return errno;
}

// updateRuntimePointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateRuntimePointer will fail.
#pragma optimize("", off)
static Runtime* getRuntimePointer()
{
    uintptr pointer = RUNTIME_POINTER;
    return (Runtime*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool rt_lock()
{
    Runtime* runtime = getRuntimePointer();

    DWORD event = runtime->WaitForSingleObject(runtime->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool rt_unlock()
{
    Runtime* runtime = getRuntimePointer();

    return runtime->ReleaseMutex(runtime->hMutex);
}

// +---------+----------+-------------+
// |  size   | capacity | user buffer |
// +---------+----------+-------------+
// |  uint   |   uint   |     var     |
// +---------+----------+-------------+

__declspec(noinline)
void* RT_malloc(uint size)
{
    Runtime* runtime = getRuntimePointer();

    if (size == 0)
    {
        return NULL;
    }
    // ensure the size is a multiple of memory page size.
    // it also for prevent track the special page size.
    uint memSize = ((size / runtime->PageSize) + 1) * runtime->PageSize;
    void* addr = runtime->VirtualAlloc(NULL, memSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
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
    uint cap = memSize - 16;
    mem_copy(address + sizeof(size), &cap, sizeof(cap));
    dbg_log("[runtime]", "malloc size: %zu", size);
    return (void*)(address + 16);
}

__declspec(noinline)
void* RT_calloc(uint num, uint size)
{
    uint total = num * size;
    if (total == 0)
    {
        return NULL;
    }
    void* addr = RT_malloc(total);
    if (addr == NULL)
    {
        return NULL;
    }
    mem_init(addr, total);
    dbg_log("[runtime]", "calloc num: %zu, size: %zu", num, size);
    return addr;
}

__declspec(noinline)
void* RT_realloc(void* ptr, uint size)
{
    if (ptr == NULL)
    {
        return RT_malloc(size);
    }
    if (size == 0)
    {
        RT_free(ptr);
        return NULL;
    }
    // check need expand capacity
    uint cap = RT_mcap(ptr);
    if (size <= cap)
    {
        *(uint*)((uintptr)(ptr)-16) = size;
        return ptr;
    }
    // allocate new memory
    if (cap < 65536)
    {
        cap = size * 2;
    } else {
        cap = size * 5 / 4; // size *= 1.25
    }
    void* newPtr = RT_malloc(size);
    if (newPtr == NULL)
    {
        return NULL;
    }
    // copy data to new memory
    uint oldSize = *(uint*)((uintptr)(ptr)-16);
    mem_copy(newPtr, ptr, oldSize);
    // free old memory
    if (!RT_free(ptr))
    {
        RT_free(newPtr);
        return NULL;
    }
    dbg_log("[runtime]", "realloc ptr: 0x%zX, size: %zu", ptr, size);
    return newPtr;
}

__declspec(noinline)
bool RT_free(void* ptr)
{
    Runtime* runtime = getRuntimePointer();

    if (ptr == NULL)
    {
        return true;
    }
    // clean the buffer data before call VirtualFree.
    void* addr = (void*)((uintptr)(ptr)-16);
    uint  size = *(uint*)addr;
    mem_init((byte*)addr, size);
    if (!runtime->VirtualFree(addr, 0, MEM_RELEASE))
    {
        return false;
    }
    dbg_log("[runtime]", "free ptr: 0x%zX", ptr);
    return true;
}

__declspec(noinline)
uint RT_msize(void* ptr)
{
    if (ptr == NULL)
    {
        return 0;
    }
    return *(uint*)((uintptr)(ptr)-16);
}

__declspec(noinline)
uint RT_mcap(void* ptr)
{
    if (ptr == NULL)
    {
        return 0;
    }
    return *(uint*)((uintptr)(ptr)-16+sizeof(uint));
}

__declspec(noinline)
errno RT_lock_mods()
{
    Runtime* runtime = getRuntimePointer();

    typedef bool (*submodule_t)();
    submodule_t submodules[] = 
    {
        runtime->WinHTTP->Lock,
        runtime->LibraryTracker->Lock,
        runtime->MemoryTracker->Lock,
        runtime->ResourceTracker->Lock,
        runtime->ArgumentStore->Lock,
        runtime->InMemoryStorage->Lock,
        runtime->ThreadTracker->Lock,
    };
    errno errnos[] = 
    {
        ERR_RUNTIME_LOCK_WIN_HTTP,
        ERR_RUNTIME_LOCK_LIBRARY,
        ERR_RUNTIME_LOCK_MEMORY,
        ERR_RUNTIME_LOCK_RESOURCE,
        ERR_RUNTIME_LOCK_ARGUMENT,
        ERR_RUNTIME_LOCK_STORAGE,
        ERR_RUNTIME_LOCK_THREAD,
    };
    for (int i = 0; i < arrlen(submodules); i++)
    {
        if (!submodules[i]())
        {
            return errnos[i];
        }
    }
    return NO_ERROR;
}

__declspec(noinline)
errno RT_unlock_mods()
{
    Runtime* runtime = getRuntimePointer();

    typedef bool (*submodule_t)();
    submodule_t submodules[] = 
    {
        runtime->ThreadTracker->Unlock,
        runtime->LibraryTracker->Unlock,
        runtime->MemoryTracker->Unlock,
        runtime->ResourceTracker->Unlock,
        runtime->ArgumentStore->Unlock,
        runtime->InMemoryStorage->Unlock,
        runtime->WinHTTP->Unlock,
    };
    errno errnos[] = 
    {
        ERR_RUNTIME_UNLOCK_THREAD,
        ERR_RUNTIME_UNLOCK_LIBRARY,
        ERR_RUNTIME_UNLOCK_MEMORY,
        ERR_RUNTIME_UNLOCK_RESOURCE,
        ERR_RUNTIME_UNLOCK_ARGUMENT,
        ERR_RUNTIME_UNLOCK_STORAGE,
        ERR_RUNTIME_UNLOCK_WIN_HTTP,
    };
    for (int i = 0; i < arrlen(submodules); i++)
    {
        if (!submodules[i]())
        {
            return errnos[i];
        }
    }
    return NO_ERROR;
}

__declspec(noinline)
void* RT_FindAPI(uint hash, uint key)
{
    return RT_GetProcAddressByHash(hash, key, true);
}

__declspec(noinline)
void* RT_FindAPI_A(byte* module, byte* function)
{                  
#ifdef _WIN64
    uint key = 0xA6C1B1E79D26D1E7;
#elif _WIN32
    uint key = 0x94645D8B;
#endif
    uint hash = HashAPI_A(module, function, key);
    return RT_GetProcAddressByHash(hash, key, true);
}

__declspec(noinline)
void* RT_FindAPI_W(uint16* module, byte* function)
{
#ifdef _WIN64
    uint key = 0xA6C1B1E79D26D1E7;
#elif _WIN32
    uint key = 0x94645D8B;
#endif
    uint hash = HashAPI_W(module, function, key);
    return RT_GetProcAddressByHash(hash, key, true);
}

__declspec(noinline)
void* RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    return RT_GetProcAddressByName(hModule, lpProcName, true);
}

__declspec(noinline)
void* RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool hook)
{
    Runtime* runtime = getRuntimePointer();

    // process ordinal import
    if (lpProcName < (LPCSTR)(0xFFFF))
    {
        return runtime->GetProcAddress(hModule, lpProcName);
    }
    // use "mem_init" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    uint16 module[MAX_PATH];
    mem_init(module, sizeof(module));
    // get module file name
    if (GetModuleFileName(hModule, module, sizeof(module)) == 0)
    {
        return NULL;
    }
    // check is runtime internal methods
    void* method = getRuntimeMethods(module, lpProcName);
    if (method != NULL)
    {
        return method;
    }
    // generate hash for get Windows API address
#ifdef _WIN64
    uint key = 0xA6C1B1E79D26D1E7;
#elif _WIN32
    uint key = 0x94645D8B;
#endif
    uint hash = HashAPI_W((uint16*)(module), (byte*)lpProcName, key);
    // try to find Windows API by hash
    void* proc = RT_GetProcAddressByHash(hash, key, hook);
    if (proc != NULL)
    {
        return proc;
    }
    // if failed to found, use original GetProcAddress
    // must skip runtime internel methods like "RT_Method"
    byte preifx[4] = { 'R', 'T', '_', 0x00 };
    ANSI procName  = (ANSI)lpProcName;
    if (strncmp_a(procName, preifx, 3) == 0)
    {
        return NULL;
    }
    return runtime->GetProcAddress(hModule, lpProcName);
}

__declspec(noinline)
void* RT_GetProcAddressByHash(uint hash, uint key, bool hook)
{
    Runtime* runtime = getRuntimePointer();

    void* proc = FindAPI(hash, key);
    if (proc == NULL)
    {
        return NULL;
    }
    if (!hook)
    {
        return proc;
    }
    void* iatHook = getIATHook(runtime, proc);
    if (iatHook != proc)
    {
        return iatHook;
    }
    void* lazyHook = getLazyAPIHook(runtime, proc);
    if (lazyHook != proc)
    {
        return lazyHook;
    }
    return proc;
}

// disable optimize for use call NOT jmp to runtime->GetProcAddress.
#pragma optimize("", off)
void* RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer();

    return runtime->GetProcAddress(hModule, lpProcName);
}
#pragma optimize("", on)

// getRuntimeMethods is used to obtain runtime internal methods, 
// such as GetProcAddress, ExitProcess and submodule methods.
// 
// HMODULE hModule = LoadLibraryA("GleamRT.dll");
// void* proc = GetProcAddress(hModule, "RT_AS_GetValue");
static void* getRuntimeMethods(LPCWSTR module, LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer();

    ArgumentStore_M*   argumentStore   = runtime->ArgumentStore;
    InMemoryStorage_M* inMemoryStorage = runtime->InMemoryStorage;

    typedef struct {
        uint hash; uint key; void* method;
    } method;
    method methods[] =
#ifdef _WIN64
    {
        { 0xA23FAC0E6398838A, 0xE4990D7D4933EE6A, GetFuncAddr(&RT_GetProcAddressByName)   },
        { 0xABD1E8F0D28E9F46, 0xAF34F5979D300C70, GetFuncAddr(&RT_GetProcAddressByHash)   },
        { 0xC9C5D350BB118FAE, 0x061A602F681F2636, GetFuncAddr(&RT_GetProcAddressOriginal) },
        { 0xED817580D5E2DD81, 0x84025019004D432B, GetFuncAddr(&RT_ExitProcess)            },
        { 0x6A02F558B3968168, 0x15BD021B51796FE2, argumentStore->GetValue     }, // RT_AS_GetValue
        { 0x528C040816E3C7C4, 0xC2BEA0891841420F, argumentStore->GetPointer   }, // RT_AS_GetPointer
        { 0x2C971D3A91D6819B, 0xCB6F3EF75315AB9E, argumentStore->Erase        }, // RT_AS_Erase
        { 0x784C9D23ABAD9E10, 0x3C7CCF88406B3E64, argumentStore->EraseAll     }, // RT_AS_EraseAll
        { 0xDB9EF088829FCEA9, 0x72EFB3A106842A53, inMemoryStorage->SetValue   }, // RT_IMS_SetValue 
        { 0xF3377A26479EB3CB, 0xB9D6D8F56D02F264, inMemoryStorage->GetValue   }, // RT_IMS_GetValue 
        { 0x448103F8E395E880, 0xDDE5F1CCCA965582, inMemoryStorage->GetPointer }, // RT_IMS_GetPointer 
        { 0x18E68E8D0181C7D3, 0xC1533F69CFD86286, inMemoryStorage->Delete     }, // RT_IMS_Delete 
        { 0xD4D85FA2D950D418, 0x8EF761B32DD5CF68, inMemoryStorage->DeleteAll  }, // RT_IMS_DeleteAll
    };
#elif _WIN32
    {
        { 0xCF983018, 0x3ECBF2DF, GetFuncAddr(&RT_GetProcAddressByName)   },
        { 0x40D5BD08, 0x302D5D2B, GetFuncAddr(&RT_GetProcAddressByHash)   },
        { 0x45556AA5, 0xB3BEF31D, GetFuncAddr(&RT_GetProcAddressOriginal) },
        { 0x39A658B0, 0x8C837EFD, GetFuncAddr(&RT_ExitProcess)            },
        { 0x60684ACC, 0xB1F98016, argumentStore->GetValue     }, // RT_AS_GetValue
        { 0x58A01B5B, 0x9E4D45AC, argumentStore->GetPointer   }, // RT_AS_GetPointer
        { 0x29C58712, 0x88F20801, argumentStore->Erase        }, // RT_AS_Erase
        { 0x6E0B3B88, 0x6A080B6B, argumentStore->EraseAll     }, // RT_AS_EraseAll
        { 0x4B5EF362, 0x4238A631, inMemoryStorage->SetValue   }, // RT_IMS_SetValue 
        { 0x835BFB13, 0xC7907B35, inMemoryStorage->GetValue   }, // RT_IMS_GetValue 
        { 0xBC30677C, 0x6EF2BC17, inMemoryStorage->GetPointer }, // RT_IMS_GetPointer 
        { 0x953387D5, 0x3EC82FF1, inMemoryStorage->Delete     }, // RT_IMS_Delete 
        { 0x9E5771AF, 0x15EF57B3, inMemoryStorage->DeleteAll  }, // RT_IMS_DeleteAll
    };
#endif
    for (int i = 0; i < arrlen(methods); i++)
    {
        uint hash = HashAPI_W((uint16*)module, (byte*)lpProcName, methods[i].key);
        if (hash != methods[i].hash)
        {
            continue;
        }
        return methods[i].method;
    }
    return NULL;
}

static void* getIATHook(Runtime* runtime, void* proc)
{
    for (int i = 0; i < arrlen(runtime->IATHooks); i++)
    {
        if (proc != runtime->IATHooks[i].Proc)
        {
            continue;
        }
        return runtime->IATHooks[i].Hook;
    }
    return proc;
}

// getLazyAPIHook is used to FindAPI after call LoadLibrary.
// Hooks in initIATHooks() are all in kernel32.dll.
static void* getLazyAPIHook(Runtime* runtime, void* proc)
{
    MemoryTracker_M*   memoryTracker   = runtime->MemoryTracker;
    ResourceTracker_M* resourceTracker = runtime->ResourceTracker;

    typedef struct {
        uint hash; uint key; void* hook;
    } hook;
    hook hooks[] =
#ifdef _WIN64
    {
        { 0x4D084BEDB72AB139, 0x0C3B997786E5B372, memoryTracker->msvcrt_malloc    },
        { 0x608A1F623962E67B, 0xABB120953420F49C, memoryTracker->msvcrt_calloc    },
        { 0xCDE1ED75FE80407B, 0xC64B380372D117F2, memoryTracker->msvcrt_realloc   },
        { 0xECC6F0177F0CCDE2, 0x43C1FCC7169E67D3, memoryTracker->msvcrt_free      },
        { 0xDA453E9BB2309BF6, 0xB13F111E4C0EA643, memoryTracker->msvcrt_msize     },
        { 0x53E4A1AC095BE0F6, 0xD152CAB732698100, memoryTracker->ucrtbase_malloc  },
        { 0x78B916AE84F7B39A, 0x32CF4F009411A2FB, memoryTracker->ucrtbase_calloc  },
        { 0x732F61E2A8E95DFC, 0x4A40B46C41B074F5, memoryTracker->ucrtbase_realloc },
        { 0x8C9673E7033C926C, 0x0BED866A2B82FABD, memoryTracker->ucrtbase_free    },
        { 0x765FF1E84D3CA299, 0x2B93B5CE54D15111, memoryTracker->ucrtbase_msize   },
        { 0x7749934E33C18703, 0xCFB41E32B03DC637, resourceTracker->WSAStartup     },
        { 0x46C76E87C13DF670, 0x37B6B54E4B2FBECC, resourceTracker->WSACleanup     },
    };
#elif _WIN32
    {
        { 0xD15ACBB7, 0x2881CB25, memoryTracker->msvcrt_malloc    },
        { 0xD34DACA0, 0xD69C094E, memoryTracker->msvcrt_calloc    },
        { 0x644CBC49, 0x332496CD, memoryTracker->msvcrt_realloc   },
        { 0xDFACD52A, 0xE56FB206, memoryTracker->msvcrt_free      },
        { 0xB15ED11C, 0xEB107AD8, memoryTracker->msvcrt_msize     },
        { 0xD475868A, 0x9A240ADB, memoryTracker->ucrtbase_malloc  },
        { 0xC407B737, 0xBBA2D057, memoryTracker->ucrtbase_calloc  },
        { 0xE8B6449C, 0x1AABE77E, memoryTracker->ucrtbase_realloc },
        { 0xCBF17F60, 0x205DDE4D, memoryTracker->ucrtbase_free    },
        { 0x203FE479, 0xDE2A742F, memoryTracker->ucrtbase_msize   },
        { 0xE487BC0B, 0x283C1684, resourceTracker->WSAStartup     },
        { 0x175B553E, 0x541A996E, resourceTracker->WSACleanup     },
    };
#endif
    for (int i = 0; i < arrlen(hooks); i++)
    {
        if (FindAPI(hooks[i].hash, hooks[i].key) != proc)
        {
            continue;
        }
        return hooks[i].hook;
    }
    return proc;
}

__declspec(noinline)
BOOL RT_SetCurrentDirectoryA(LPSTR lpPathName)
{
    Runtime* runtime = getRuntimePointer();

    dbg_log("[runtime]", "SetCurrentDirectoryA: %s", lpPathName);

    if (lpPathName == NULL)
    {
        return false;
    }
    if (*lpPathName != '*')
    {
        return true;
    }
    return runtime->SetCurrentDirectoryA(++lpPathName);
}

__declspec(noinline)
BOOL RT_SetCurrentDirectoryW(LPWSTR lpPathName)
{
    Runtime* runtime = getRuntimePointer();

    dbg_log("[runtime]", "SetCurrentDirectoryW: %ls", lpPathName);

    if (lpPathName == NULL)
    {
        return false;
    }
    if (*lpPathName != L'*')
    {
        return true;
    }
    return runtime->SetCurrentDirectoryW(++lpPathName);
}

__declspec(noinline)
void RT_Sleep(DWORD dwMilliseconds)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return;
    }

    // copy API address
    CreateWaitableTimerW_t create = runtime->CreateWaitableTimerW;
    SetWaitableTimer_t     set    = runtime->SetWaitableTimer;
    WaitForSingleObject_t  wait   = runtime->WaitForSingleObject;
    CloseHandle_t          close  = runtime->CloseHandle;

    if (!rt_unlock())
    {
        return;
    }

    HANDLE hTimer = create(NULL, false, NAME_RT_TIMER_SLEEP);
    if (hTimer == NULL)
    {
        return;
    }
    for (;;)
    {
        if (dwMilliseconds < 10)
        {
            dwMilliseconds = 10;
        }
        int64 dueTime = -((int64)dwMilliseconds * 1000 * 10);
        if (!set(hTimer, &dueTime, 0, NULL, NULL, true))
        {
            break;
        }
        if (wait(hTimer, INFINITE) != WAIT_OBJECT_0)
        {
            break;
        }
        break;
    }
    close(hTimer);
}

__declspec(noinline)
DWORD RT_SleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    if (!bAlertable)
    {
        RT_SleepHR(dwMilliseconds);
        return 0;
    }

    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return 0;
    }

    SleepEx_t sleepEx = runtime->SleepEx;

    if (!rt_unlock())
    {
        return 0;
    }
    return sleepEx(dwMilliseconds, bAlertable);
}

__declspec(noinline)
void RT_ExitProcess(UINT uExitCode)
{
    Runtime* runtime = getRuntimePointer();

    runtime->ExitProcess(uExitCode);
}

__declspec(noinline)
errno RT_SleepHR(DWORD dwMilliseconds)
{
    Runtime* runtime = getRuntimePointer();

    if (runtime->WaitForSingleObject(runtime->hMutexSleep, INFINITE) != WAIT_OBJECT_0)
    {
        return ERR_RUNTIME_LOCK_SLEEP;
    }

    if (dwMilliseconds <= 100)
    {
        // prevent sleep too frequent
        dwMilliseconds = 100;
    } else {
        // make sure the sleep time is a multiple of 1s
        dwMilliseconds = (dwMilliseconds / 1000) * 1000;
        if (dwMilliseconds == 0)
        {
            dwMilliseconds = 1000;
        }
    }

    // for test submodule faster
#ifndef RELEASE_MODE
    dwMilliseconds = 5 + (DWORD)RandUintN(0, 50);
#endif

    errno errno = NO_ERROR;
    for (;;)
    {
        // set sleep arguments
        if (runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE) != WAIT_OBJECT_0)
        {
            errno = ERR_RUNTIME_LOCK_EVENT;
            break;
        }
        runtime->EventType = EVENT_TYPE_SLEEP;
        runtime->SleepTime = dwMilliseconds;
        if (!runtime->ReleaseMutex(runtime->hMutexEvent))
        {
            errno = ERR_RUNTIME_UNLOCK_EVENT;
            break;
        }
        // notice event handler
        if (!runtime->SetEvent(runtime->hEventArrive))
        {
            errno = ERR_RUNTIME_NOTICE_EVENT_HANDLER;
            break;
        }
        // wait handler process event
        if (runtime->WaitForSingleObject(runtime->hEventDone, INFINITE) != WAIT_OBJECT_0)
        {
            errno = ERR_RUNTIME_WAIT_EVENT_HANDLER;
            break;
        }
        // receive return errno
        if (runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE) != WAIT_OBJECT_0)
        {
            errno = ERR_RUNTIME_LOCK_EVENT;
            break;
        }
        errno = runtime->ReturnErrno;
        if (!runtime->ReleaseMutex(runtime->hMutexEvent))
        {
            errno = ERR_RUNTIME_UNLOCK_EVENT;
            break;
        }
        // reset event
        if (!runtime->ResetEvent(runtime->hEventDone))
        {
            errno = ERR_RUNTIME_RESET_EVENT;
            break;
        }
        break;
    }

    if (!runtime->ReleaseMutex(runtime->hMutexSleep))
    {
        return ERR_RUNTIME_UNLOCK_SLEEP;
    }
    return errno;
}

__declspec(noinline)
static void eventHandler()
{
    Runtime* runtime = getRuntimePointer();

    bool  exit  = false;
    errno errno = NO_ERROR;

    for (;;)
    {
        uint32 waitEvent = runtime->WaitForSingleObject(runtime->hEventArrive, INFINITE);
        switch (waitEvent)
        {
        case WAIT_ABANDONED:
        case WAIT_OBJECT_0:
            errno = processEvent(runtime, &exit);
            break;
        default:
            return;
        }
        // store return error
        waitEvent = runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE);
        if (waitEvent != WAIT_OBJECT_0)
        {
            return;
        }
        runtime->ReturnErrno = errno;
        if (!runtime->ReleaseMutex(runtime->hMutexEvent))
        {
            return;
        }
        // notice caller
        if (!runtime->ResetEvent(runtime->hEventArrive))
        {
            return;
        }
        if (!runtime->SetEvent(runtime->hEventDone))
        {
            return;
        }
        // check is the exit event
        if (exit)
        {
            dbg_log("[runtime]", "exit event handler");
            return;
        }
        // check error for exit event handler
        if (errno != NO_ERROR && !(errno & ERR_FLAG_CAN_IGNORE))
        {
            dbg_log("[runtime]", "exit event handler with errno: 0x%X", errno);
            return;
        }
    }
}

static errno processEvent(Runtime* runtime, bool* exit)
{
    // get event type and arguments
    uint32 waitEvent = runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE);
    if (waitEvent != WAIT_OBJECT_0)
    {
        return ERR_RUNTIME_LOCK_EVENT;
    }
    uint32 eventType = runtime->EventType;
    uint32 sleepTime = runtime->SleepTime;
    if (!runtime->ReleaseMutex(runtime->hMutexEvent))
    {
        return ERR_RUNTIME_UNLOCK_EVENT;
    }
    // process event
    switch (eventType)
    {
    case EVENT_TYPE_SLEEP:
        dbg_log("[runtime]", "trigger event: sleep");
        return sleepHR(runtime, sleepTime);
    case EVENT_TYPE_STOP:
        dbg_log("[runtime]", "trigger event: stop");
        *exit = true;
        return NO_ERROR;
    default:
        panic(PANIC_UNREACHABLE_CODE);
    }
    return NO_ERROR;
}

__declspec(noinline)
static errno sleepHR(Runtime* runtime, uint32 milliseconds)
{
    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }

    errno err = RT_lock_mods();
    if (err != NO_ERROR)
    {
        return err;
    }

    HANDLE hTimer = NULL;
    errno  errno  = NO_ERROR;
    for (;;)
    {
        // create and set waitable timer
        hTimer = runtime->CreateWaitableTimerW(NULL, false, NAME_RT_TIMER_SLEEPHR);
        if (hTimer == NULL)
        {
            errno = ERR_RUNTIME_CREATE_WAITABLE_TIMER;
            break;
        }
        int64 dueTime = -((int64)milliseconds * 1000 * 10);
        if (!runtime->SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, true))
        {
            errno = ERR_RUNTIME_SET_WAITABLE_TIMER;
            break;
        }

        errno = hide(runtime);
        if (errno != NO_ERROR && !(errno & ERR_FLAG_CAN_IGNORE))
        {
            break;
        }
        errno = sleep(runtime, hTimer);
        if (errno != NO_ERROR && !(errno & ERR_FLAG_CAN_IGNORE))
        {
            break;
        }
        errno = recover(runtime);
        if (errno != NO_ERROR && !(errno & ERR_FLAG_CAN_IGNORE))
        {
            break;
        }
        break;
    }

    // clean created waitable timer
    if (hTimer != NULL)
    {
        if (!runtime->CloseHandle(hTimer) && errno == NO_ERROR)
        {
            errno = ERR_RUNTIME_CLOSE_WAITABLE_TIMER;
        }
    }

    err = RT_unlock_mods();
    if (err != NO_ERROR)
    {
        return err;
    }

    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
static errno hide(Runtime* runtime)
{
    typedef errno (*submodule_t)();
    submodule_t submodules[] = {
        runtime->WinHTTP->Clean,
        runtime->ThreadTracker->Suspend,
        runtime->LibraryTracker->Encrypt,
        runtime->MemoryTracker->Encrypt,
        runtime->ResourceTracker->Encrypt,
        runtime->ArgumentStore->Encrypt,
        runtime->InMemoryStorage->Encrypt,
    };
    for (int i = 0; i < arrlen(submodules); i++)
    {
        errno errno = submodules[i]();
        if (errno != NO_ERROR && !(errno & ERR_FLAG_CAN_IGNORE))
        {
            return errno;
        }
    }
    return NO_ERROR;
}

__declspec(noinline)
static errno recover(Runtime* runtime)
{
    typedef errno (*submodule_t)();
    submodule_t submodules[] = {
        runtime->LibraryTracker->Decrypt,
        runtime->MemoryTracker->Decrypt,
        runtime->ResourceTracker->Decrypt,
        runtime->ArgumentStore->Decrypt,
        runtime->InMemoryStorage->Decrypt,
        runtime->ThreadTracker->Resume,
    };
    for (int i = 0; i < arrlen(submodules); i++)
    {
        errno errno = submodules[i]();
        if (errno != NO_ERROR && !(errno & ERR_FLAG_CAN_IGNORE))
        {
            return errno;
        }
    }
    return NO_ERROR;
}

__declspec(noinline)
static errno sleep(Runtime* runtime, HANDLE hTimer)
{
    // calculate begin and end address
    uintptr beginAddress = (uintptr)(runtime->Options.BootInstAddress);
    uintptr runtimeAddr  = (uintptr)(GetFuncAddr(&InitRuntime));
    if (beginAddress == 0 || beginAddress > runtimeAddr)
    {
        beginAddress = runtimeAddr;
    }
    uintptr endAddress = (uintptr)(runtime->Epilogue);
    // must adjust protect before call shield stub // TODO update protect
    void* addr = (void*)beginAddress;
    DWORD size = (DWORD)(endAddress - beginAddress);
    DWORD oldProtect;
    if (!runtime->VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        return ERR_RUNTIME_ADJUST_PROTECT;
    }
    // build shield context before encrypt main memory page
    Shield_Ctx ctx = {
        .BeginAddress = beginAddress,
        .EndAddress   = endAddress,
        .hTimer       = hTimer,

        .WaitForSingleObject = runtime->WaitForSingleObject,
    };
    RandBuffer(ctx.CryptoKey, sizeof(ctx.CryptoKey));
    // encrypt main page
    void* buf = runtime->MainMemPage;
    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv,  CRYPTO_IV_SIZE);
    EncryptBuf(buf, MAIN_MEM_PAGE_SIZE, key, iv);
    // call shield!!!
    if (!DefenseRT(&ctx))
    {
        // TODO if failed to defense, need to recover them
        return ERR_RUNTIME_DEFENSE_RT;
    }
    // decrypt main page
    DecryptBuf(buf, MAIN_MEM_PAGE_SIZE, key, iv);
    // TODO remove this call, stub will adjust it
    if (!runtime->VirtualProtect(addr, size, oldProtect, &oldProtect))
    {
        return ERR_RUNTIME_RECOVER_PROTECT;
    }
    // flush instruction cache after decrypt
    void* baseAddr = (void*)beginAddress;
    uint  instSize = (uint)size;
    if (!runtime->FlushInstructionCache(CURRENT_PROCESS, baseAddr, instSize))
    {
        return ERR_RUNTIME_FLUSH_INST_CACHE;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno RT_Hide()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errlm = RT_lock_mods();
    if (errlm != NO_ERROR)
    {
        return errlm;
    }

    errno err = hide(runtime);

    errno errum = RT_unlock_mods();
    if (errum != NO_ERROR)
    {
        return errum;
    }
    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return err;
}

__declspec(noinline)
errno RT_Recover()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errlm = RT_lock_mods();
    if (errlm != NO_ERROR)
    {
        return errlm;
    }

    errno err = recover(runtime);

    errno errum = RT_unlock_mods();
    if (errum != NO_ERROR)
    {
        return errum;
    }
    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return err;
}

__declspec(noinline)
errno RT_Metrics(Runtime_Metrics* metrics)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }

    runtime->LibraryTracker->GetStatus(&metrics->Library);
    runtime->MemoryTracker->GetStatus(&metrics->Memory);
    runtime->ThreadTracker->GetStatus(&metrics->Thread);
    runtime->ResourceTracker->GetStatus(&metrics->Resource);

    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno RT_Cleanup()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errlm = RT_lock_mods();
    if (errlm != NO_ERROR)
    {
        return errlm;
    }

    // maybe some librarys will use the tracked
    // memory page or heap, so free memory after
    // free all library.
    errno err = NO_ERROR;
    typedef errno (*submodule_t)();
    submodule_t submodules[] = 
    {
        // first kill all threads
        runtime->ThreadTracker->KillAll,

        // high-level modules
        runtime->WinHTTP->Clean,

        // runtime submodules
        runtime->ResourceTracker->FreeAll,
        runtime->LibraryTracker->FreeAll,
        runtime->MemoryTracker->FreeAll,
    };
    errno enmod = NO_ERROR;
    for (int i = 0; i < arrlen(submodules); i++)
    {
        enmod = submodules[i]();
        if (enmod != NO_ERROR && err == NO_ERROR)
        {
            err = enmod;
        }
    }

    errno errum = RT_unlock_mods();
    if (errum != NO_ERROR)
    {
        return errum;
    }
    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return err;
}

__declspec(noinline)
errno RT_Exit()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }

    errno err = RT_lock_mods();
    if (err != NO_ERROR)
    {
        return err;
    }

    DWORD oldProtect;
    if (!adjustPageProtect(runtime, &oldProtect))
    {
        return ERR_RUNTIME_ADJUST_PROTECT;
    }

    // maybe some librarys will use the tracked
    // memory page or heap, so free memory after
    // free all library.
    typedef errno (*submodule_t)();
    submodule_t submodules[] = 
    {
        // first kill all threads
        runtime->ThreadTracker->Clean,

        // high-level modules
        runtime->WinHTTP->Uninstall,
        runtime->WinFile->Uninstall,
        runtime->WinBase->Uninstall,

        // runtime submodules
        runtime->InMemoryStorage->Clean,
        runtime->ArgumentStore->Clean,
        runtime->ResourceTracker->Clean,
        runtime->LibraryTracker->Clean,
        runtime->MemoryTracker->Clean,
    };
    errno enmod = NO_ERROR;
    for (int i = 0; i < arrlen(submodules); i++)
    {
        enmod = submodules[i]();
        if (enmod != NO_ERROR && err == NO_ERROR)
        {
            err = enmod;
        }
    }

    // must copy structure before clean runtime
    Runtime clone;
    mem_init(&clone, sizeof(Runtime));
    mem_copy(&clone, runtime, sizeof(Runtime));

    // clean runtime resource
    errno enclr = cleanRuntime(runtime);
    if (enclr != NO_ERROR && err == NO_ERROR)
    {
        err = enclr;
    }

    // store original pointer for recover instructions
    Runtime* stub = runtime;

    // must replace it until reach here
    runtime = &clone;

    // must calculate address before erase instructions
    void* init = GetFuncAddr(&InitRuntime);
    void* addr = runtime->Options.BootInstAddress;
    if (addr == NULL || (uintptr)addr > (uintptr)init)
    {
        addr = init;
    }

    // recover instructions for generate shellcode must
    // call it after call cleanRuntime, otherwise event
    // handler will get the incorrect runtime address
    if (runtime->Options.NotEraseInstruction)
    {
        if (!recoverRuntimePointer(stub) && err == NO_ERROR)
        {
            err = ERR_RUNTIME_EXIT_RECOVER_INST;
        }
    }

    // erase runtime instructions except this function
    if (!runtime->Options.NotEraseInstruction)
    {
        uintptr begin = (uintptr)(GetFuncAddr(&InitRuntime));
        uintptr end   = (uintptr)(GetFuncAddr(&RT_Exit));
        uintptr size  = end - begin;
        eraseMemory(begin, size);
        begin = (uintptr)(GetFuncAddr(&rt_epilogue));
        end   = (uintptr)(GetFuncAddr(&Argument_Stub));
        size  = end - begin;
        eraseMemory(begin, size);
    }

    // recover memory project
    // TODO move it to cleaner stub
    if (!runtime->Options.NotAdjustProtect)
    {
        uintptr begin = (uintptr)(addr);
        uintptr end   = (uintptr)(runtime->Epilogue);
        SIZE_T  size  = (SIZE_T)(end - begin);
        DWORD old;
        if (!runtime->VirtualProtect(addr, size, oldProtect, &old) && err == NO_ERROR)
        {
            err = ERR_RUNTIME_RECOVER_PROTECT;
        }
    }

    // clean stack that store cloned structure data 
    eraseMemory((uintptr)(runtime), sizeof(Runtime));
    return err;
}

// TODO replace to xorshift
__declspec(noinline)
static void eraseMemory(uintptr address, uintptr size)
{
    byte* addr = (byte*)address;
    for (uintptr i = 0; i < size; i++)
    {
        byte b = *addr;
        if (i > 0)
        {
            byte prev = *(byte*)(address + i - 1);
            b -= prev;
            b ^= prev;
            b += prev;
            b |= prev;
        }
        b += (byte)(address + i);
        b |= (byte)(address ^ 0xFF);
        *addr = b;
        addr++;
    }
}

// prevent it be linked to other functions.
#pragma optimize("", off)

#pragma warning(push)
#pragma warning(disable: 4189)
static void rt_epilogue()
{
    byte var = 1;
    return;
}
#pragma warning(pop)

#pragma optimize("", on)
