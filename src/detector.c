#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_psapi.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "random.h"
#include "crypto.h"
#include "win_api.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "detector.h"
#include "debug.h"

#define THRESHOLD_HAS_DEBUGGER       50
#define THRESHOLD_HAS_MEMORY_SCANNER 10
#define THRESHOLD_IN_SANDBOX         80
#define THRESHOLD_IN_VIRTUAL_MACHINE 70
#define THRESHOLD_IN_EMULATOR        70
#define THRESHOLD_IS_ACCELERATED     80

// MUST be a multiple of 100.
#define MAX_SAFE_RANK 200

typedef struct {
    // store options
    bool DisableDetector;
    bool NotEraseInstruction;

    // process environment
    void* PEB;
    void* IMOML;

    // API addresses
    GetTickCount_t        GetTickCount;
    FreeLibrary_t         FreeLibrary;
    VirtualFree_t         VirtualFree;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;

    // lazy API addresses
    QueryWorkingSetEx_t QueryWorkingSetEx;

    // for detector memory scanner
    LPVOID  trapMemPage;
    HMODULE hPsapi;

    // protect data
    HANDLE hMutex;

    // most test items only run once,
    // but some items need detect loop.
    bool isDetected;

    bool PrevDebugged;
    bool StepOnMemTrap;

    uint16 HasDebugger;
    uint16 HasMemoryScanner;
    uint16 InSandbox;
    uint16 InVirtualMachine;
    uint16 InEmulator;
    uint16 IsAccelerated;
} Detector;

// methods for user
BOOL DT_Detect();
BOOL DT_GetStatus(DT_Status* status);

// methods for runtime
errno DT_Stop();

// hard encoded address in getDetectorPointer for replacement
#ifdef _WIN64
    #define DETECTOR_POINTER 0x7FABCDDD111111D1
#elif _WIN32
    #define DETECTOR_POINTER 0x7FABCDD1
#endif
static Detector* getDetectorPointer();

static bool dt_lock();
static bool dt_unlock();

static bool initDetectorAPI(Detector* detector, Context* context);
static bool updateDetectorPointer(Detector* detector);
static bool recoverDetectorPointer(Detector* detector);
static bool initDetectorEnvironment(Detector* detector, Context* context);
static void eraseDetectorMethods(Context* context);
static void cleanDetector(Detector* detector);

static bool detectOnceItem();
static bool detectLoopItem();

static bool detectDebugger();
static bool detectMemoryScanner();
static bool detectSandbox();
static bool detectVirtualMachine();
static bool detectEmulator();
static bool detectAccelerator();

Detector_M* InitDetector(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr detectorAddr = addr + LAYOUT_DT_STRUCT + RandUintN(addr, 128);
    uintptr methodAddr   = addr + LAYOUT_DT_MODULE + RandUintN(addr, 128);
    // allocate detector memory
    Detector* detector = (Detector*)detectorAddr;
    mem_init(detector, sizeof(Detector));
    // store options
    detector->DisableDetector     = context->DisableDetector;
    detector->NotEraseInstruction = context->NotEraseInstruction;
    // store process environment
    detector->PEB   = context->PEB;
    detector->IMOML = context->IMOML;
    // initialize detector
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initDetectorAPI(detector, context))
        {
            errno = ERR_DETECTOR_INIT_API;
            break;
        }
        if (!updateDetectorPointer(detector))
        {
            errno = ERR_DETECTOR_UPDATE_PTR;
            break;
        }
        if (!initDetectorEnvironment(detector, context))
        {
            errno = ERR_DETECTOR_INIT_ENV;
            break;
        }
        break;
    }
    eraseDetectorMethods(context);
    if (errno != NO_ERROR)
    {
        cleanDetector(detector);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for detector
    Detector_M* method = (Detector_M*)methodAddr;
    // methods for user
    method->Detect    = GetFuncAddr(&DT_Detect);
    method->GetStatus = GetFuncAddr(&DT_GetStatus);
    // methods for runtime
    method->Stop = GetFuncAddr(&DT_Stop);
    return method;
}

__declspec(noinline)
static bool initDetectorAPI(Detector* detector, Context* context)
{
    detector->GetTickCount        = context->GetTickCount;
    detector->FreeLibrary         = context->FreeLibrary;
    detector->VirtualFree         = context->VirtualFree;
    detector->ReleaseMutex        = context->ReleaseMutex;
    detector->WaitForSingleObject = context->WaitForSingleObject;
    detector->CloseHandle         = context->CloseHandle;
    return true;
}

// CANNOT merge updateDetectorPointer and recoverDetectorPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateDetectorPointer(Detector* detector)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getDetectorPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != DETECTOR_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)detector;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool recoverDetectorPointer(Detector* detector)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getDetectorPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)detector)
        {
            target++;
            continue;
        }
        *pointer = DETECTOR_POINTER;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool initDetectorEnvironment(Detector* detector, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_DETECTOR_MUTEX);
    if (hMutex == NULL)
    {
        return false;
    }
    detector->hMutex = hMutex;
    // allocate trap memory page
    SIZE_T size = (3 + RandUintN(0, 16)) * 1024;
    LPVOID page = context->VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL)
    {
        return false;
    }
    detector->trapMemPage = page;
    // not try to find QueryWorkingSetEx if Detector is disabled
    if (context->DisableDetector)
    {
        return true;
    }
    // try to find QueryWorkingSetEx in kernel32.dll
#ifdef _WIN64
    uint mHash = 0xB85339B93FAFCA27;
    uint pHash = 0x712F73BAA281B7A7;
    uint hKey  = 0xC3107C1D3C0E7E7A;
#elif _WIN32
    uint mHash = 0x7A2E2DB8;
    uint pHash = 0x79D1EEA9;
    uint hKey  = 0x0F43DE10;
#endif
    QueryWorkingSetEx_t QueryWorkingSetEx = context->FindAPI(mHash, pHash, hKey);
    if (QueryWorkingSetEx != NULL)
    {
        detector->QueryWorkingSetEx = QueryWorkingSetEx;
        return true;
    }
    // make sure psapi.dll is loaded for old Windows
    byte dllName[] = {
        'p'^0x3A, 's'^0x49, 'a'^0xC7, 'p'^0x19,
        'i'^0x3A, '.'^0x49, 'd'^0xC7, 'l'^0x19,
        'l'^0x3A, 000^0x49, 000^0xC7, 000^0x19,
    };
    byte key[] = { 0x3A, 0x49, 0xC7, 0x19 };
    XORBuf(dllName, sizeof(dllName), key, sizeof(key));
    HMODULE hPsapi = context->LoadLibraryA(dllName);
    if (hPsapi == NULL)
    {
        return false;
    }
    // psapi.QueryWorkingSetEx is not exist on old Windows
#ifdef _WIN64
    mHash = 0xB8B3D1CE23700017;
    pHash = 0x75F48436269D0717;
    hKey  = 0x0DB79DD5BA6DDEBC;
#elif _WIN32
    mHash = 0x3859A4AC;
    pHash = 0x06333B8D;
    hKey  = 0xE9D6A09C;
#endif
    QueryWorkingSetEx = context->FindAPI(mHash, pHash, hKey);
    if (QueryWorkingSetEx == NULL)
    {
        context->FreeLibrary(hPsapi);
        return true;
    }
    detector->QueryWorkingSetEx = QueryWorkingSetEx;
    detector->hPsapi = hPsapi;
    return true;
}

__declspec(noinline)
static void eraseDetectorMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initDetectorAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseDetectorMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

__declspec(noinline)
static void cleanDetector(Detector* detector)
{
    if (detector->CloseHandle != NULL && detector->hMutex != NULL)
    {
        detector->CloseHandle(detector->hMutex);
    }
    if (detector->VirtualFree != NULL && detector->trapMemPage != NULL)
    {
        detector->VirtualFree(detector->trapMemPage, 0, MEM_RELEASE);
    }
}

// updateDetectorPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateDetectorPointer will fail.
#pragma optimize("", off)
static Detector* getDetectorPointer()
{
    uintptr pointer = DETECTOR_POINTER;
    return (Detector*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool dt_lock()
{
    Detector* detector = getDetectorPointer();

    DWORD event = detector->WaitForSingleObject(detector->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool dt_unlock()
{
    Detector* detector = getDetectorPointer();

    return detector->ReleaseMutex(detector->hMutex);
}

__declspec(noinline)
BOOL DT_Detect()
{
    Detector* detector = getDetectorPointer();

    if (detector->DisableDetector)
    {
        return true;
    }

    if (!dt_lock())
    {
        return false;
    }

    BOOL success = true;
    for (;;)
    {
        // items that need detect loop
        if (detector->isDetected)
        {
            success = detectLoopItem();
            break;
        }
        // common detect items
        success = detectOnceItem();
        detector->isDetected = true;
        break;
    }

    if (!dt_unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
static bool detectOnceItem()
{
    bool success = true;
    typedef bool (*detection_t)();
    detection_t list[] = {
        GetFuncAddr(&detectDebugger),
        GetFuncAddr(&detectMemoryScanner),
        GetFuncAddr(&detectSandbox),
        GetFuncAddr(&detectVirtualMachine),
        GetFuncAddr(&detectEmulator),
        GetFuncAddr(&detectAccelerator),
    };
    int seq[arrlen(list)];
    RandSequence(seq, arrlen(seq));
    for (int i = 0; i < arrlen(seq); i++)
    {
        int idx = seq[i];
        if (!list[idx]())
        {
            success = false;
            break;
        }
    }
    return success;
}

__declspec(noinline)
static bool detectLoopItem()
{
    bool success = true;
    typedef bool (*detection_t)();
    detection_t list[] = {
        GetFuncAddr(&detectDebugger),
        GetFuncAddr(&detectMemoryScanner),
    };
    int seq[arrlen(list)];
    RandSequence(seq, arrlen(seq));
    for (int i = 0; i < arrlen(seq); i++)
    {
        int idx = seq[i];
        if (!list[idx]())
        {
            success = false;
            break;
        }
    }
    return success;
}

__declspec(noinline)
static bool detectDebugger()
{
    Detector* detector = getDetectorPointer();

    if (detector->PrevDebugged)
    {
        return true;
    }

    uintptr peb = (uintptr)(detector->PEB);
    bool BeingDebugged = *(bool*)(peb + 2);
    if (BeingDebugged)
    {
        detector->HasDebugger += 100;
        detector->PrevDebugged = true;
        return true;
    }
    return true;
}

__declspec(noinline)
static bool detectMemoryScanner()
{
    Detector* detector = getDetectorPointer();

    // check API is existed
    if (detector->QueryWorkingSetEx == NULL)
    {
        return true;
    }

    if (detector->StepOnMemTrap)
    {
        return true;
    }

    PSAPI_WORKING_SET_EX_INFORMATION info = {
        .VirtualAddress = detector->trapMemPage,
    };
    DWORD cb = sizeof(PSAPI_WORKING_SET_EX_INFORMATION);
    if (!detector->QueryWorkingSetEx(CURRENT_PROCESS, &info, cb))
    {
        return false;
    }
    if (info.VirtualAttributes.Valid)
    {
        detector->HasMemoryScanner += 100;
        detector->StepOnMemTrap = true;
    }
    return true;
}

__declspec(noinline)
static bool detectSandbox()
{
    Detector* detector = getDetectorPointer();

    // detect "SbieDLL.dll" is loaded
    uint16 dllName[] = {
        L'S'^0x1F0B, L'b'^0xA95C, L'i'^0x21C5, L'e'^0xC6F7,
        L'D'^0x1F0B, L'L'^0xA95C, L'L'^0x21C5, L'.'^0xC6F7,
        L'd'^0x1F0B, L'l'^0xA95C, L'l'^0x21C5, 0000^0xC6F7,
    };
    uint16 key[] = { 0x1F0B, 0xA95C, 0x21C5, 0xC6F7 };
    XORBuf(dllName, sizeof(dllName), key, sizeof(key));
    if (GetModuleHandle(detector->IMOML, dllName) != NULL)
    {
        detector->InSandbox += 100;
        return true;
    }
    return true;
}

__declspec(noinline)
static bool detectVirtualMachine()
{
    Detector* detector = getDetectorPointer();

    return true;
}

__declspec(noinline)
static bool detectEmulator()
{
    Detector* detector = getDetectorPointer();

    return true;
}

__declspec(noinline)
static bool detectAccelerator()
{
    Detector* detector = getDetectorPointer();

    return true;
}

__declspec(noinline)
BOOL DT_GetStatus(DT_Status* status)
{
    Detector* detector = getDetectorPointer();

    if (detector->DisableDetector)
    {
        status->IsEnabled = false;
        return true;
    }
    status->IsEnabled = true;

    if (!dt_lock())
    {
        return false;
    }

    int32 total = 0;
    typedef struct {
        uint16 src; BOOL* dst; uint16 th;
    } item;
    item items[] = {
        { detector->HasDebugger,      &status->HasDebugger,      THRESHOLD_HAS_DEBUGGER       },
        { detector->HasMemoryScanner, &status->HasMemoryScanner, THRESHOLD_HAS_MEMORY_SCANNER },
        { detector->InSandbox,        &status->InSandbox,        THRESHOLD_IN_SANDBOX         },
        { detector->InVirtualMachine, &status->InVirtualMachine, THRESHOLD_IN_VIRTUAL_MACHINE },
        { detector->InEmulator,       &status->InEmulator,       THRESHOLD_IN_EMULATOR        },
        { detector->IsAccelerated,    &status->IsAccelerated,    THRESHOLD_IS_ACCELERATED     },
    };
    for (int i = 0; i < arrlen(items); i++)
    {
        item item = items[i];
        if (item.src >= item.th)
        {
            total += item.src;
            *item.dst = true;
        } else {
            *item.dst = false;
        }
    }

    int32 rank;
    if (total < MAX_SAFE_RANK)
    {
        rank = ((MAX_SAFE_RANK - total) / (MAX_SAFE_RANK / 100));
    } else {
        rank = 0;
    }
    status->SafeRank = rank;

    if (!dt_unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
errno DT_Stop()
{
    Detector* detector = getDetectorPointer();

    errno errno = NO_ERROR;

    // close mutex
    if (!detector->CloseHandle(detector->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_DETECTOR_CLOSE_MUTEX;
    }

    // free trap memory page
    if (!detector->VirtualFree(detector->trapMemPage, 0, MEM_RELEASE) && errno == NO_ERROR)
    {
        errno = ERR_DETECTOR_FREE_TRAP_MEM;
    }

    // free psapi.dll handle
    if (detector->hPsapi != NULL)
    {
        if (!detector->FreeLibrary(detector->hPsapi) && errno == NO_ERROR)
        {
            errno = ERR_DETECTOR_FREE_PSAPI;
        }
    }

    // recover instructions
    if (detector->NotEraseInstruction)
    {
        if (!recoverDetectorPointer(detector) && errno == NO_ERROR)
        {
            errno = ERR_DETECTOR_RECOVER_INST;
        }
    }
    return errno;
}
