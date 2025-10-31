#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "random.h"
#include "win_api.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "detector.h"
#include "debug.h"

typedef struct {
    // store options
    bool DisableDetector;
    bool NotEraseInstruction;

    // API addresses
    GetTickCount_t        GetTickCount;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;

    // protect data
    HANDLE hMutex;

    uint16 HasDebugger;
    uint16 HasMemoryScanner;
    uint16 InSandbox;
    uint16 InVirtualMachine;
    uint16 InEmulator;
    uint16 IsAccelerated;
} Detector;

// methods for user
errno DT_Detect();
errno DT_GetStatus(DT_Status* status);

// methods for runtime
errno DT_Stop();

// hard encoded address in getDetectorPointer for replacement
#ifdef _WIN64
    #define DETECTOR_POINTER 0x7FABCDDD111111D1
#elif _WIN32
    #define DETECTOR_POINTER 0x7FABCDD1
#endif
static Detector* getDetectorPointer();

static bool initDetectorAPI(Detector* detector, Context* context);
static bool updateDetectorPointer(Detector* detector);
static bool recoverDetectorPointer(Detector* detector);
static bool initDetectorEnvironment(Detector* detector, Context* context);
static void eraseDetectorMethods(Context* context);
static void cleanDetector(Detector* detector);

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
errno DT_Detect()
{
    Detector* detector = getDetectorPointer();

    if (detector->DisableDetector)
    {
        return NO_ERROR;
    }

    return NO_ERROR;
}

__declspec(noinline)
errno DT_GetStatus(DT_Status* status)
{
    Detector* detector = getDetectorPointer();

    if (detector->DisableDetector)
    {
        status->IsEnabled = false;
        return NO_ERROR;
    }

    return NO_ERROR;
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
