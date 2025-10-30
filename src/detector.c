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
    bool NotEraseInstruction;

    // API addresses
    GetTickCount_t        GetTickCount;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;

    // protect data
    HANDLE hMutex;
} Detector;

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
    detector->NotEraseInstruction = context->NotEraseInstruction;

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
