#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
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
    #define DETECTOR_POINTER 0x7FABCDEF111111D1
#elif _WIN32
    #define DETECTOR_POINTER 0x7FABCDD1
#endif
static Detector* getDetectorPointer();

Detector_M* InitDetector(Context* context)
{

}
