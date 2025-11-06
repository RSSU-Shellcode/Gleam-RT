#ifndef DETECTOR_H
#define DETECTOR_H

#include "c_types.h"
#include "errno.h"
#include "context.h"

typedef struct {
    bool IsEnabled;
    bool HasDebugger;
    bool HasMemoryScanner;
    bool InSandbox;
    bool InVirtualMachine;
    bool InEmulator;
    bool IsAccelerated;
    int8 SafeRank;
} DT_Status;

typedef bool (*DetDetect_t)();
typedef bool (*DetGetStatus_t)(DT_Status* status);

typedef errno (*DetStop_t)();

typedef struct {
    DetDetect_t    Detect;
    DetGetStatus_t GetStatus;

    DetStop_t Stop;
} Detector_M;

Detector_M* InitDetector(Context* context);

#endif // DETECTOR_H
