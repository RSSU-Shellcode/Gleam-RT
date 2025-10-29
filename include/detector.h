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
} DET_Status;

typedef errno (*DETDetect_t)();
typedef errno (*DETStatus_t)(DET_Status* status);

typedef errno (*DETStop_t)();

typedef struct {
    DETDetect_t Detect;
    DETStatus_t Status;

    DETStop_t Stop;
} Detector_M;

Detector_M* InitDetector(Context* context);

#endif // DETECTOR_H
