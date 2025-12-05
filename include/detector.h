#ifndef DETECTOR_H
#define DETECTOR_H

#include "c_types.h"
#include "errno.h"
#include "context.h"

typedef struct {
    BOOL  IsEnabled;
    BOOL  HasDebugger;
    BOOL  HasMemoryScanner;
    BOOL  InSandbox;
    BOOL  InVirtualMachine;
    BOOL  InEmulator;
    BOOL  IsAccelerated;
    int32 SafeRank;
} DT_Status;

typedef BOOL (*DetDetect_t)();
typedef BOOL (*DetGetStatus_t)(DT_Status* status);

typedef bool  (*DetLock_t)();
typedef bool  (*DetUnlock_t)();
typedef errno (*DetStop_t)();

typedef struct {
    // for user
    DetDetect_t    Detect;
    DetGetStatus_t GetStatus;

    // for runtime internal usage
    DetLock_t   Lock;
    DetUnlock_t Unlock;
    DetStop_t   Stop;

    // data for sysmon
    HANDLE hMutex;
} Detector_M;

Detector_M* InitDetector(Context* context);

#endif // DETECTOR_H
