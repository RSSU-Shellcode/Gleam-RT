#ifndef SYSMON_H
#define SYSMON_H

#include "c_types.h"
#include "errno.h"
#include "context.h"

typedef struct {
    BOOL  IsEnabled;
    int32 Reserved;
    int64 NumNormal;
    int64 NumRecover;
    int64 NumPanic;
} SM_Status;

typedef bool (*SMGetStatus_t)(SM_Status* status);

typedef bool  (*SMLock_t)();
typedef bool  (*SMUnlock_t)();
typedef errno (*SMPause_t)();
typedef errno (*SMContinue_t)();
typedef errno (*SMStop_t)();

typedef struct {
    SMGetStatus_t GetStatus;

    SMLock_t     Lock;
    SMUnlock_t   Unlock;
    SMPause_t    Pause;
    SMContinue_t Continue;
    SMStop_t     Stop;
} Sysmon_M;

Sysmon_M* InitSysmon(Context* context);

#endif // SYSMON_H
