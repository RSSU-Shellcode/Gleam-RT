#ifndef WATCHDOG_H
#define WATCHDOG_H

#include "c_types.h"
#include "errno.h"
#include "context.h"

#define WATCHDOG_KICK_TIMEOUT 5000 // 5s

typedef struct {
    int64 NumKick;
    int64 NumNormal;
    int64 NumReset;
} WD_Status;

typedef void (*WDHandler_t)();

typedef errno (*WDKick_t)();
typedef errno (*WDEnable_t)();
typedef errno (*WDDisable_t)();
typedef bool  (*WDIsEnabled_t)();
typedef void  (*WDSetHandler_t)(WDHandler_t handler);
typedef bool  (*WDGetStatus_t)(WD_Status* status);

typedef bool  (*WDLock_t)();
typedef bool  (*WDUnlock_t)();
typedef errno (*WDPause_t)();
typedef errno (*WDContinue_t)();
typedef errno (*WDStop_t)();

typedef struct {
    WDKick_t       Kick;
    WDEnable_t     Enable;
    WDDisable_t    Disable;
    WDIsEnabled_t  IsEnabled;
    WDSetHandler_t SetHandler;
    WDGetStatus_t  GetStatus;

    WDLock_t     Lock;
    WDUnlock_t   Unlock;
    WDPause_t    Pause;
    WDContinue_t Continue;
    WDStop_t     Stop;
} Watchdog_M;

Watchdog_M* InitWatchdog(Context* context);

#endif // WATCHDOG_H
