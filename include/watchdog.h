#ifndef WATCHDOG_H
#define WATCHDOG_H

#include "c_types.h"
#include "errno.h"
#include "context.h"

typedef struct {
    int64 NumKick;
    int64 NumReset;
} WD_Status;

typedef void (*WDHandler_t)();

typedef void (*WDKick_t)();
typedef void (*WDEnable_t)();
typedef void (*WDDisable_t)();
typedef void (*WDSetHandler_t)(WDHandler_t handler);
typedef bool (*WDGetStatus_t)(WD_Status* status);

typedef bool  (*WDLock_t)();
typedef bool  (*WDUnlock_t)();
typedef errno (*WDPause_t)();
typedef errno (*WDContinue_t)();
typedef errno (*WDStop_t)();

typedef struct {
    WDKick_t       Kick;
    WDEnable_t     Enable;
    WDDisable_t    Disable;
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
