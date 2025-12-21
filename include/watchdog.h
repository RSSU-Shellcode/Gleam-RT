#ifndef WATCHDOG_H
#define WATCHDOG_H

#include "c_types.h"
#include "win_types.h"
#include "errno.h"
#include "context.h"

#define WATCHDOG_KICK_TIMEOUT 5000 // 5s

typedef struct {
    BOOL  IsEnabled;
    int32 Reserved;
    int64 NumKick;
    int64 NumNormal;
    int64 NumReset;
} WD_Status;

typedef void (*WDHandler_t)();

typedef void  (*WDSetHandler_t)(WDHandler_t handler);
typedef void  (*WDSetTimeout_t)(uint32 milliseconds);
typedef errno (*WDKick_t)();
typedef errno (*WDEnable_t)();
typedef errno (*WDDisable_t)();
typedef BOOL  (*WDIsEnabled_t)();
typedef BOOL  (*WDGetStatus_t)(WD_Status* status);

typedef bool  (*WDLock_t)();
typedef bool  (*WDUnlock_t)();
typedef errno (*WDPause_t)();
typedef errno (*WDContinue_t)();
typedef errno (*WDStop_t)();

typedef struct {
    // for user
    WDSetHandler_t SetHandler;
    WDSetTimeout_t SetTimeout;
    WDKick_t       Kick;
    WDEnable_t     Enable;
    WDDisable_t    Disable;
    WDIsEnabled_t  IsEnabled;
    WDGetStatus_t  GetStatus;

    // for runtime internal usage
    WDLock_t     Lock;
    WDUnlock_t   Unlock;
    WDPause_t    Pause;
    WDContinue_t Continue;
    WDStop_t     Stop;

    // data for sysmon
    HANDLE hMutex;
} Watchdog_M;

Watchdog_M* InitWatchdog(Context* context);

#endif // WATCHDOG_H
