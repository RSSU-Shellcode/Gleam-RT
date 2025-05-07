#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "errno.h"
#include "context.h"
#include "watchdog.h"
#include "debug.h"

typedef struct {
    // store options
    bool NotEraseInstruction;

    SuspendThread_t          SuspendThread;
    ResumeThread_t           ResumeThread;
    CreateWaitableTimerA_t   CreateWaitableTimerA;
    SetWaitableTimer_t       SetWaitableTimer;
    SetEvent_t               SetEvent;
    ReleaseMutex_t           ReleaseMutex;
    WaitForSingleObject_t    WaitForSingleObject;
    WaitForMultipleObjects_t WaitForMultipleObjects;
    CloseHandle_t            CloseHandle;

    // about watcher
    HANDLE hEvent;
    HANDLE hThread;

    // global mutex
    HANDLE hMutex;

    // watchdog status
    WD_Status status;
    HANDLE    statusMu;
} Watchdog;

// methods for user
void WD_Kick();
void WD_Enable();
void WD_Disable();
void WD_SetHandler(WDHandler_t handler);
bool WD_GetStatus(WD_Status* status);

// methods for runtime
bool  WD_Lock();
bool  WD_Unlock();
errno WD_Pause();
errno WD_Continue();
errno WD_Stop();

// hard encoded address in getWatchdogPointer for replacement
#ifdef _WIN64
    #define WATCHDOG_POINTER 0x7FABCDEF111111F2
#elif _WIN32
    #define WATCHDOG_POINTER 0x7FABCDF2
#endif
static Watchdog* getWatchdogPointer();

static bool initWatchdogAPI(Watchdog* watchdog, Context* context);
static bool updateWatchdogPointer(Watchdog* watchdog);
static bool recoverWatchdogPointer(Watchdog* watchdog);
static bool initWatchdogEnvironment(Watchdog* watchdog, Context* context);
static void eraseWatchdogMethods(Context* context);
static void cleanWatchdog(Watchdog* watchdog);

static void wd_watcher();
static uint wd_sleep(uint32 milliseconds);

static bool wd_lock_status();
static bool wd_unlock_status();
static void wd_add_kick();
static void wd_add_reset();

Watchdog_M* InitWatchdog(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr watchdogAddr = address + 26000 + RandUintN(address, 128);
    uintptr methodAddr   = address + 27000 + RandUintN(address, 128);
    // initialize watchdog
    Watchdog* watchdog = (Watchdog*)watchdogAddr;
    mem_init(watchdog, sizeof(Watchdog));
    // store options
    watchdog->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initWatchdogAPI(watchdog, context))
        {
            errno = ERR_WATCHDOG_INIT_API;
            break;
        }
        if (!updateWatchdogPointer(watchdog))
        {
            errno = ERR_WATCHDOG_UPDATE_PTR;
            break;
        }
        if (!initWatchdogEnvironment(watchdog, context))
        {
            errno = ERR_WATCHDOG_INIT_ENV;
            break;
        }
        break;
    }
    eraseWatchdogMethods(context);
    if (errno != NO_ERROR)
    {
        cleanWatchdog(watchdog);
        SetLastErrno(errno);
        return NULL;
    }

}
