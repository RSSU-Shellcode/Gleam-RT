#include <stdio.h>
#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "watchdog.h"
#include "test.h"

static HANDLE hEvent = NULL;
static void reset_handler();

static bool TestWatchdog_Watcher();
static bool TestWatchdog_Enable();
static bool TestWatchdog_Disable();
static bool TestWatchdog_GetStatus();
static bool TestWatchdog_Pause();
static bool TestWatchdog_Continue();
static bool TestWatchdog_Stop();

bool TestRuntime_Watchdog()
{
    test_t tests[] = {
        { TestWatchdog_Watcher   },
        { TestWatchdog_Enable    },
        { TestWatchdog_Disable   },
        { TestWatchdog_GetStatus },
        { TestWatchdog_Pause     },
        { TestWatchdog_Continue  },
        { TestWatchdog_Stop      },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        printf_s("--------------------------------\n");
        if (!tests[i]())
        {
            return false;
        }
        printf_s("--------------------------------\n\n");
    }
    return true;
}

static bool TestWatchdog_Watcher()
{
    CreateEventA_t        CreateEventA        = FindAPI_A("kernel32.dll", "CreateEventA");
    WaitForSingleObject_t WaitForSingleObject = FindAPI_A("kernel32.dll", "WaitForSingleObject");

    hEvent = CreateEventA(NULL, true, false, NULL);
    if (hEvent == NULL)
    {
        printf_s("failed to create event: 0x%X\n", GetLastErrno());
        return false;
    }
    runtime->Watchdog.SetHandler(&reset_handler);

    // set kick timeout for test faster
    runtime->Watchdog.SetTimeout(1000);

    errno errno = runtime->Watchdog.Enable();
    if (errno != NO_ERROR)
    {
        printf_s("failed to enable watchdog: 0x%X\n", errno);
        return false;
    }

    for (int i = 0; i < 3; i++)
    {
        printf_s("kick watchdog\n");
        runtime->Watchdog.Kick();
        runtime->Thread.Sleep(1000);
    }

    if (WaitForSingleObject(hEvent, INFINITE) != WAIT_OBJECT_0)
    {
        printf_s("failed to wait watchdog reset: 0x%X\n", GetLastErrno());
        return false;
    }

    printf_s("test Watchdog_Watcher passed\n");
    return true;
}

static void reset_handler()
{
    printf_s("----watchdog reset----\n");

    SetEvent_t SetEvent = FindAPI_A("kernel32.dll", "SetEvent");
    if (SetEvent(hEvent))
    {
        return;
    }

    printf_s("failed to set event\n");
    panic(PANIC_UNREACHABLE_CODE);
}

static bool TestWatchdog_Enable()
{
    errno errno = runtime->Watchdog.Enable();
    if (errno != NO_ERROR)
    {
        printf_s("failed to enable watchdog: 0x%X\n", errno);
        return false;
    }

    printf_s("test TestWatchdog_Enable passed\n");
    return true;
}

static bool TestWatchdog_Disable()
{
    errno errno = runtime->Watchdog.Disable();
    if (errno != NO_ERROR)
    {
        printf_s("failed to disable watchdog: 0x%X\n", errno);
        return false;
    }

    printf_s("test TestWatchdog_Disable passed\n");
    return true;
}

static bool TestWatchdog_GetStatus()
{
    WD_Status status;
    mem_init(&status, sizeof(status));

    if (!runtime->Watchdog.Status(&status))
    {
        printf_s("failed to get watchdog status\n");
        return false;
    }

    if (status.NumKick != 3)
    {
        printf_s("invalid the number of kick\n");
        return false;
    }
    if (status.NumNormal < 1)
    {
        printf_s("invalid the number of normal\n");
        return false;
    }
    if (status.NumReset != 1)
    {
        printf_s("invalid the number of reset\n");
        return false;
    }

    printf_s("test TestWatchdog_GetStatus passed\n");
    return true;
}

static bool TestWatchdog_Pause()
{
    errno errno = runtime->Watchdog._Pause();
    if (errno != NO_ERROR)
    {
        printf_s("failed to pause watchdog: 0x%X\n", errno);
        return false;
    }

    printf_s("test Watchdog_Pause passed\n");
    return true;
}

static bool TestWatchdog_Continue()
{
    errno errno = runtime->Watchdog._Continue();
    if (errno != NO_ERROR)
    {
        printf_s("failed to continue watchdog: 0x%X\n", errno);
        return false;
    }

    printf_s("test Watchdog_Continue passed\n");
    return true;
}

static bool TestWatchdog_Stop()
{
    errno errno = runtime->Watchdog.Enable();
    if (errno != NO_ERROR)
    {
        printf_s("failed to enable watchdog: 0x%X\n", errno);
        return false;
    }

    // not disable watchdog before stop runtime

    printf_s("test Watchdog_Stop passed\n");
    return true;
}
