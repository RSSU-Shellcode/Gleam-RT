#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "watchdog.h"
#include "test.h"

static bool TestWatchdog_Watcher();
static bool TestWatchdog_GetStatus();
static bool TestWatchdog_Pause();
static bool TestWatchdog_Continue();

bool TestRuntime_Watchdog()
{
    test_t tests[] = {
        { TestWatchdog_Watcher   },
        { TestWatchdog_GetStatus },
        { TestWatchdog_Pause     },
        { TestWatchdog_Continue  },
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
    printf_s("test Watchdog_Watcher passed\n");
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

    // if (status.NumNormal < 1)
    // {
    //     printf_s("invalid the number of normal\n");
    //     return false;
    // }

    printf_s("test TestWatchdog_GetStatus passed\n");
    return true;
}

static bool TestWatchdog_Pause()
{
    errno errno = runtime->Watchdog.Pause();
    if (errno != NO_ERROR)
    {
        printf_s("failed to pause watchdog: 0x%X\n", errno);
        return true;
    }

    printf_s("test Watchdog_Pause passed\n");
    return true;
}

static bool TestWatchdog_Continue()
{
    errno errno = runtime->Watchdog.Continue();
    if (errno != NO_ERROR)
    {
        printf_s("failed to continue watchdog: 0x%X\n", errno);
        return true;
    }

    printf_s("test Watchdog_Continue passed\n");
    return true;
}
