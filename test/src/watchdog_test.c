#include <stdio.h>
#include "c_types.h"
#include "test.h"

static bool TestWatchdog_Pause();
static bool TestWatchdog_Continue();

bool TestRuntime_Watchdog()
{
    test_t tests[] = {
        { TestWatchdog_Pause },
        { TestWatchdog_Continue },
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

static bool TestWatchdog_Pause()
{
    printf_s("test Watchdog_Pause passed\n");
    return true;
}

static bool TestWatchdog_Continue()
{
    printf_s("test Watchdog_Continue passed\n");
    return true;
}
