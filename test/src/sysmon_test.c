#include <stdio.h>
#include "c_types.h"
#include "test.h"

static bool TestSysmon_Pause();
static bool TestSysmon_Continue();

bool TestRuntime_Sysmon()
{
    test_t tests[] = {
        { TestSysmon_Pause    },
        { TestSysmon_Continue },
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

static bool TestSysmon_Pause()
{
    printf_s("test Sysmon_Pause passed\n");
    return true;
}

static bool TestSysmon_Continue()
{
    printf_s("test Sysmon_Continue passed\n");
    return true;
}
