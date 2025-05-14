#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "sysmon.h"
#include "test.h"

static bool TestSysmon_GetStatus();
static bool TestSysmon_Pause();
static bool TestSysmon_Continue();

bool TestRuntime_Sysmon()
{
    test_t tests[] = {
        { TestSysmon_GetStatus },
        { TestSysmon_Pause     },
        { TestSysmon_Continue  },
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

static bool TestSysmon_GetStatus()
{
    SM_Status status;
    mem_init(&status, sizeof(status));

    if (!runtime->Sysmon.Status(&status))
    {
        printf_s("failed to get sysmon status\n");
        return false;
    }

    if (status.NumNormal < 1)
    {
        printf_s("invalid the number of normal\n");
        return false;
    }

    printf_s("test Sysmon_GetStatus passed\n");
    return true;
}

static bool TestSysmon_Pause()
{
    errno errno = runtime->Sysmon.Pause();
    if (errno != NO_ERROR)
    {
        printf_s("failed to pause sysmon: 0x%X\n", errno);
        return false;
    }

    printf_s("test Sysmon_Pause passed\n");
    return true;
}

static bool TestSysmon_Continue()
{
    errno errno = runtime->Sysmon.Continue();
    if (errno != NO_ERROR)
    {
        printf_s("failed to continue sysmon: 0x%X\n", errno);
        return false;
    }

    printf_s("test Sysmon_Continue passed\n");
    return true;
}
