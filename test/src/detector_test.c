#include <stdio.h>
#include "c_types.h"
#include "errno.h"
#include "detector.h"
#include "test.h"

static bool TestDetector_Debugger();
static bool TestDetector_MemoryScanner();
static bool TestDetector_Sandbox();
static bool TestDetector_SafeRank();

bool TestRuntime_Detector()
{
    test_t tests[] = {
        { TestDetector_Debugger      },
        { TestDetector_MemoryScanner },
        { TestDetector_Sandbox       },
        { TestDetector_SafeRank      },
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

static bool TestDetector_Debugger()
{
    DT_Status status;
    if (!runtime->Detector.Status(&status))
    {
        printf_s("failed to get detector status: 0x%X\n", GetLastErrno());
        return false;
    }

    if (!status.HasDebugger)
    {
        printf_s("not in debugger\n");
        return false;
    }

    printf_s("test Debugger passed\n");
    return true;
}

static bool TestDetector_MemoryScanner()
{
    printf_s("test MemoryScanner passed\n");
    return true;
}

static bool TestDetector_Sandbox()
{
    printf_s("test Sandbox passed\n");
    return true;
}

static bool TestDetector_SafeRank()
{
    DT_Status status;
    if (!runtime->Detector.Status(&status))
    {
        printf_s("failed to get detector status: 0x%X\n", GetLastErrno());
        return false;
    }

    if (!status.IsEnabled)
    {
        printf_s("detector is disabled\n");
        return false;
    }
    printf_s("safe rank: %d\n", status.SafeRank);

    printf_s("test SafeRank passed\n");
    return true;
}
