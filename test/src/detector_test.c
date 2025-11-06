#include <stdio.h>
#include "c_types.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

static bool TestDetector_Debugger();
static bool TestDetector_MemoryScanner();
static bool TestDetector_Sandbox();

bool TestRuntime_Detector()
{
    test_t tests[] = {
        { TestDetector_Debugger      },
        { TestDetector_MemoryScanner },
        { TestDetector_Sandbox       },
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
    return true;
}

static bool TestDetector_MemoryScanner()
{
    return true;
}

static bool TestDetector_Sandbox()
{
    return true;
}
