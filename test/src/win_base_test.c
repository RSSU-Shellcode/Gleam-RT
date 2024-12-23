#include <stdio.h>
#include "c_types.h"
#include "win_types.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

static bool TestWinBase_ANSIToUTF16();
static bool TestWinBase_UTF16ToANSI();

bool TestRuntime_WinBase()
{
    test_t tests[] = 
    {
        { TestWinBase_ANSIToUTF16 },
        { TestWinBase_UTF16ToANSI },
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

static bool TestWinBase_ANSIToUTF16()
{
    ANSI  s0 = "ansi";
    UTF16 s1 = L"ansi";

    UTF16 s = runtime->WinBase.ANSIToUTF16(s0);
    if (s == NULL)
    {
        printf_s("failed to convert ANSI to UTF16: 0x%X\n", GetLastErrno());
        return false;
    }
    if (strcmp_w(s1, s) != 0)
    {
        printf_s("unexpected UTF16 string\n");
        return false;
    }
    runtime->Memory.Free(s);
    return true;
}

static bool TestWinBase_UTF16ToANSI()
{
    UTF16 s0 = L"utf16";
    ANSI  s1 = "utf16";

    ANSI s = runtime->WinBase.UTF16ToANSI(s0);
    if (s == NULL)
    {
        printf_s("failed to convert UTF16 to ANSI: 0x%X\n", GetLastErrno());
        return false;
    }
    if (strcmp_a(s1, s) != 0)
    {
        printf_s("unexpected UTF16 string\n");
        return false;
    }
    runtime->Memory.Free(s);
    return true;
}
