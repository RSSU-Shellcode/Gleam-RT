#include <stdio.h>
#include "c_types.h"
#include "lib_string.h"
#include "test.h"

#define BANNER_BEGIN_SIZE 10 // strlen("Test Begin")
#define BANNER_END_SIZE   11 // strlen("Test Passed")
#define BANNER_FAIL_SIZE  11 // strlen("Test Failed")

static void printBannerBegin(byte* name, uint len);
static void printBannerEnd  (byte* name, uint len, bool pass);

int __cdecl main()
{
    // calculate the banner length
    uint maxNameLen = 0;
    for (int i = 0; i < arrlen(tests); i++)
    {
        uint len = strlen_a(tests[i].Name);
        if (len > maxNameLen)
        {
            maxNameLen = len;
        }
    }
    // ================TestFunction begin================
    uint bannerLen = (uint)16 + BANNER_END_SIZE + maxNameLen + 16;

    // run unit tests
    bool failed = false;
    for (int i = 0; i < arrlen(tests); i++)
    {
        printBannerBegin(tests[i].Name, bannerLen);
        bool pass = tests[i].Test();
        if (!pass)
        {
            failed = true;
        }
        printBannerEnd(tests[i].Name, bannerLen, pass);
    }

    if (failed)
    {
        printf_s("Failed to test\n");
        return 1;
    }
    printf_s("All tests passed!\n");
    return 0;
}

static void printBannerBegin(byte* name, uint len)
{
    uint padLen = ( len - BANNER_BEGIN_SIZE - strlen_a(name)) / 2;
    bool equal  = ( len - BANNER_BEGIN_SIZE - strlen_a(name)) % 2 == 0;
    // print prefix
    for (uint i = 0; i < padLen; i++)
    {
        printf_s("=");
    }
    printf_s("Test%s Begin", name);
    // print suffix
    for (uint i = 0; i < padLen; i++)
    {
        printf_s("=");
    }
    // padding data
    if (!equal)
    {
        printf_s("=");
    }
    printf_s("\n");
}

static void printBannerEnd(byte* name, uint len, bool pass)
{
    uint padLen = ( len - BANNER_END_SIZE - strlen_a(name)) / 2;
    bool equal  = ( len - BANNER_END_SIZE - strlen_a(name)) % 2 == 0;
    // print prefix
    for (uint i = 0; i < padLen; i++)
    {
        printf_s("=");
    }
    if (pass)
    {
        printf_s("Test%s Passed", name);
    } else {
        printf_s("Test%s FAILED", name);
    }
    // print suffix
    for (uint i = 0; i < padLen; i++)
    {
        printf_s("=");
    }
    // padding data
    if (!equal)
    {
        printf_s("=");
    }
    printf_s("\n\n");
}
