#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

static bool TestWinCrypto_RandBuffer();
static bool TestWinCrypto_SHA1();

static void printHexBytes(byte* buf, uint size);

bool TestRuntime_WinCrypto()
{
    test_t tests[] = {
        { TestWinCrypto_RandBuffer },
        { TestWinCrypto_SHA1       },
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

static bool TestWinCrypto_RandBuffer()
{
    byte buf[16] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    errno err = runtime->WinCrypto.RandBuffer(buf, sizeof(buf));
    if (err != NO_ERROR)
    {
        printf_s("failed to test RandBuffer: %X\n", err);
        return false;
    }

    printHexBytes(buf, sizeof(buf));
    if (buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[15] == 0)
    {
        printf_s("get incorrect random data\n");
        return false;
    }

    printf_s("test RandBuffer passed\n");
    return true;
}

static bool TestWinCrypto_SHA1()
{
    byte buf[4] = { 1, 2, 3, 4 };

    byte hash[20];
    errno err = runtime->WinCrypto.SHA1(buf, sizeof(buf), hash);
    if (err != NO_ERROR)
    {
        printf_s("failed to test SHA1: %X\n", err);
        return false;
    }

    printHexBytes(hash, sizeof(hash));
    byte expected[20] = {
        0x12, 0xDA, 0xDA, 0x1F, 0xFF, 0x4D, 0x47, 0x87,
        0xAD, 0xE3, 0x33, 0x31, 0x47, 0x20, 0x2C, 0x3B,
        0x44, 0x3E, 0x37, 0x6F,
    };
    if (!mem_equal(hash, expected, 20))
    {
        printf_s("get incorrect SHA1 hash\n");
        return false;
    }

    printf_s("test SHA1 passed\n");
    return true;
}

static void printHexBytes(byte* buf, uint size)
{
    int counter = 0;
    for (uint i = 0; i < size; i++)
    {
        printf_s("%02X ", *buf);

        buf++;
        counter++;
        if (counter >= 16)
        {
            counter = 0;
            printf_s("\n");
        }
    }
    printf_s("\n");
}
