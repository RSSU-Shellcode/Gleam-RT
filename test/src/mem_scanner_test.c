#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "mem_scanner.h"
#include "test.h"

static bool TestMemScanByValue();
static bool TestMemScanByPattern();
static bool TestBinToPattern();

static void printResults(uintptr* results, uint num);

bool TestMemScanner()
{
    test_t tests[] = 
    {
        { TestMemScanByValue   },
        { TestMemScanByPattern },
        { TestBinToPattern     },
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

static bool TestMemScanByValue()
{
    uintptr results[100];
    uint num = MemScanByValue("test", 4, results, arrlen(results));
    if (num == -1 || num == 0)
    {
        printf_s("failed to scan target data: 0x%X\n", GetLastErrno());
        return false;
    }
    printResults(results, num);

    printf_s("test MemScanByValue passed\n");
    return true;
}

static bool TestMemScanByPattern()
{
    uintptr results[100]; // "test"

    // exact value
    uint num = MemScanByPattern("74 65 73 74", results, arrlen(results));
    if (num == -1 || num == 0)
    {
        printf_s("failed to scan target data: 0x%X\n", GetLastErrno());
        return false;
    }
    printResults(results, num);

    // contains arbitrary value
    num = MemScanByPattern("74 65 ?? 74", results, arrlen(results));
    if (num == -1 || num == 0)
    {
        printf_s("failed to scan target data: 0x%X\n", GetLastErrno());
        return false;
    }
    printResults(results, num);

    // invalid patterns
    byte* patterns[] = {
        "74 65 A? 74",
        "74 65 ?A 74",
        "74 65 7474",
        "74 65 7G",
        "?? ?? ?? ??",
    };
    for (int i = 0; i < arrlen(patterns); i++)
    {
        num = MemScanByPattern(patterns[i], results, arrlen(results));
        if (num != -1 || GetLastErrno() != ERR_MEM_SCANNER_INVALID_CONDITION)
        {
            printf_s("unexcepted return value or errno\n");
            return false;
        }
    }

    printf_s("test MemScanByPattern passed\n");
    return true;
}

static bool TestBinToPattern()
{
    byte pattern[32];
    BinToPattern("test", 4, pattern);
    if (strcmp_a(pattern, "74 65 73 74 ") != 0)
    {
        printf_s("invalid output pattern\n");
        return false;
    }

    uint64 value = 0xABCDEF123456;
    BinToPattern(&value, sizeof(value), pattern);
    if (strcmp_a(pattern, "56 34 12 EF CD AB 00 00 ") != 0)
    {
        printf_s("invalid output pattern\n");
        return false;
    }

    printf_s("test BinToPattern passed\n");
    return true;
}

static void printResults(uintptr* results, uint num)
{
    for (uint i = 0; i < num; i++)
    {
        printf_s("%zu: 0x%zX\n", i, results[i]);
    }
    printf_s("num result: %zu\n", num);
}
