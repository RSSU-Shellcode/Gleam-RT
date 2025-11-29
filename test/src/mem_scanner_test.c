#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "mem_scanner.h"
#include "test.h"

static bool TestMemScanByValue();
static bool TestMemScanByConfig();
static bool TestBinToPattern();

static void printResults(uintptr* results, uint num);

bool TestMemScanner()
{
    test_t tests[] = 
    {
        { TestMemScanByValue  },
        { TestMemScanByConfig },
        { TestBinToPattern    },
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
    uint num = runtime->MemScanner.ScanByValue("test", 4, results, arrlen(results));
    if (num == -1 || num == 0)
    {
        printf_s("failed to scan target data: 0x%X\n", GetLastErrno());
        return false;
    }
    printResults(results, num);

    printf_s("test MemScanByValue passed\n");
    return true;
}

static bool TestMemScanByConfig()
{
    uintptr results[100];

    // exact value
    MemScan_Cfg config = {
        .Pattern = "74 65 73 74", // "test"
        .Protect = PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ,
        .Type    = MEM_PRIVATE|MEM_IMAGE,
    };

    uint num = runtime->MemScanner.ScanByConfig(&config, results, arrlen(results));
    if (num == -1 || num == 0)
    {
        printf_s("failed to scan target data: 0x%X\n", GetLastErrno());
        return false;
    }
    printResults(results, num);

    // contains arbitrary value
    config.Pattern = "74 65 ?? 74";
    num = runtime->MemScanner.ScanByConfig(&config, results, arrlen(results));
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
        config.Pattern = patterns[i];
        num = runtime->MemScanner.ScanByConfig(&config, results, arrlen(results));
        if (num != -1 || GetLastErrno() != ERR_MEM_SCANNER_INVALID_CONDITION)
        {
            printf_s("unexcepted return value or errno\n");
            return false;
        }
    }

    printf_s("test MemScanByConfig passed\n");
    return true;
}

static bool TestBinToPattern()
{
    byte pattern[32];
    runtime->MemScanner.BinToPattern("test", 4, pattern);
    if (strcmp_a(pattern, "74 65 73 74 ") != 0)
    {
        printf_s("invalid output pattern\n");
        return false;
    }

    uint64 value = 0xABCDEF123456;
    runtime->MemScanner.BinToPattern(&value, sizeof(value), pattern);
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
