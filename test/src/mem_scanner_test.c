#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "mem_scanner.h"
#include "test.h"

static bool TestMemScan();

static void printResults(uintptr* results, uint num);

bool TestMemScanner()
{
    test_t tests[] = 
    {
        { TestMemScan },
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

static bool TestMemScan()
{
    uintptr results[1000]; // "test"
    uint num = MemScan("74 65 73 74", results, arrlen(results));
    if (num == -1)
    {
        printf_s("failed to scan target data: 0x%X\n", GetLastErrno());
        return false;
    }
    printResults(results, num);

    // "74 65 73 74 "
    // "74 65 ?? 74"
    // "?A"
    // "A?"

    printf_s("test MemScan passed\n");
    return true;
}

static void printResults(uintptr* results, uint num)
{
    for (uint i = 0; i < num; i++)
    {
        printf_s("%zu: 0x%zX\n", i, *results);
        results++;
    }
    printf_s("num result: %zu\n", num);
}
