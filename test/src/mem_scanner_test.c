#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "mem_scanner.h"
#include "test.h"

static bool TestMemScan();

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
    uintptr results[10]; // "test"
    uint num = MemScan("74 65 73 74", results, arrlen(results));

    printf_s("test MemScan passed\n");
    return true;
}
