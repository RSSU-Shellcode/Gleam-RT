#ifndef TEST_H
#define TEST_H

#include "c_types.h"
#include "runtime.h"

// define global variables for tests
Runtime_M* runtime;

// define unit tests
#pragma warning(push)
#pragma warning(disable: 4276)
bool TestLibMemory();
bool TestLibString();
bool TestRandom();
bool TestCrypto();

bool TestInitRuntime();
bool TestRuntime_Memory();
bool TestRuntime_Argument();
bool TestRuntime_WinBase();
bool TestRuntime_WinFile();
bool TestRuntime_WinHTTP();
bool TestRuntime_Exit();
#pragma warning(pop)

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = 
{
    { "Lib_Memory", TestLibMemory },
    { "Lib_String", TestLibString },
    { "Random",     TestRandom    },
    { "Crypto",     TestCrypto    },

    { "InitRuntime",      TestInitRuntime      },
    { "Runtime_Memory",   TestRuntime_Memory   },
    { "Runtime_Argument", TestRuntime_Argument },
    { "Runtime_WinBase",  TestRuntime_WinBase  },
    { "Runtime_WinFile",  TestRuntime_WinFile  },
    { "Runtime_WinHTTP",  TestRuntime_WinHTTP  },
    { "Runtime_Exit",     TestRuntime_Exit     },
};

#endif // TEST_H
