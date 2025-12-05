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
bool TestLibMatch();
bool TestRandom();
bool TestCrypto();
bool TestCompress();
bool TestSerialize();
bool TestMemScanner();

bool TestInitRuntime();
bool TestRuntime_Detector();
bool TestRuntime_Memory();
bool TestRuntime_Argument();
bool TestRuntime_Storage();
bool TestRuntime_WinBase();
bool TestRuntime_WinFile();
bool TestRuntime_WinHTTP();
bool TestRuntime_WinCrypto();
bool TestRuntime_Watchdog();
bool TestRuntime_Sysmon();
bool TestRuntime_Exit();
bool TestRuntime_Options();
#pragma warning(pop)

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = 
{
    { "InitRuntime", TestInitRuntime },

    { "Lib_Memory",  TestLibMemory  },
    { "Lib_String",  TestLibString  },
    { "Lib_Match",   TestLibMatch   },
    { "Random",      TestRandom     },
    { "Crypto",      TestCrypto     },
    { "Compress",    TestCompress   },
    { "Serialize",   TestSerialize  },
    { "Mem_Scanner", TestMemScanner },

    { "Runtime_Detector",  TestRuntime_Detector  },
    { "Runtime_Memory",    TestRuntime_Memory    },
    { "Runtime_Argument",  TestRuntime_Argument  },
    { "Runtime_Storage",   TestRuntime_Storage   },
    { "Runtime_WinBase",   TestRuntime_WinBase   },
    { "Runtime_WinFile",   TestRuntime_WinFile   },
    { "Runtime_WinHTTP",   TestRuntime_WinHTTP   },
    { "Runtime_WinCrypto", TestRuntime_WinCrypto },
    { "Runtime_Watchdog",  TestRuntime_Watchdog  },
    { "Runtime_Sysmon",    TestRuntime_Sysmon    },
    { "Runtime_Exit",      TestRuntime_Exit      },
    { "Runtime_Options",   TestRuntime_Options   },
};

#endif // TEST_H
