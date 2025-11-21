#include <stdio.h>
#include "c_types.h"
#include "random.h"
#include "test.h"

static void TestGenerateSeed();
static void TestRandByte();
static void TestRandBool();
static void TestRandInt();
static void TestRandUint();
static void TestRandInt64();
static void TestRandUint64();
static void TestRandIntN();
static void TestRandUintN();
static void TestRandInt64N();
static void TestRandUint64N();
static void TestRandBuffer();
static void TestRandSequence();

bool TestRandom()
{
    typedef void (*test_t)();
    test_t tests[] = 
    {
        { TestGenerateSeed },
        { TestRandByte     },
        { TestRandBool     },
        { TestRandInt      },
        { TestRandUint     },
        { TestRandInt64    },
        { TestRandUint64   },
        { TestRandIntN     },
        { TestRandUintN    },
        { TestRandInt64N   },
        { TestRandUint64N  },
        { TestRandBuffer   },
        { TestRandSequence },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        tests[i]();
    }
    return true;
}

static void TestGenerateSeed()
{
    printf_s("======TestGenerateSeed begin=======\n");

    for (uint i = 0; i < 10; i++)
    {
        printf_s("seed: %llu\n", GenerateSeed());
    }

    printf_s("======TestGenerateSeed passed======\n\n");
}

static void TestRandByte()
{
    printf_s("========TestRandByte begin=========\n");

    for (uint i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("byte: %d\n", RandByte(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (uint i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandByte(last);
        printf_s("byte: %lld\n", val);
        last += val;
    }

    printf_s("========TestRandByte passed========\n\n");
}

static void TestRandBool()
{
    printf_s("=========TestRandBool begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("bool: %d\n", RandBool(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandBool(last);
        printf_s("bool: %lld\n", val);
        last += last + val + 1;
    }

    printf_s("========TestRandBool passed========\n\n");
}

static void TestRandInt()
{
    printf_s("=========TestRandInt begin=========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("int: %lld\n", (uint64)RandInt(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt(last);
        printf_s("int: %lld\n", val);
        last += val;
    }

    printf_s("=========TestRandInt passed========\n\n");
}

static void TestRandUint()
{
    printf_s("=========TestRandUint begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("uint: %llu\n", (uint64)RandUint(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandUint(last);
        printf_s("uint: %llu\n", val);
        last += val;
    }

    printf_s("========TestRandUint passed========\n\n");
}

static void TestRandInt64()
{
    printf_s("========TestRandInt64 begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("int64: %lld\n", (uint64)RandInt64(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt64(last);
        printf_s("int64: %lld\n", val);
        last += val;
    }

    printf_s("========TestRandInt64 passed=======\n\n");
}

static void TestRandUint64()
{
    printf_s("=======TestRandUint64 begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("uint64: %llu\n", RandUint64(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = RandUint64(last);
        printf_s("uint64: %llu\n", val);
        last += val;
    }

    printf_s("=======TestRandUint64 passed=======\n\n");
}

static void TestRandIntN()
{
    printf_s("==========RandIntN begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandIntN(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("int: %lld\n", val);
    }

    printf_s("==========RandIntN passed==========\n\n");
}

static void TestRandUintN()
{
    printf_s("=========RandUintN begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandUintN(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("uint: %llu\n", val);
    }

    printf_s("=========RandUintN passed==========\n\n");
}

static void TestRandInt64N()
{
    printf_s("=========RandInt64N begin==========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandInt64N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("int64: %lld\n", val);
    }

    printf_s("=========RandInt64N passed=========\n\n");
}

static void TestRandUint64N()
{
    printf_s("========RandUint64N begin==========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandUint64N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("uint64: %llu\n", val);
    }

    printf_s("========RandUint64N passed=========\n\n");
}

static void TestRandBuffer()
{
    printf_s("=======TestRandBuffer begin========\n");

    byte buf[16];
    RandBuffer(buf, arrlen(buf));

    printf_s("buf: ");
    for (int i = 0; i < arrlen(buf); i++)
    {
        printf_s("%d ", buf[i]);
    }
    printf_s("\n");

    printf_s("=======TestRandBuffer passed=======\n\n");
}

static void TestRandSequence()
{
    printf_s("========RandSequence begin==========\n");

    int seq[8];
    RandSequence(seq, arrlen(seq));

    printf_s("seq: [ ");
    for (int i = 0; i < arrlen(seq); i++)
    {
        printf_s("%d ", seq[i]);
    }
    printf_s("]\n");

    printf_s("========RandSequence passed=========\n\n");
}
