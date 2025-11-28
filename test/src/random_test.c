#include <stdio.h>
#include "c_types.h"
#include "random.h"
#include "test.h"

static void TestGenerateSeed();
static void TestRandInt();
static void TestRandInt8();
static void TestRandInt16();
static void TestRandInt32();
static void TestRandInt64();
static void TestRandUint();
static void TestRandUint8();
static void TestRandUint16();
static void TestRandUint32();
static void TestRandUint64();
static void TestRandIntN();
static void TestRandInt8N();
static void TestRandInt16N();
static void TestRandInt32N();
static void TestRandInt64N();
static void TestRandUintN();
static void TestRandUint8N();
static void TestRandUint16N();
static void TestRandUint32N();
static void TestRandUint64N();
static void TestRandByte();
static void TestRandBool();
static void TestRandBOOL();
static void TestRandBuffer();
static void TestRandSequence();

bool TestRandom()
{
    typedef void (*test_t)();
    test_t tests[] = 
    {
        { TestGenerateSeed },
        { TestRandInt      },
        { TestRandInt8     },
        { TestRandInt16    },
        { TestRandInt32    },
        { TestRandInt64    },
        { TestRandUint     },
        { TestRandUint8    },
        { TestRandUint16   },
        { TestRandUint32   },
        { TestRandUint64   },
        { TestRandIntN     },
        { TestRandInt8N    },
        { TestRandInt16N   },
        { TestRandInt32N   },
        { TestRandInt64N   },
        { TestRandUintN    },
        { TestRandUint8N   },
        { TestRandUint16N  },
        { TestRandUint32N  },
        { TestRandUint64N  },
        { TestRandByte     },
        { TestRandBool     },
        { TestRandBOOL     },
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

static void TestRandInt8()
{
    printf_s("=========TestRandInt8 begin=========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("int8: %lld\n", (uint64)RandInt8(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt8(last);
        printf_s("int8: %lld\n", val);
        last += val;
    }

    printf_s("=========TestRandInt8 passed========\n\n");
}

static void TestRandInt16()
{
    printf_s("=========TestRandInt16 begin=========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("int16: %lld\n", (uint64)RandInt16(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt16(last);
        printf_s("int16: %lld\n", val);
        last += val;
    }

    printf_s("=========TestRandInt16 passed========\n\n");
}

static void TestRandInt32()
{
    printf_s("=========TestRandInt32 begin=========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("int32: %lld\n", (uint64)RandInt32(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt32(last);
        printf_s("int32: %lld\n", val);
        last += val;
    }

    printf_s("=========TestRandInt32 passed========\n\n");
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

static void TestRandUint8()
{
    printf_s("=======TestRandUint8 begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("uint8: %llu\n", (uint64)RandUint8(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = RandUint8(last);
        printf_s("uint8: %llu\n", val);
        last += val;
    }

    printf_s("=======TestRandUint8 passed=======\n\n");
}

static void TestRandUint16()
{
    printf_s("=========TestRandUint16 begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("uint16: %llu\n", (uint64)RandUint16(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandUint16(last);
        printf_s("uint16: %llu\n", val);
        last += val;
    }

    printf_s("========TestRandUint16 passed========\n\n");
}

static void TestRandUint32()
{
    printf_s("=========TestRandUint32 begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("uint32: %llu\n", (uint64)RandUint32(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandUint32(last);
        printf_s("uint32: %llu\n", val);
        last += val;
    }

    printf_s("========TestRandUint32 passed========\n\n");
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

static void TestRandInt8N()
{
    printf_s("==========RandInt8N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandInt8N(seed, 100);
        if (val > 100)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("int8: %lld\n", val);
    }

    printf_s("==========RandInt8N passed==========\n\n");
}

static void TestRandInt16N()
{
    printf_s("==========RandInt16N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandInt16N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("int16: %lld\n", val);
    }

    printf_s("==========RandInt16N passed==========\n\n");
}

static void TestRandInt32N()
{
    printf_s("==========RandInt32N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandInt32N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("int32: %lld\n", val);
    }

    printf_s("==========RandInt32N passed==========\n\n");
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

static void TestRandUint8N()
{
    printf_s("=========RandUint8N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandUint8N(seed, 200);
        if (val > 200)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("uint8: %llu\n", val);
    }

    printf_s("=========RandUint8N passed==========\n\n");
}

static void TestRandUint16N()
{
    printf_s("=========RandUint16N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandUint16N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("uint16: %llu\n", val);
    }

    printf_s("=========RandUint16N passed==========\n\n");
}

static void TestRandUint32N()
{
    printf_s("=========RandUint32N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandUint32N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("uint32: %llu\n", val);
    }

    printf_s("=========RandUint32N passed==========\n\n");
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

static void TestRandBOOL()
{
    printf_s("=========TestRandBOOL begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("bool: %d\n", RandBOOL(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandBOOL(last);
        printf_s("bool: %lld\n", val);
        last += last + val + 1;
    }

    printf_s("========TestRandBOOL passed========\n\n");
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
