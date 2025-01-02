#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "lib_match.h"
#include "test.h"

static bool TestMatch_MatchByte();
static bool TestMatch_MatchBytes();

bool TestLibMatch()
{
    test_t tests[] = 
    {
        { TestMatch_MatchByte  },
        { TestMatch_MatchBytes },
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

static bool TestMatch_MatchByte()
{
    byte s[] = { 1, 2, 3, 4 };
    integer n = sizeof(s);

    if (MatchByte(s, n, 1) != 0)
    {
        printf_s("invalid MatchByte returned index 0\n");
        return false;
    }
    if (MatchByte(s, n, 4) != 3)
    {
        printf_s("invalid MatchByte returned index 3\n");
        return false;
    }
    if (MatchByte(s, n, 3) != 2)
    {
        printf_s("invalid MatchByte returned index 2\n");
        return false;
    }

    printf_s("test MatchByte passed\n");
    return true;
}

static bool TestMatch_MatchBytes()
{
    byte s[] = { 1, 2, 3, 4 };
    integer n = sizeof(s);
    
    byte s0[] = { 0 };
    if (MatchBytes(s, n, s0, 0) != 0)
    {
        printf_s("invalid MatchBytes returned index 0\n");
        return false;
    }

    byte s1[] = { 0 };
    if (MatchBytes(s, n, s1, sizeof(s1)) != -1)
    {
        printf_s("invalid MatchBytes returned index -1\n");
        return false;
    }

    byte s2[] = { 1, 2, 3, 5 };
    if (MatchBytes(s, n, s2, sizeof(s2)) != -1)
    {
        printf_s("invalid MatchBytes returned index -1\n");
        return false;
    }

    byte s3[] = { 1, 2, 3, 4, 5 };
    if (MatchBytes(s, n, s3, sizeof(s3)) != -1)
    {
        printf_s("invalid MatchBytes returned index -1\n");
        return false;
    }

    byte s4[] = { 2, 3, 4 };
    if (MatchBytes(s, n, s4, sizeof(s4)) != 1)
    {
        printf_s("invalid MatchBytes returned index 1\n");
        return false;
    }

    byte sl[128];
    mem_init(sl, sizeof(sl));
    for (int i = 0; i < 128; i++)
    {
        sl[i] = (byte)i;
    }
    byte s5[] = { 99, 100, 101 };
    if (MatchBytes(sl, sizeof(sl), s5, sizeof(s5)) != 99)
    {
        printf_s("invalid MatchBytes returned index 99\n");
        return false;
    }

    printf_s("test MatchBytes passed\n");
    return true;
}
