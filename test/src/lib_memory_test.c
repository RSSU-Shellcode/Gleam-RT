#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "test.h"

static bool TestMem_copy();
static bool TestMem_move();
static bool TestMem_init();
static bool TestMem_set();
static bool TestMem_cmp();
static bool TestMem_equal();
static bool TestMem_is_zero();

bool TestLibMemory()
{
    test_t tests[] = 
    {
        { TestMem_copy    },
        { TestMem_move    },
        { TestMem_init    },
        { TestMem_set     },
        { TestMem_cmp     },
        { TestMem_equal   },
        { TestMem_is_zero },
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

static bool TestMem_copy()
{
    byte src[4] = { 1, 2, 3, 4 };
    byte dst[8];
    mem_copy(dst, src, sizeof(src));

    if (dst[0] != 1 || dst[1] != 2 || dst[2] != 3 || dst[3] != 4)
    {
        printf_s("mem_copy process invalid data\n");
        return false;
    }
    printf_s("test mem_copy passed\n");
    return true;
}

static bool TestMem_move()
{
    byte src[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte* dst = &src[1];
    mem_move(dst, src, 4);

    if (dst[0] != 1 || dst[1] != 2 || dst[2] != 3 || dst[3] != 4)
    {
        printf_s("mem_move move invalid data\n");
        return false;
    }
    if (src[0] != 1 || src[1] != 1 || src[2] != 2 || src[3] != 3)
    {
        printf_s("mem_move process invalid data\n");
        return false;
    }
    if (src[4] != 4 || src[5] != 6 || src[6] != 7 || src[7] != 8)
    {
        printf_s("mem_move process invalid data\n");
        return false;
    }
    printf_s("test mem_move passed\n");
    return true;
}

static bool TestMem_init()
{
    byte mem[4] = { 1, 2, 3, 4 };
    mem_init(mem, sizeof(mem));

    if (*(uint32*)(mem) != 0)
    {
        printf_s("mem_init process invalid data\n");
        return false;
    }
    printf_s("test mem_init passed\n");
    return true;
}

static bool TestMem_set()
{
    byte mem[4] = { 1, 2, 3, 4 };
    mem_set(mem, 0x11, sizeof(mem));

    if (*(uint32*)(mem) != 0x11111111)
    {
        printf_s("mem_set process invalid data\n");
        return false;
    }
    printf_s("test mem_set passed\n");
    return true;
}

static bool TestMem_cmp()
{
    byte a0[4] = { 1, 2, 3, 4 };
    byte b0[4] = { 1, 2, 3, 4 };
    if (mem_cmp(a0, b0, sizeof(a0)) != 0)
    {
        printf_s("mem_cmp process invalid data\n");
        return false;
    }

    byte a1[4] = { 1, 2, 3, 5 };
    byte b1[4] = { 1, 2, 3, 4 };
    if (mem_cmp(a1, b1, sizeof(a1)) != 1)
    {
        printf_s("mem_cmp process invalid data\n");
        return false;
    }

    byte a2[4] = { 1, 2, 3, 4 };
    byte b2[4] = { 1, 2, 3, 5 };
    if (mem_cmp(a2, b2, sizeof(a2)) != -1)
    {
        printf_s("mem_cmp process invalid data\n");
        return false;
    }
    printf_s("test mem_cmp passed\n");
    return true;
}

static bool TestMem_equal()
{
    byte a0[4] = { 1, 2, 3, 4 };
    byte b0[4] = { 1, 2, 3, 4 };
    if (!mem_equal(a0, b0, sizeof(a0)))
    {
        printf_s("mem_equal process invalid data\n");
        return false;
    }

    byte a1[4] = { 1, 2, 3, 4 };
    byte b1[4] = { 1, 2, 2, 4 };
    if (mem_equal(a1, b1, sizeof(a1)))
    {
        printf_s("mem_equal process invalid data\n");
        return false;
    }
    printf_s("test mem_equal passed\n");
    return true;
}

static bool TestMem_is_zero()
{
    byte mem0[4] = { 0, 0, 0, 0 };
    if (!mem_is_zero(mem0, sizeof(mem0)))
    {
        printf_s("mem_is_zero process invalid data\n");
        return false;
    }

    byte mem1[4] = { 0, 0, 1, 0 };
    if (mem_is_zero(mem1, sizeof(mem1)))
    {
        printf_s("mem_is_zero process invalid data\n");
        return false;
    }
    printf_s("test mem_is_zero passed\n");
    return true;
}
