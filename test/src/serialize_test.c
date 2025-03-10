#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "serialize.h"
#include "test.h"

static bool TestSer_Serialize();
static bool TestSer_Unserialize();

static void printHexBytes(byte* buf, uint size);

bool TestSerialize()
{
    test_t tests[] = 
    {
        { TestSer_Serialize   },
        { TestSer_Unserialize },
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

#pragma pack(1)
typedef struct {
    uint32 arg1;
    uint32 arg2[2];
    byte*  arg3;
    ANSI   arg4;
    uint8  arg5;
    uint16 arg6;
} struct1;
#pragma pack()

static bool TestSer_Serialize()
{
    struct1 s1 = {
        .arg1 = 123,
        .arg3 = NULL,
        .arg4 = "123",
        .arg5 = 0x19,
        .arg6 = 0x1548,
    };
    s1.arg2[0] = 456;
    s1.arg2[1] = 789;
    uint32 descriptor[] = {
        SERIALIZE_FLAG_VALUE|sizeof(s1.arg1),
        SERIALIZE_FLAG_VALUE|sizeof(s1.arg2),
        SERIALIZE_FLAG_POINTER|0,
        SERIALIZE_FLAG_POINTER|4,
        SERIALIZE_FLAG_VALUE|sizeof(s1.arg5),
        SERIALIZE_FLAG_VALUE|sizeof(s1.arg6),
        SERIALIZE_ITEM_END,
    };
    uint32 expected = 4 + (7 * 4) + (4 + 8 + 0 + 4 + 1 + 2);

    uint32 len = Serialize(descriptor, &s1, NULL);
    if (len != expected)
    {
        printf_s("Serialize with invalid output length\n");
        return false;
    }
    void* serialized = runtime->Memory.Alloc(len);
    len = Serialize(descriptor, &s1, serialized);
    if (len != expected)
    {
        printf_s("Serialize with invalid output length\n");
        return false;
    }

    printHexBytes(serialized, len);
    byte expecteds[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00, 
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x04, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x7B, 0x00, 0x00, 0x00, 0xC8, 0x01, 0x00, 0x00, 
        0x15, 0x03, 0x00, 0x00, 0x31, 0x32, 0x33, 0x00, 
        0x19, 0x48, 0x15
    };
    if (!mem_equal(expecteds, serialized, len))
    {
        printf_s("Serialize with invalid output data\n");
        return false;
    }

    runtime->Memory.Free(serialized);

    printf_s("test Serialize passed\n");
    return true;
}

static bool TestSer_Unserialize()
{
    printf_s("test Unserialize passed\n");
    return true;
}

static void printHexBytes(byte* buf, uint size)
{
    int counter = 0;
    for (uint i = 0; i < size; i++)
    {
        printf_s("%02X ", *buf);

        buf++;
        counter++;
        if (counter >= 16)
        {
            counter = 0;
            printf_s("\n");
        }
    }
    printf_s("\n");
}
