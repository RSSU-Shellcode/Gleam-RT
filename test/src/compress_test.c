#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "random.h"
#include "compress.h"
#include "test.h"

static bool TestCom_Compress();
static bool TestCom_Decompress();
static bool TestCom_Fuzz();

bool TestCompress()
{
    test_t tests[] = 
    {
        { TestCom_Compress   },
        { TestCom_Decompress },
        { TestCom_Fuzz       },
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

static bool TestCom_Compress()
{
    LPSTR path = "..\\src\\runtime.c";
    databuf data;
    errno errno = runtime->WinFile.ReadFileA(path, &data);
    if (errno != NO_ERROR)
    {
        printf_s("failed to read test file: 0x%X\n", errno);
        return false;
    }

    uint windows[] = {
        32, 64, 128, 256, 512, 1024, 1536, 2048, 4096,
    };
    for (int i = 0; i < arrlen(windows); i++)
    {
        void* dst = runtime->Memory.Alloc(data.len);
        uint  len = Compress(dst, data.buf, data.len, windows[i]);
        printf_s("compressed: %zu/%zu, window: %zu\n", len, data.len, windows[i]);
        runtime->Memory.Free(dst);
    }

    runtime->Memory.Free(data.buf);
    printf_s("test compress passed\n");
    return true;
}

static bool TestCom_Decompress()
{
    LPSTR path = "..\\src\\runtime.c";
    databuf data;
    errno errno = runtime->WinFile.ReadFileA(path, &data);
    if (errno != NO_ERROR)
    {
        printf_s("failed to read test file: 0x%X\n", errno);
        return false;
    }

    void* dst = runtime->Memory.Alloc(data.len);
    uint len = Compress(dst, data.buf, data.len, 2048);
    printf_s("compressed:   %zu\n", len);

    void* raw = runtime->Memory.Alloc(data.len);
    len = Decompress(raw, dst, len);
    printf_s("decompressed: %zu\n", len);

    if (len != data.len)
    {
        printf_s("incorrect decompressed data size: %zu\n", len);
        return false;
    }
    if (mem_cmp(data.buf, raw, data.len) != 0)
    {
        printf_s("incorrect decompressed data\n");
        return false;
    }

    runtime->Memory.Free(data.buf);
    runtime->Memory.Free(dst);
    runtime->Memory.Free(raw);
    printf_s("test decompress passed\n");
    return true;
}

static bool TestCom_Fuzz()
{
    uint  size = (uint)(32 * 1024);
    byte* data = runtime->Memory.Alloc(size);

    for (int i = 0; i < 100; i++ )
    {
        // padding random data
        uint64 seed = (uint64)(data);
        uint   idx  = 0;
        for (int j = 0; j < 1000; j++)
        {
            switch (RandBool(seed))
            {
            case true:
                for (int k = 0; k < 32; k++)
                {
                    data[idx] = (byte)RandIntN(seed, 4);
                    seed = RandUint64(seed);
                    idx++;
                }
                break;
            case false:
                for (int k = 0; k < 16; k++)
                {
                    data[idx] = (byte)RandIntN(seed, 6);
                    seed = RandUint64(seed);
                    idx++;
                }
                break;
            }
        }

        void* dst = runtime->Memory.Alloc(size);
        uint len = Compress(dst, data, size, 512);
        void* raw = runtime->Memory.Alloc(size);
        len = Decompress(raw, dst, len);

        if (len != size)
        {
            printf_s("incorrect fuzz decompressed data size: %zu\n", len);
            return false;
        }
        if (mem_cmp(data, raw, size) != 0)
        {
            printf_s("incorrect fuzz decompressed data\n");
            return false;
        }

        runtime->Memory.Free(dst);
        runtime->Memory.Free(raw);
    }

    runtime->Memory.Free(data);
    printf_s("test compress fuzz passed\n");
    return true;
}
