#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "compress.h"
#include "test.h"

static bool TestCom_Compress();
static bool TestCom_Decompress();

bool TestCompress()
{
    test_t tests[] = 
    {
        { TestCom_Compress   },
        { TestCom_Decompress },
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

    byte* data; uint size;
    errno errno = runtime->WinFile.ReadFileA(path, &data, &size);
    if (errno != NO_ERROR)
    {
        printf_s("failed to read test file: 0x%X\n", errno);
        return false;
    }

    uint windows[] = {
		32, 64, 128, 256, 512,
		1024, 1536, 2048, 4096,
    };
    for (int i = 0; i < arrlen(windows); i++)
    {
        void* dst = runtime->Memory.Alloc(size);
        uint  len = Compress(dst, data, size, windows[i]);
        printf_s("compressed: %zu/%zu, window: %zu\n", len, size, windows[i]);
        runtime->Memory.Free(dst);
    }

    runtime->Memory.Free(data);
    return true;
}

static bool TestCom_Decompress()
{
    LPSTR path = "..\\src\\runtime.c";

    byte* data; uint size;
    errno errno = runtime->WinFile.ReadFileA(path, &data, &size);
    if (errno != NO_ERROR)
    {
        printf_s("failed to read test file: 0x%X\n", errno);
        return false;
    }

    void* dst = runtime->Memory.Alloc(size);
    uint len = Compress(dst, data, size, 2048);
    printf_s("compressed: %zu\n", len);

    void* raw = runtime->Memory.Alloc(size);
    len = Decompress(raw, dst, len);
    printf_s("decompressed: %zu\n", len);

    if (len != size)
    {
        printf_s("incorrect decompressed data size: %zu\n", len);
        return false;
    }
    if (mem_cmp(data, raw, size) != 0)
    {
        printf_s("incorrect decompressed data\n");
        return false;
    }

    runtime->Memory.Free(data);
    runtime->Memory.Free(dst);
    runtime->Memory.Free(raw);
    return true;
}
