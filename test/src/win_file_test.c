#include <stdio.h>
#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

static CreateFileA_t   CreateFileA;
static CreateFileW_t   CreateFileW;
static GetFileSizeEx_t GetFileSizeEx;
static ReadFile_t      ReadFile;
static CloseHandle_t   CloseHandle;

static bool TestWinFile_ReadFileA();
static bool TestWinFile_ReadFileW();
static bool TestWinFile_WriteFileA();
static bool TestWinFile_WriteFileW();

bool TestRuntime_WinFile()
{
    CreateFileA   = FindAPI_A("kernel32.dll", "CreateFileA");
    CreateFileW   = FindAPI_A("kernel32.dll", "CreateFileW");
    GetFileSizeEx = FindAPI_A("kernel32.dll", "GetFileSizeEx");
    ReadFile      = FindAPI_A("kernel32.dll", "ReadFile");
    CloseHandle   = FindAPI_A("kernel32.dll", "CloseHandle");

    test_t tests[] = 
    {
        { TestWinFile_ReadFileA  },
        { TestWinFile_ReadFileW  },
        { TestWinFile_WriteFileA },
        { TestWinFile_WriteFileW },
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

static bool TestWinFile_ReadFileA()
{
    LPSTR path = "test.vcxproj";

    databuf data;
    errno errno = runtime->WinFile.ReadFileA(path, &data);
    if (errno != NO_ERROR)
    {
        printf_s("failed to ReadFileA: 0x%X\n", errno);
        return false;
    }

    HANDLE hFile = CreateFileA(
        path, GENERIC_READ, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf_s("failed to open file: 0x%X\n", GetLastErrno());
        return false;
    }
    int64 fSize;
    if (!GetFileSizeEx(hFile, &fSize))
    {
        printf_s("failed to get file size: 0x%X\n", GetLastErrno());
        return false;
    }
    if (data.len != (uint)fSize)
    {
        printf_s("get different file size %zu %llu\n", data.len, fSize);
        return false;
    }
    byte* buf = runtime->Memory.Alloc((uint)fSize);
    if (!ReadFile(hFile, buf, (DWORD)fSize, NULL, NULL))
    {
        printf_s("failed to read file: 0x%X\n", GetLastErrno());
        return false;
    }
    if (mem_cmp(data.buf, buf, data.len) != 0)
    {
        printf_s("read different file data\n");
        return false;
    }
    if (!CloseHandle(hFile))
    {
        printf_s("failed to close file: 0x%X\n", GetLastErrno());
        return false;
    }

    runtime->Memory.Free(data.buf);
    runtime->Memory.Free(buf);
    printf_s("test ReadFileA passed\n");
    return true;
}

static bool TestWinFile_ReadFileW()
{
    LPWSTR path = L"test.vcxproj.filters";

    databuf data;
    errno errno = runtime->WinFile.ReadFileW(path, &data);
    if (errno != NO_ERROR)
    {
        printf_s("failed to ReadFileW: 0x%X\n", errno);
        return false;
    }

    HANDLE hFile = CreateFileW(
        path, GENERIC_READ, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf_s("failed to open file: 0x%X\n", GetLastErrno());
        return false;
    }
    int64 fSize;
    if (!GetFileSizeEx(hFile, &fSize))
    {
        printf_s("failed to get file size: 0x%X\n", GetLastErrno());
        return false;
    }
    if (data.len != (uint)fSize)
    {
        printf_s("get different file size %zu %llu\n", data.len, fSize);
        return false;
    }
    byte* buf = runtime->Memory.Alloc((uint)fSize);
    if (!ReadFile(hFile, buf, (DWORD)fSize, NULL, NULL))
    {
        printf_s("failed to read file: 0x%X\n", GetLastErrno());
        return false;
    }
    if (mem_cmp(data.buf, buf, data.len) != 0)
    {
        printf_s("read different file data\n");
        return false;
    }
    if (!CloseHandle(hFile))
    {
        printf_s("failed to close file: 0x%X\n", GetLastErrno());
        return false;
    }

    runtime->Memory.Free(data.buf);
    runtime->Memory.Free(buf);
    printf_s("test ReadFileW passed\n");
    return true;
}

static bool TestWinFile_WriteFileA()
{
    byte testdata[256];
    mem_init(testdata, sizeof(testdata));
    for (int i = 0; i < 256; i++)
    {
        testdata[i] = (byte)i;
    }

    LPSTR path = "testdata/WriteFileA.bin";
    databuf file = {
        .buf = testdata,
        .len = sizeof(testdata),
    };
    errno errno = runtime->WinFile.WriteFileA(path, &file);
    if (errno != NO_ERROR)
    {
        printf_s("failed to write testdata to file\n");
        return false;
    }

    databuf data;
    errno = runtime->WinFile.ReadFileA(path, &data);
    if (errno != NO_ERROR)
    {
        printf_s("failed to read testdata file\n");
        return false;
    }
    if (mem_cmp(testdata, data.buf, sizeof(testdata)) != 0)
    {
        printf_s("write file with incorrect data\n");
        return false;
    }
    if (data.len != sizeof(testdata))
    {
        printf_s("write file with incorrect size\n");
        return false;
    }

    runtime->Memory.Free(data.buf);
    printf_s("test WriteFileA passed\n");
    return true;
}

static bool TestWinFile_WriteFileW()
{
    byte testdata[513];
    mem_init(testdata, sizeof(testdata));
    for (int i = 0; i < 513; i++)
    {
        testdata[i] = (byte)i;
    }

    LPWSTR path = L"testdata/WriteFileW.bin";
    databuf file = {
        .buf = testdata,
        .len = sizeof(testdata),
    };
    errno errno = runtime->WinFile.WriteFileW(path, &file);
    if (errno != NO_ERROR)
    {
        printf_s("failed to write testdata to file\n");
        return false;
    }

    databuf data;
    errno = runtime->WinFile.ReadFileW(path, &data);
    if (errno != NO_ERROR)
    {
        printf_s("failed to read testdata file\n");
        return false;
    }
    if (mem_cmp(testdata, data.buf, sizeof(testdata)) != 0)
    {
        printf_s("write file with incorrect data\n");
        return false;
    }
    if (data.len != sizeof(testdata))
    {
        printf_s("write file with incorrect size\n");
        return false;
    }

    runtime->Memory.Free(data.buf);
    printf_s("test WriteFileW passed\n");
    return true;
}
