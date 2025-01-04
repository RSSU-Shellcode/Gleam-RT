#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "hash_api.h"

// not use function main() for not use "msvcrt.dll"
// not use CommandLineToArgvW for not load "shell32.dll"
// so it only read the ".\test_x64.bin" or ".\test_x86.bin"

typedef uint (*entryPoint_t)();

#pragma comment(linker, "/ENTRY:EntryPoint")
uint EntryPoint()
{
    VirtualAlloc_t  VirtualAlloc  = FindAPI_A("kernel32.dll", "VirtualAlloc");
    VirtualFree_t   VirtualFree   = FindAPI_A("kernel32.dll", "VirtualFree");
    CreateFileA_t   CreateFileA   = FindAPI_A("kernel32.dll", "CreateFileA");
    GetFileSizeEx_t GetFileSizeEx = FindAPI_A("kernel32.dll", "GetFileSizeEx");
    ReadFile_t      ReadFile      = FindAPI_A("kernel32.dll", "ReadFile");
    CloseHandle_t   CloseHandle   = FindAPI_A("kernel32.dll", "CloseHandle");

    // read shellcode from file
#ifdef _WIN64
    LPCSTR fileName = "test_x64.bin";
#elif _WIN32
    LPCSTR fileName = "test_x86.bin";
#endif
    HANDLE hFile = CreateFileA(
        fileName, GENERIC_READ, 0, NULL, 
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return 1;
    }
    int64 fileSize;
    if (!GetFileSizeEx(hFile, &fileSize))
    {
        return 2;
    }
    SIZE_T size = (SIZE_T)fileSize;
    void* buf = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (buf == NULL)
    {
        return 3;
    }
    if (!ReadFile(hFile, buf, (DWORD)fileSize, NULL, NULL))
    {
        return 4;
    }
    if (!CloseHandle(hFile))
    {
        return 5;
    }

    // execute shellcode
    uint exitCode = ((entryPoint_t)(buf))();

    // clean resource
    if (!VirtualFree(buf, 0, MEM_RELEASE))
    {
        return 6;
    }
    return exitCode;
}
