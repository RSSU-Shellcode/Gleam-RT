#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "hash_api.h"
#include "errno.h"
#include "mod_argument.h"
#include "runtime.h"

// NOT using stdio is to ensure that no runtime instructions 
// are introduced to avoid compiler optimization link errors 
// that cause the extracted shellcode to contain incorrect 
// relative/absolute memory addresses.

static LoadLibraryA_t LoadLibraryA;
static CreateFileA_t  CreateFileA;
static WriteFile_t    WriteFile;
static CloseHandle_t  CloseHandle;

typedef int (*printf_s_t)(const char* format, ...);
static printf_s_t printf_s;

bool testShellcode(bool erase);
bool saveShellcode();

static void init()
{
    LoadLibraryA = FindAPI_A("kernel32.dll", "LoadLibraryA");
    CreateFileA  = FindAPI_A("kernel32.dll", "CreateFileA");
    WriteFile    = FindAPI_A("kernel32.dll", "WriteFile");
    CloseHandle  = FindAPI_A("kernel32.dll", "CloseHandle");

    HMODULE hModule = LoadLibraryA("msvcrt.dll");
    if (hModule == NULL)
    {
        return;
    }
    printf_s = FindAPI_A("msvcrt.dll", "printf_s");
}

#pragma comment(linker, "/ENTRY:EntryPoint")
int EntryPoint()
{
    init();
    if (!testShellcode(false))
    {
        return 1;
    }
    if (!saveShellcode())
    {
        return 2;
    }
    if (!testShellcode(true))
    {
        return 3;
    }
    printf_s("build shellcode successfully\n");
    return 0;
}

bool testShellcode(bool erase)
{
    Runtime_Opts opt = {
        .BootInstAddress     = NULL,
        .DisableSysmon       = false,
        .DisableWatchdog     = false,
        .NotEraseInstruction = !erase,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
    Runtime_M* RuntimeM = InitRuntime(&opt);
    if (RuntimeM == NULL)
    {
        printf_s("failed to initialize runtime: 0x%X\n", GetLastErrno());
        return false;
    }
    printf_s("RuntimeM: 0x%llX\n", (uint64)RuntimeM);
    errno errno = RuntimeM->Core.Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit runtime: 0x%X\n", errno);
        return false;
    }
    return true;
}

bool saveShellcode()
{
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Argument_Stub);
    uintptr size  = end - begin;
    // check runtime option stub is valid
    end -= OPTION_STUB_SIZE;
    if (*(byte*)(end) != OPTION_STUB_MAGIC)
    {
        printf_s("invalid runtime option stub\n");
        return false;
    }
    for (uintptr i = 0; i < OPTION_STUB_SIZE - 1; i++)
    {
        end++;
        if (*(byte*)(end) != 0x00)
        {
            printf_s("invalid runtime option stub\n");
            return false;
        }
    }
    // extract shellcode and save to file
#ifdef _WIN64
    LPSTR path = "../dist/GleamRT_x64.bin";
#elif _WIN32
    LPSTR path = "../dist/GleamRT_x86.bin";
#endif
    HANDLE hFile = CreateFileA(
        path, GENERIC_WRITE, 0, NULL, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf_s("failed to create output file: 0x%X\n", GetLastErrno());
        return false;
    }
    if (!WriteFile(hFile, (byte*)begin, (DWORD)size, NULL, NULL))
    {
        printf_s("failed to write shellcode: 0x%X\n", GetLastErrno());
        return false;
    }
    if (!CloseHandle(hFile))
    {
        printf_s("failed to close file: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}
