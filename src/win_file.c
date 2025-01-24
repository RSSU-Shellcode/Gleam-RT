#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "errno.h"
#include "context.h"
#include "win_file.h"
#include "debug.h"

#ifdef RELEASE_MODE
    #define CHUNK_SIZE 4096
#else
    #define CHUNK_SIZE 64
#endif

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    CreateFileA_t   CreateFileA;
    CreateFileW_t   CreateFileW;
    GetFileSizeEx_t GetFileSizeEx;
    ReadFile_t      ReadFile;
    WriteFile_t     WriteFile;
    CloseHandle_t   CloseHandle;

    // submodules method
    mt_malloc_t malloc;
    mt_free_t   free;
} WinFile;

// methods for user
errno WF_ReadFileA(LPSTR path, byte** buf, uint* size);
errno WF_ReadFileW(LPWSTR path, byte** buf, uint* size);
errno WF_WriteFileA(LPSTR path, byte* buf, uint size);
errno WF_WriteFileW(LPWSTR path, byte* buf, uint size);

// methods for runtime
errno WF_Uninstall();

// hard encoded address in getModulePointer for replacement
#ifdef _WIN64
    #define MODULE_POINTER 0x7FABCDEF111111E2
#elif _WIN32
    #define MODULE_POINTER 0x7FABCDE2
#endif
static WinFile* getModulePointer();

static bool initModuleAPI(WinFile* module, Context* context);
static bool updateModulePointer(WinFile* module);
static bool recoverModulePointer(WinFile* module);
static bool initModuleEnvironment(WinFile* module, Context* context);
static void eraseModuleMethods(Context* context);

errno readFile(HANDLE hFile, byte** buf, uint* size);
errno writeFile(HANDLE hFile, byte* buf, uint size);

WinFile_M* InitWinFile(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr moduleAddr = address + 18000 + RandUintN(address, 128);
    uintptr methodAddr = address + 19000 + RandUintN(address, 128);
    // initialize module
    WinFile* module = (WinFile*)moduleAddr;
    mem_init(module, sizeof(WinFile));
    // store options
    module->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initModuleAPI(module, context))
        {
            errno = ERR_WIN_FILE_INIT_API;
            break;
        }
        if (!updateModulePointer(module))
        {
            errno = ERR_WIN_FILE_UPDATE_PTR;
            break;
        }
        if (!initModuleEnvironment(module, context))
        {
            errno = ERR_WIN_FILE_INIT_ENV;
            break;
        }
        break;
    }
    eraseModuleMethods(context);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    // create method set
    WinFile_M* method = (WinFile_M*)methodAddr;
    method->ReadFileA  = GetFuncAddr(&WF_ReadFileA);
    method->ReadFileW  = GetFuncAddr(&WF_ReadFileW);
    method->WriteFileA = GetFuncAddr(&WF_WriteFileA);
    method->WriteFileW = GetFuncAddr(&WF_WriteFileW);
    method->Uninstall  = GetFuncAddr(&WF_Uninstall);
    return method;
}

static bool initModuleAPI(WinFile* module, Context* context)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x25A5D7F5BB962DC8, 0x9CD44B683CE17BB6 }, // CreateFileA
        { 0x1E0DC0D6B2FBC9BE, 0xD0D465B1C6EE90D2 }, // CreateFileW
        { 0x5E4CF1B0CACB9DD4, 0xF2F660A9FA989AA5 }, // GetFileSizeEx
        { 0xA35B1843BD034620, 0x5A61E67086B515E9 }, // ReadFile
        { 0x2DC91E971C8A6CAB, 0x53D106A37CB5022C }, // WriteFile
    };
#elif _WIN32
    {
        { 0xF1EB542C, 0xBE63A34F }, // CreateFileA
        { 0x72331B65, 0x2347FDB8 }, // CreateFileW
        { 0x75FAD4ED, 0xF7D881E8 }, // GetFileSizeEx
        { 0x02C8D131, 0xA90353CD }, // ReadFile
        { 0x0A0B19BF, 0x91D1EBF2 }, // WriteFile
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    module->CreateFileA   = list[0].proc;
    module->CreateFileW   = list[1].proc;
    module->GetFileSizeEx = list[2].proc;
    module->ReadFile      = list[3].proc;
    module->WriteFile     = list[4].proc;

    module->CloseHandle = context->CloseHandle;
    return true;
}

// CANNOT merge updateModulePointer and recoverModulePointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

static bool updateModulePointer(WinFile* module)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getModulePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != MODULE_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)module;
        success = true;
        break;
    }
    return success;
}

static bool recoverModulePointer(WinFile* module)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getModulePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)module)
        {
            target++;
            continue;
        }
        *pointer = MODULE_POINTER;
        success = true;
        break;
    }
    return success;
}

static bool initModuleEnvironment(WinFile* module, Context* context)
{
    module->malloc = context->mt_malloc;
    module->free   = context->mt_free;
    return true;
}

static void eraseModuleMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initModuleAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseModuleMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

// updateModulePointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateModulePointer will fail.
#pragma optimize("", off)
static WinFile* getModulePointer()
{
    uintptr pointer = MODULE_POINTER;
    return (WinFile*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
errno WF_ReadFileA(LPSTR path, byte** buf, uint* size)
{
    WinFile* module = getModulePointer();

    HANDLE hFile = module->CreateFileA(
        path, GENERIC_READ, 0, NULL, 
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return GetLastErrno();
    }
    return readFile(hFile, buf, size);
}

__declspec(noinline)
errno WF_ReadFileW(LPWSTR path, byte** buf, uint* size)
{
    WinFile* module = getModulePointer();

    HANDLE hFile = module->CreateFileW(
        path, GENERIC_READ, 0, NULL, 
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return GetLastErrno();
    }
    return readFile(hFile, buf, size);
}

__declspec(noinline)
errno readFile(HANDLE hFile, byte** buf, uint* size)
{
    WinFile* module = getModulePointer();

    int64 fSize  = 0;
    byte* buffer = NULL;
    errno errno  = NO_ERROR;
    for (;;)
    {
        // get the file size
        if (!module->GetFileSizeEx(hFile, &fSize))
        {
            errno = GetLastErrno();
            break;
        }
        // allocate memory for store file
        byte* fBuf = module->malloc((uint)fSize);
        if (fBuf == NULL)
        {
            errno = GetLastErrno();
            break;
        }
        buffer = fBuf;
        // read file until EOF
        int64 read = 0;
        for (;;)
        {
            // prevent buffer overflow
            int64 chunkSize = CHUNK_SIZE;
            int64 remaining = fSize - read;
            if (remaining < chunkSize)
            {
                chunkSize = remaining;
            }
            // read file chunk
            DWORD n;
            if (!module->ReadFile(hFile, fBuf, (DWORD)chunkSize, &n, NULL))
            {
                errno = GetLastErrno();
                break;
            }
            // check is EOF
            if (n < chunkSize)
            {
                break;
            }
            read += n;
            if (read == fSize)
            {
                break;
            }
            // read next chunk
            fBuf += n;
        }
        break;
    }

    if (!module->CloseHandle(hFile) && errno == NO_ERROR)
    {
        errno = GetLastErrno();
    }
    if (errno != NO_ERROR)
    {
        module->free(buffer);
        return errno;
    }

    // write result
    *buf = buffer;
    if (size != NULL)
    {
        *size = (uint)fSize;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno WF_WriteFileA(LPSTR path, byte* buf, uint size)
{
    WinFile* module = getModulePointer();

    HANDLE hFile = module->CreateFileA(
        path, GENERIC_WRITE, 0, NULL, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return GetLastErrno();
    }
    return writeFile(hFile, buf, size);
}

__declspec(noinline)
errno WF_WriteFileW(LPWSTR path, byte* buf, uint size)
{
    WinFile* module = getModulePointer();

    HANDLE hFile = module->CreateFileW(
        path, GENERIC_WRITE, 0, NULL, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return GetLastErrno();
    }
    return writeFile(hFile, buf, size);
}

__declspec(noinline)
errno writeFile(HANDLE hFile, byte* buf, uint size)
{
    WinFile* module = getModulePointer();

    uint  written = 0;
    errno errno   = NO_ERROR;
    for (;;)
    {
        // prevent buffer overflow
        uint chunkSize = CHUNK_SIZE;
        uint remaining = size - written;
        if (remaining < chunkSize)
        {
            chunkSize = remaining;
        }
        // write file chunk
        DWORD n;
        if (!module->WriteFile(hFile, buf, (DWORD)chunkSize, &n, NULL))
        {
            errno = GetLastErrno();
            break;
        }
        // check is finished
        written += n;
        if (written == size)
        {
            break;
        }
        // write next chunk
        buf += n;
    }

    if (!module->CloseHandle(hFile) && errno == NO_ERROR)
    {
        errno = GetLastErrno();
    }
    return errno;
}

__declspec(noinline)
errno WF_Uninstall()
{
    WinFile* module = getModulePointer();

    errno errno = NO_ERROR;

    // recover instructions
    if (module->NotEraseInstruction)
    {
        if (!recoverModulePointer(module) && errno == NO_ERROR)
        {
            errno = ERR_WIN_FILE_RECOVER_INST;
        }
    }
    return errno;
}
