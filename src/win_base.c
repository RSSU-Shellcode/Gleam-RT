#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "errno.h"
#include "context.h"
#include "win_base.h"
#include "debug.h"

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    MultiByteToWideChar_t MultiByteToWideChar;
    WideCharToMultiByte_t WideCharToMultiByte;

    // submodules method
    mt_malloc_t  malloc;
    mt_calloc_t  calloc;
    mt_realloc_t realloc;
    mt_free_t    free;
} WinBase;

// methods for user
UTF16 WB_ANSIToUTF16(ANSI s);
ANSI  WB_UTF16ToANSI(UTF16 s);
UTF16 WB_ANSIToUTF16N(ANSI s, int n);
ANSI  WB_UTF16ToANSIN(UTF16 s, int n);

// methods for runtime
errno WB_Uninstall();

// hard encoded address in getModulePointer for replacement
#ifdef _WIN64
    #define MODULE_POINTER 0x7FABCDEF111111E1
#elif _WIN32
    #define MODULE_POINTER 0x7FABCDE1
#endif
static WinBase* getModulePointer();

static bool initModuleAPI(WinBase* module, Context* context);
static bool updateModulePointer(WinBase* module);
static bool recoverModulePointer(WinBase* module);
static bool initModuleEnvironment(WinBase* module, Context* context);
static void eraseModuleMethods(Context* context);

WinBase_M* InitWinBase(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr moduleAddr = address + 16384 + RandUintN(address, 128);
    uintptr methodAddr = address + 17000 + RandUintN(address, 128);
    // initialize module
    WinBase* module = (WinBase*)moduleAddr;
    mem_init(module, sizeof(WinBase));
    // store options
    module->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initModuleAPI(module, context))
        {
            errno = ERR_WIN_BASE_INIT_API;
            break;
        }
        if (!updateModulePointer(module))
        {
            errno = ERR_WIN_BASE_UPDATE_PTR;
            break;
        }
        if (!initModuleEnvironment(module, context))
        {
            errno = ERR_WIN_BASE_INIT_ENV;
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
    WinBase_M* method = (WinBase_M*)methodAddr;
    method->ANSIToUTF16  = GetFuncAddr(&WB_ANSIToUTF16);
    method->UTF16ToANSI  = GetFuncAddr(&WB_UTF16ToANSI);
    method->ANSIToUTF16N = GetFuncAddr(&WB_ANSIToUTF16N);
    method->UTF16ToANSIN = GetFuncAddr(&WB_UTF16ToANSIN);
    method->Uninstall    = GetFuncAddr(&WB_Uninstall);
    return method;
}

static bool initModuleAPI(WinBase* module, Context* context)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xFECF5D77CC76C334, 0x3291C4717151B366}, // MultiByteToWideChar
        { 0x32C7684AB4B518B6, 0x0C4F51C8DCCC447D}, // WideCharToMultiByte
    };
#elif _WIN32
    {
        { 0x68A627A6, 0x4087B044}, // MultiByteToWideChar
        { 0x4F572177, 0x5F4B7BE1}, // WideCharToMultiByte
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
    module->MultiByteToWideChar = list[0].proc;
    module->WideCharToMultiByte = list[1].proc;
    // skip warning
    context = NULL;
    return true;
}

// CANNOT merge updateModulePointer and recoverModulePointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

static bool updateModulePointer(WinBase* module)
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

static bool recoverModulePointer(WinBase* module)
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

static bool initModuleEnvironment(WinBase* module, Context* context)
{
    module->malloc  = context->mt_malloc;
    module->calloc  = context->mt_calloc;
    module->realloc = context->mt_realloc;
    module->free    = context->mt_free;
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
static WinBase* getModulePointer()
{
    uintptr pointer = MODULE_POINTER;
    return (WinBase*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
UTF16 WB_ANSIToUTF16(ANSI s)
{
    return WB_ANSIToUTF16N(s, -1);
}

__declspec(noinline)
ANSI WB_UTF16ToANSI(UTF16 s)
{
    return WB_UTF16ToANSIN(s, -1);
}

__declspec(noinline)
UTF16 WB_ANSIToUTF16N(ANSI s, int n)
{
    WinBase* module = getModulePointer();

    int len = module->MultiByteToWideChar(CP_ACP, 0, s, n, NULL, 0);
    if (len == 0)
    {
        return NULL;
    }
    UTF16 str = module->malloc((uint)(len * 2));
    if (str == NULL)
    {
        return NULL;
    }
    len = module->MultiByteToWideChar(CP_ACP, 0, s, n, str, len);
    if (len == 0)
    {
        module->free(str);
        return NULL;
    }
    return str;
}

__declspec(noinline)
ANSI WB_UTF16ToANSIN(UTF16 s, int n)
{
    WinBase* module = getModulePointer();

    int len = module->WideCharToMultiByte(CP_ACP, 0, s, n, NULL, 0, NULL, NULL);
    if (len == 0)
    {
        return NULL;
    }
    ANSI str = module->malloc(len);
    if (str == NULL)
    {
        return NULL;
    }
    len = module->WideCharToMultiByte(CP_ACP, 0, s, n, str, len, NULL, NULL);
    if (len == 0)
    {
        module->free(str);
        return NULL;
    }
    return str;
}

__declspec(noinline)
errno WB_Uninstall()
{
    WinBase* module = getModulePointer();

    errno errno = NO_ERROR;

    // recover instructions
    if (module->NotEraseInstruction)
    {
        if (!recoverModulePointer(module) && errno == NO_ERROR)
        {
            errno = ERR_WIN_BASE_RECOVER_INST;
        }
    }
    return errno;
}
