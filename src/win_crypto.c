#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_advapi32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "context.h"
#include "random.h"
#include "errno.h"
#include "win_crypto.h"
#include "debug.h"

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    CryptAcquireContextA_t CryptAcquireContextA;
    CryptReleaseContext_t  CryptReleaseContext;
    CryptGenRandom_t       CryptGenRandom;
    CryptCreateHash_t      CryptCreateHash;
    CryptHashData_t        CryptHashData;
    CryptGetHashParam_t    CryptGetHashParam;
    CryptDestroyHash_t     CryptDestroyHash;

    LoadLibraryA_t        LoadLibraryA;
    FreeLibrary_t         FreeLibrary;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;

    // submodules method
    mt_malloc_t  malloc;
    mt_calloc_t  calloc;
    mt_realloc_t realloc;
    mt_free_t    free;
    mt_msize_t   msize;
} WinCrypto;

// methods for user
void WC_RandBuffer(byte* data, uint len);
void WC_SHA1(byte* data, uint len, byte* hash);

// methods for runtime
errno WC_Uninstall();

// hard encoded address in getModulePointer for replacement
#ifdef _WIN64
    #define MODULE_POINTER 0x7FABCDEF111111E4
#elif _WIN32
    #define MODULE_POINTER 0x7FABCDE4
#endif
static WinCrypto* getModulePointer();

static bool initModuleAPI(WinCrypto* module, Context* context);
static bool updateModulePointer(WinCrypto* module);
static bool recoverModulePointer(WinCrypto* module);
static bool initModuleEnvironment(WinCrypto* module, Context* context);
static void eraseModuleMethods(Context* context);

WinCrypto_M* InitWinCrypto(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr moduleAddr = address + 22000 + RandUintN(address, 128);
    uintptr methodAddr = address + 23000 + RandUintN(address, 128);
    // initialize module
    WinCrypto* module = (WinCrypto*)moduleAddr;
    mem_init(module, sizeof(WinCrypto));
    // store options
    module->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initModuleAPI(module, context))
        {
            errno = ERR_WIN_CRYPTO_INIT_API;
            break;
        }
        if (!updateModulePointer(module))
        {
            errno = ERR_WIN_CRYPTO_UPDATE_PTR;
            break;
        }
        if (!initModuleEnvironment(module, context))
        {
            errno = ERR_WIN_CRYPTO_INIT_ENV;
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
    // methods for user
    WinCrypto_M* method = (WinCrypto_M*)methodAddr;
    method->RandBuffer = GetFuncAddr(&WC_RandBuffer);
    method->SHA1       = GetFuncAddr(&WC_SHA1);
    // methods for runtime
    method->Uninstall = GetFuncAddr(&WC_Uninstall);
    return method;
}
