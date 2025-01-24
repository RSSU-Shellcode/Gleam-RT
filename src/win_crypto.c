#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_advapi32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
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

    // protect data
    HMODULE hModule; // advapi32.dll
    HANDLE  hMutex;  // global mutex
} WinCrypto;

// methods for user
errno WC_RandBuffer(byte* data, uint len);
errno WC_SHA1(byte* data, uint len, byte* hash);

// methods for runtime
errno WC_Uninstall();

// hard encoded address in getModulePointer for replacement
#ifdef _WIN64
    #define MODULE_POINTER 0x7FABCDEF111111E4
#elif _WIN32
    #define MODULE_POINTER 0x7FABCDE4
#endif
static WinCrypto* getModulePointer();

static bool wc_lock();
static bool wc_unlock();

static bool initModuleAPI(WinCrypto* module, Context* context);
static bool updateModulePointer(WinCrypto* module);
static bool recoverModulePointer(WinCrypto* module);
static bool initModuleEnvironment(WinCrypto* module, Context* context);
static void eraseModuleMethods(Context* context);

static bool initWinCryptoEnv();
static bool findWinCryptoAPI();

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

static bool initModuleAPI(WinCrypto* module, Context* context)
{
    module->LoadLibraryA        = context->LoadLibraryA;
    module->FreeLibrary         = context->FreeLibrary;
    module->ReleaseMutex        = context->ReleaseMutex;
    module->WaitForSingleObject = context->WaitForSingleObject;
    module->CloseHandle         = context->CloseHandle;
    return true;
}

// CANNOT merge updateModulePointer and recoverModulePointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

static bool updateModulePointer(WinCrypto* module)
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

static bool recoverModulePointer(WinCrypto* module)
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

static bool initModuleEnvironment(WinCrypto* module, Context* context)
{
    // create global mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    module->hMutex = hMutex;
    // copy submodule methods
    module->malloc  = context->mt_malloc;
    module->calloc  = context->mt_calloc;
    module->realloc = context->mt_realloc;
    module->free    = context->mt_free;
    module->msize   = context->mt_msize;
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
static WinCrypto* getModulePointer()
{
    uintptr pointer = MODULE_POINTER;
    return (WinCrypto*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool wc_lock()
{
    WinCrypto* module = getModulePointer();

    DWORD event = module->WaitForSingleObject(module->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool wc_unlock()
{
    WinCrypto* module = getModulePointer();

    return module->ReleaseMutex(module->hMutex);
}

__declspec(noinline)
static bool initWinCryptoEnv()
{
    WinCrypto* module = getModulePointer();

    if (!wc_lock())
    {
        return false;
    }

    bool success = false;
    for (;;)
    {
        if (module->hModule != NULL)
        {
            success = true;
            break;
        }
        // decrypt to "advapi32.dll"
        byte dllName[] = {
            'a'^0xC4, 'd'^0x79, 'v'^0xF2, 'a'^0x2A, 
            'p'^0xC4, 'i'^0x79, '3'^0xF2, '2'^0x2A, 
            '.'^0xC4, 'd'^0x79, 'l'^0xF2, 'l'^0x2A,
            000^0xC4,
        };
        byte key[] = {0xC4, 0x79, 0xF2, 0x2A};
        XORBuf(dllName, sizeof(dllName), key, sizeof(key));
        // load advapi32.dll
        HMODULE hModule = module->LoadLibraryA(dllName);
        if (hModule == NULL)
        {
            break;
        }
        // prepare API address
        if (!findWinCryptoAPI())
        {
            SetLastErrno(ERR_WIN_CRYPTO_API_NOT_FOUND);
            module->FreeLibrary(hModule);
            break;
        }
        module->hModule = hModule;
        success = true;
        break;
    }

    if (!wc_unlock())
    {
        return false;
    }
    return success;
}

static bool findWinCryptoAPI()
{
    WinCrypto* module = getModulePointer();

    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x229A36DB5A153884, 0x5C8D8943760A0AD5 }, // CryptAcquireContextA
        { 0xC8A4ABEFC4A15414, 0xDCD358FAAA9AD697 }, // CryptReleaseContext
        { 0x052D13759C233989, 0xD129B99F2DE11CE1 }, // CryptGenRandom
        { 0xCA46DCB36C8EF17A, 0xEDEA67BFCC8F2970 }, // CryptCreateHash
        { 0x08F3ADAD64028885, 0xFF7C7DF5E4A9283F }, // CryptHashData
        { 0x76F8459880F8ACF9, 0x252C1D935020E9D4 }, // CryptGetHashParam
        { 0x2003C9A7DB794999, 0x0E51E1688FD1869E }, // CryptDestroyHash
    };
#elif _WIN32
    {
        { 0x8999214A, 0x46521BDF }, // CryptAcquireContextA
        { 0x201C2004, 0x435A9F1B }, // CryptReleaseContext
        { 0x608C5DA1, 0xE9C08140 }, // CryptGenRandom
        { 0xAC10214C, 0x745E27FB }, // CryptCreateHash
        { 0x34BF08ED, 0x2C655EC2 }, // CryptHashData
        { 0x5D3903BA, 0x461539AA }, // CryptGetHashParam
        { 0x599DEAEE, 0xB4B75228 }, // CryptDestroyHash
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
    module->CryptAcquireContextA = list[0x00].proc;
    module->CryptReleaseContext  = list[0x01].proc;
    module->CryptGenRandom       = list[0x02].proc;
    module->CryptCreateHash      = list[0x03].proc;
    module->CryptHashData        = list[0x04].proc;
    module->CryptGetHashParam    = list[0x05].proc;
    module->CryptDestroyHash     = list[0x06].proc; 
    return true;
}

__declspec(noinline)
errno WC_RandBuffer(byte* data, uint len)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RandBuffer: 0x%zX, %zu", data, len);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;

    bool success = false;
    for (;;)
    {
        bool ok = module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
        );
        if (!ok)
        {
            break;
        }
        if (!module->CryptGenRandom(hProv, (DWORD)len, data))
        {
            break;
        }
        success = true;
        break;
    }
    errno lastErr = GetLastErrno();

    if (hProv != NULL)
    {
        module->CryptReleaseContext(hProv, 0);
    }

    if (!success)
    {
        return lastErr;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno WC_SHA1(byte* data, uint len, byte* hash)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "SHA1: 0x%zX, %zu", data, len);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;

    bool success = false;
    for (;;)
    {
        bool ok = module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
        );
        if (!ok)
        {
            break;
        }
        if (!module->CryptCreateHash(hProv, CALG_SHA1, NULL, 0, &hHash))
        {
            break;
        }
        if (!module->CryptHashData(hHash, data, (DWORD)len, 0))
        {
            break;
        }
        DWORD hashLen;
        if (!module->CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
        {
            break;
        }
        success = true;
        break;
    }
    errno lastErr = GetLastErrno();

    if (hHash != NULL)
    {
        module->CryptDestroyHash(hHash);
    }
    if (hProv != NULL)
    {
        module->CryptReleaseContext(hProv, 0);
    }

    if (!success)
    {
        return lastErr;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno WC_Uninstall()
{
    WinCrypto* module = getModulePointer();

    errno errno = NO_ERROR;

    // free advapi32.dll
    if (module->hModule != NULL)
    {
        if (!module->FreeLibrary(module->hModule) && errno == NO_ERROR)
        {
            errno = ERR_WIN_CRYPTO_FREE_LIBRARY;
        }
    }

    // close mutex
    if (!module->CloseHandle(module->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_WIN_CRYPTO_CLOSE_MUTEX;
    }

    // recover instructions
    if (module->NotEraseInstruction)
    {
        if (!recoverModulePointer(module) && errno == NO_ERROR)
        {
            errno = ERR_WIN_CRYPTO_RECOVER_INST;
        }
    }
    return errno;
}
