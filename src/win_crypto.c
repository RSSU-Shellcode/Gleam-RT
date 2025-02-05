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
    CryptAcquireContextA_t  CryptAcquireContextA;
    CryptReleaseContext_t   CryptReleaseContext;
    CryptGenRandom_t        CryptGenRandom;
    CryptGenKey_t           CryptGenKey;
    CryptDeriveKey_t        CryptDeriveKey;
    CryptExportKey_t        CryptExportKey;
    CryptCreateHash_t       CryptCreateHash;
    CryptHashData_t         CryptHashData;
    CryptGetHashParam_t     CryptGetHashParam;
    CryptDestroyHash_t      CryptDestroyHash;
    CryptImportKey_t        CryptImportKey;
    CryptSetKeyParam_t      CryptSetKeyParam;
    CryptEncrypt_t          CryptEncrypt;
    CryptDecrypt_t          CryptDecrypt;
    CryptDestroyKey_t       CryptDestroyKey;
    CryptSignHashA_t        CryptSignHashA;
    CryptVerifySignatureA_t CryptVerifySignatureA;

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
errno WC_AESEncrypt(databuf* data, databuf* key, databuf* out);
errno WC_AESDecrypt(databuf* data, databuf* key, databuf* out);
errno WC_RSAGenKey(uint usage, uint bits, databuf* key);
errno WC_RSASign(databuf* data, databuf* key, databuf* sign);
errno WC_RSAVerify(databuf* data, databuf* key, databuf* sign);
errno WC_RSAEncrypt(databuf* data, databuf* key, databuf* out);
errno WC_RSADecrypt(databuf* data, databuf* key, databuf* out);

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
    method->AESEncrypt = GetFuncAddr(&WC_AESEncrypt);
    method->AESDecrypt = GetFuncAddr(&WC_AESDecrypt);
    method->RSAGenKey  = GetFuncAddr(&WC_RSAGenKey);
    method->RSASign    = GetFuncAddr(&WC_RSASign);
    method->RSAVerify  = GetFuncAddr(&WC_RSAVerify);
    method->RSAEncrypt = GetFuncAddr(&WC_RSAEncrypt);
    method->RSADecrypt = GetFuncAddr(&WC_RSADecrypt);
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
        // decrypt to "advapi32.dll\0"
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
        { 0x7139781045860379, 0xD9B823C41B31892D }, // CryptGenKey
        { 0x75F125EA08848F34, 0x8F77BCC6829BD0A4 }, // CryptDeriveKey
        { 0xFBD14E610ABC19B0, 0x427A278C5526F497 }, // CryptExportKey
        { 0xCA46DCB36C8EF17A, 0xEDEA67BFCC8F2970 }, // CryptCreateHash
        { 0x08F3ADAD64028885, 0xFF7C7DF5E4A9283F }, // CryptHashData
        { 0x76F8459880F8ACF9, 0x252C1D935020E9D4 }, // CryptGetHashParam
        { 0x2003C9A7DB794999, 0x0E51E1688FD1869E }, // CryptDestroyHash
        { 0x8D1E49656BB1E55E, 0x7EF987CE7272029B }, // CryptImportKey
        { 0x3D31DE5787EA688F, 0xB851328C0A45FBD2 }, // CryptSetKeyParam
        { 0x56C8B4615CEA5713, 0x3ACD65C055BEF2C6 }, // CryptEncrypt
        { 0x9AEECF188C0A6B15, 0xEFCD0584199F194B }, // CryptDecrypt
        { 0x5C0D6B76D2524A1F, 0x6B665445585C1AB4 }, // CryptDestroyKey
        { 0xAFF4E2EFE83F7659, 0xD46F801C7B1A139A }, // CryptSignHashA
        { 0xBCB00320DFAF3AD3, 0xEF345CBEAAB6E545 }, // CryptVerifySignatureA
    };
#elif _WIN32
    {
        { 0x8999214A, 0x46521BDF }, // CryptAcquireContextA
        { 0x201C2004, 0x435A9F1B }, // CryptReleaseContext
        { 0x608C5DA1, 0xE9C08140 }, // CryptGenRandom
        { 0x9EDA4CE2, 0x1D81FE5F }, // CryptGenKey
        { 0x630E8D56, 0xAE61AFD0 }, // CryptDeriveKey
        { 0x1F7F51F7, 0x38675FE9 }, // CryptExportKey
        { 0xAC10214C, 0x745E27FB }, // CryptCreateHash
        { 0x34BF08ED, 0x2C655EC2 }, // CryptHashData
        { 0x5D3903BA, 0x461539AA }, // CryptGetHashParam
        { 0x599DEAEE, 0xB4B75228 }, // CryptDestroyHash
        { 0xF6111932, 0x31A2ABE4 }, // CryptImportKey
        { 0x847508E7, 0xBAA59832 }, // CryptSetKeyParam
        { 0x8D308D6A, 0x5F981D82 }, // CryptEncrypt
        { 0xC3B016FD, 0x2645198B }, // CryptDecrypt
        { 0x140AED46, 0xD877FFE7 }, // CryptDestroyKey
        { 0xBF957CE6, 0xD014705B }, // CryptSignHashA
        { 0x03911C87, 0x1DEA20BD }, // CryptVerifySignatureA
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
    module->CryptAcquireContextA  = list[0x00].proc;
    module->CryptReleaseContext   = list[0x01].proc;
    module->CryptGenRandom        = list[0x02].proc;
    module->CryptGenKey           = list[0x03].proc;
    module->CryptDeriveKey        = list[0x04].proc;
    module->CryptExportKey        = list[0x05].proc;
    module->CryptCreateHash       = list[0x06].proc;
    module->CryptHashData         = list[0x07].proc;
    module->CryptGetHashParam     = list[0x08].proc;
    module->CryptDestroyHash      = list[0x09].proc;
    module->CryptImportKey        = list[0x0A].proc;
    module->CryptSetKeyParam      = list[0x0B].proc;
    module->CryptEncrypt          = list[0x0C].proc;
    module->CryptDecrypt          = list[0x0D].proc;
    module->CryptDestroyKey       = list[0x0E].proc;
    module->CryptSignHashA        = list[0x0F].proc;
    module->CryptVerifySignatureA = list[0x10].proc;
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
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
        )){
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
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
        )){
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
        DWORD hashLen = WC_SHA1_HASH_SIZE;
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
errno WC_AESEncrypt(databuf* data, databuf* key, databuf* out)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "AESEncrypt: 0x%zX, 0x%zX, 0x%zX", data, key, out);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    byte* output = NULL;
    uint  length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // build exportable AES key with PLAINTEXTKEY
        byte buf[sizeof(AESKEYHEADER) + 32];
        mem_init(buf, sizeof(buf));
        AESKEYHEADER* header = (AESKEYHEADER*)buf;
        header->header.bType    = PLAINTEXTKEYBLOB;
        header->header.bVersion = CUR_BLOB_VERSION;
        header->header.reserved = 0;
        switch (key->len)
        {
        case 16:
            header->header.aiKeyAlg = CALG_AES_128;
            break;
        case 24:
            header->header.aiKeyAlg = CALG_AES_192;
            break;
        case 32:
            header->header.aiKeyAlg = CALG_AES_256;
            break;
        }
        header->dwKeySize = (DWORD)(key->len);
        mem_copy(buf + sizeof(AESKEYHEADER), key->buf, key->len);
        // import AES key to context
        if (!module->CryptImportKey(hProv, buf, sizeof(buf), NULL, CRYPT_EXPORTABLE, &hKey))
        {
            break;
        }
        // set mode and padding method
        DWORD dwParam = CRYPT_MODE_CBC;
        if (!module->CryptSetKeyParam(hKey, KP_MODE, (BYTE*)(&dwParam), 0))
        {
            break;
        }
        dwParam = PKCS5_PADDING;
        if (!module->CryptSetKeyParam(hKey, KP_PADDING, (BYTE*)(&dwParam), 0))
        {
            break;
        }
        // allocate buffer and copy plain data
        length = WC_AES_IV_SIZE + (data->len / WC_AES_BLOCK_SIZE + 1) * WC_AES_BLOCK_SIZE;
        output = module->malloc(length);
        mem_copy(output + WC_AES_IV_SIZE, data->buf, data->len);
        // generate random IV and set it
        if (!module->CryptGenRandom(hProv, WC_AES_IV_SIZE, output))
        {
            break;
        }
        if (!module->CryptSetKeyParam(hKey, KP_IV, output, 0))
        {
            break;
        }
        // encrypt data
        DWORD inputLen = (DWORD)(data->len);
        DWORD dataLen  = (DWORD)length - WC_AES_IV_SIZE;
        if (!module->CryptEncrypt(
            hKey, NULL, true, 0, output + WC_AES_IV_SIZE, &inputLen, dataLen
        )){
            break;
        }
        success = true;
        break;
    }
    errno lastErr = GetLastErrno();

    if (hKey != NULL)
    {
        module->CryptDestroyKey(hKey);
    }
    if (hProv != NULL)
    {
        module->CryptReleaseContext(hProv, 0);
    }

    if (!success)
    {
        module->free(output);
        return lastErr;
    }
    out->buf = output;
    out->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_AESDecrypt(databuf* data, databuf* key, databuf* out)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "AESDecrypt: 0x%zX, 0x%zX, 0x%zX", data, key, out);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    byte* output = NULL;
    uint  length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // build exportable AES key with PLAINTEXTKEY
        byte buf[sizeof(AESKEYHEADER) + 32];
        mem_init(buf, sizeof(buf));
        AESKEYHEADER* header = (AESKEYHEADER*)buf;
        header->header.bType    = PLAINTEXTKEYBLOB;
        header->header.bVersion = CUR_BLOB_VERSION;
        header->header.reserved = 0;
        switch (key->len)
        {
        case 16:
            header->header.aiKeyAlg = CALG_AES_128;
            break;
        case 24:
            header->header.aiKeyAlg = CALG_AES_192;
            break;
        case 32:
            header->header.aiKeyAlg = CALG_AES_256;
            break;
        }
        header->dwKeySize = (DWORD)(key->len);
        mem_copy(buf + sizeof(AESKEYHEADER), key->buf, key->len);
        // import AES key to context
        if (!module->CryptImportKey(hProv, buf, sizeof(buf), NULL, CRYPT_EXPORTABLE, &hKey))
        {
            break;
        }
        // set mode and padding method
        DWORD dwParam = CRYPT_MODE_CBC;
        if (!module->CryptSetKeyParam(hKey, KP_MODE, (BYTE*)(&dwParam), 0))
        {
            break;
        }
        dwParam = PKCS5_PADDING;
        if (!module->CryptSetKeyParam(hKey, KP_PADDING, (BYTE*)(&dwParam), 0))
        {
            break;
        }
        // set IV from the prefix of data
        if (!module->CryptSetKeyParam(hKey, KP_IV, data->buf, 0))
        {
            break;
        }
        // copy cipher data and decrypt it
        byte* src = (byte*)(data->buf) + WC_AES_IV_SIZE;
        uint  len = data->len - WC_AES_IV_SIZE;
        output = module->malloc(len);
        mem_copy(output, src, len);
        DWORD plainLen = (DWORD)len;
        if (!module->CryptDecrypt(hKey, NULL, true, 0, output, &plainLen))
        {
            break;
        }
        length = plainLen;
        success = true;
        break;
    }
    errno lastErr = GetLastErrno();

    if (hKey != NULL)
    {
        module->CryptDestroyKey(hKey);
    }
    if (hProv != NULL)
    {
        module->CryptReleaseContext(hProv, 0);
    }

    if (!success)
    {
        module->free(output);
        return lastErr;
    }
    out->buf = output;
    out->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_RSAGenKey(uint usage, uint bits, databuf* key)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RSAGenKey: %d, %zu", usage, bits);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    byte* output = NULL;
    uint  length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        ALG_ID algID = 0;
        switch (usage)
        {
        case WC_RSA_KEY_USAGE_SIGN:
            algID = CALG_RSA_SIGN;
            break;
        case WC_RSA_KEY_USAGE_KEYX:
            algID = CALG_RSA_KEYX;
            break;
        default:
            SetLastErrno(ERR_WIN_CRYPTO_INVALID_KEY_USAGE);
            break;
        }
        DWORD flags = (DWORD)bits << 16 | CRYPT_EXPORTABLE;
        if (!module->CryptGenKey(hProv, algID, flags, &hKey))
        {
            break;
        }
        DWORD outputLen;
        if (!module->CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, NULL, &outputLen))
        {
            break;
        }
        output = module->malloc(outputLen);
        if (!module->CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, output, &outputLen))
        {
            break;
        }
        length = outputLen;
        success = true;
        break;
    }
    errno lastErr = GetLastErrno();

    if (hKey != NULL)
    {
        module->CryptDestroyKey(hKey);
    }
    if (hProv != NULL)
    {
        module->CryptReleaseContext(hProv, 0);
    }

    if (!success)
    {
        module->free(output);
        return lastErr;
    }
    key->buf = output;
    key->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_RSASign(databuf* data, databuf* key, databuf* sign)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RSASign: 0x%zX, 0x%zX, 0x%zX", data, key, sign);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    HCRYPTHASH hHash = NULL;
    byte* output = NULL;
    DWORD length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // import private key to context
        if (!module->CryptImportKey(
            hProv, key->buf, (DWORD)(key->len), NULL, CRYPT_EXPORTABLE, &hKey
        )){
            break;
        }
        // calculate hash of data
        if (!module->CryptCreateHash(hProv, CALG_SHA1, NULL, 0, &hHash))
        {
            break;
        }
        if (!module->CryptHashData(hHash, data->buf, (DWORD)(data->len), 0))
        {
            break;
        }
        byte  hash[WC_SHA1_HASH_SIZE];
        DWORD hashLen = sizeof(hash);
        if (!module->CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
        {
            break;
        }
        // get message signature length
        if (!module->CryptSignHashA(hHash, AT_SIGNATURE, NULL, 0, NULL, &length))
        {
            break;
        }
        // sign message
        output = module->malloc(length);
        if (!module->CryptSignHashA(hHash, AT_SIGNATURE, NULL, 0, output, &length))
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
    if (hKey != NULL)
    {
        module->CryptDestroyKey(hKey);
    }
    if (hProv != NULL)
    {
        module->CryptReleaseContext(hProv, 0);
    }

    if (!success)
    {
        module->free(output);
        return lastErr;
    }
    sign->buf = output;
    sign->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_RSAVerify(databuf* data, databuf* key, databuf* sign)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RSAVerify: 0x%zX, 0x%zX, 0x%zX", data, key, sign);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    HCRYPTHASH hHash = NULL;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // import public key to context
        if (!module->CryptImportKey(
            hProv, key->buf, (DWORD)(key->len), NULL, CRYPT_EXPORTABLE, &hKey
        )){
            break;
        }
        // calculate hash of data
        if (!module->CryptCreateHash(hProv, CALG_SHA1, NULL, 0, &hHash))
        {
            break;
        }
        if (!module->CryptHashData(hHash, data->buf, (DWORD)(data->len), 0))
        {
            break;
        }
        byte  hash[WC_SHA1_HASH_SIZE];
        DWORD hashLen = sizeof(hash);
        if (!module->CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
        {
            break;
        }
        // verify signature about data hash
        if (!module->CryptVerifySignatureA(
            hHash, sign->buf, (DWORD)(sign->len), hKey, NULL, 0
        )){
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
    if (hKey != NULL)
    {
        module->CryptDestroyKey(hKey);
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
errno WC_RSAEncrypt(databuf* data, databuf* key, databuf* out)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RSAEncrypt: 0x%zX, 0x%zX, 0x%zX", data, key, out);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    byte* output = NULL;
    uint  length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // import RSA public key to context
        if (!module->CryptImportKey(
            hProv, key->buf, (DWORD)(key->len), NULL, CRYPT_EXPORTABLE, &hKey
        )){
            break;
        }
        // calculate the cipher data size
        DWORD outputLen = (DWORD)(data->len);
        if (!module->CryptEncrypt(hKey, NULL, true, 0, NULL, &outputLen, 0))
        {
            break;
        }
        // allocate buffer and copy plain data
        output = module->malloc(outputLen);
        mem_copy(output, data->buf, data->len);
        // encrypt data
        DWORD inputLen = (DWORD)(data->len);
        if (!module->CryptEncrypt(hKey, NULL, true, 0, output, &inputLen, outputLen))
        {
            break;
        }
        length = outputLen;
        success = true;
        break;
    }
    errno lastErr = GetLastErrno();

    if (hKey != NULL)
    {
        module->CryptDestroyKey(hKey);
    }
    if (hProv != NULL)
    {
        module->CryptReleaseContext(hProv, 0);
    }

    if (!success)
    {
        module->free(output);
        return lastErr;
    }
    out->buf = output;
    out->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_RSADecrypt(databuf* data, databuf* key, databuf* out)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RSADecrypt: 0x%zX, 0x%zX, 0x%zX", data, key, out);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    byte* output = NULL;
    uint  length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // import RSA private key to context
        if (!module->CryptImportKey(
            hProv, key->buf, (DWORD)(key->len), NULL, CRYPT_EXPORTABLE, &hKey
        )){
            break;
        }
        // copy cipher data and decrypt it
        output = module->malloc(data->len);
        mem_copy(output, data->buf, data->len);
        DWORD plainLen = (DWORD)(data->len);
        if (!module->CryptDecrypt(hKey, NULL, true, 0, output, &plainLen))
        {
            break;
        }
        length = plainLen;
        success = true;
        break;
    }
    errno lastErr = GetLastErrno();

    if (hKey != NULL)
    {
        module->CryptDestroyKey(hKey);
    }
    if (hProv != NULL)
    {
        module->CryptReleaseContext(hProv, 0);
    }

    if (!success)
    {
        module->free(output);
        return lastErr;
    }
    out->buf = output;
    out->len = length;
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
