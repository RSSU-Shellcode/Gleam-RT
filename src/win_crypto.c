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

    // store environment
    void* IMOML;

    // API addresses
    CryptAcquireContextA_t  CryptAcquireContextA;
    CryptReleaseContext_t   CryptReleaseContext;
    CryptGenRandom_t        CryptGenRandom;
    CryptGenKey_t           CryptGenKey;
    CryptExportKey_t        CryptExportKey;
    CryptCreateHash_t       CryptCreateHash;
    CryptSetHashParam_t     CryptSetHashParam;
    CryptGetHashParam_t     CryptGetHashParam;
    CryptHashData_t         CryptHashData;
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
errno WC_RandBuffer(databuf* data);
errno WC_Hash(ALG_ID aid, databuf* data, databuf* hash);
errno WC_HMAC(ALG_ID aid, databuf* data, databuf* key, databuf* hash);
errno WC_AESEncrypt(databuf* data, databuf* key, databuf* output);
errno WC_AESDecrypt(databuf* data, databuf* key, databuf* output);
errno WC_RSAGenKey(uint usage, uint bits, databuf* key);
errno WC_RSAPubKey(databuf* key, databuf* output);
errno WC_RSASign(ALG_ID aid, databuf* data, databuf* key, databuf* signature);
errno WC_RSAVerify(ALG_ID aid, databuf* data, databuf* key, databuf* signature);
errno WC_RSAEncrypt(databuf* data, databuf* key, databuf* output);
errno WC_RSADecrypt(databuf* data, databuf* key, databuf* output);

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

static errno isValidRSAPrivateKey(databuf* key);
static errno isValidRSAPublicKey(databuf* key);

WinCrypto_M* InitWinCrypto(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr moduleAddr = address + 22000 + RandUintN(address, 128);
    uintptr methodAddr = address + 23000 + RandUintN(address, 128);
    // allocate module memory
    WinCrypto* module = (WinCrypto*)moduleAddr;
    mem_init(module, sizeof(WinCrypto));
    // store options
    module->NotEraseInstruction = context->NotEraseInstruction;
    // store environment
    module->IMOML = context->IMOML;
    // initialize module
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
    method->Hash       = GetFuncAddr(&WC_Hash);
    method->HMAC       = GetFuncAddr(&WC_HMAC);
    method->AESEncrypt = GetFuncAddr(&WC_AESEncrypt);
    method->AESDecrypt = GetFuncAddr(&WC_AESDecrypt);
    method->RSAGenKey  = GetFuncAddr(&WC_RSAGenKey);
    method->RSAPubKey  = GetFuncAddr(&WC_RSAPubKey);
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
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_WIN_CRYPTO_MUTEX);
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
        uint mHash; uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xB6F03004CD357474, 0xA351B02C407D69CC, 0xDD7D00B830A394FC }, // CryptAcquireContextA
        { 0x8A9FC9ED17AEC71C, 0x41AC4A30D20E8B2E, 0x96556E657055BDA9 }, // CryptReleaseContext
        { 0x3A1784CBE54B0BA4, 0x1B55DEBA9D6933F1, 0x6825FB594E8F80A8 }, // CryptGenRandom
        { 0xF884FA6B7F026840, 0xE7B2EB87FFEFBFD9, 0xA53E8656CF8E08E9 }, // CryptGenKey
        { 0xF9BC05DA31E3EBC1, 0x3C4A4F16EA243D9B, 0x0AF2AB242BB0FDEF }, // CryptExportKey
        { 0x310476309F1DC16F, 0x524072F2DF4E467D, 0x088DB8077AE3C86A }, // CryptCreateHash
        { 0x211744E8281B5C93, 0xC8AC1AF2337010F2, 0x2FCAA3A4CA39D3B5 }, // CryptSetHashParam
        { 0x12DB3C697FB240FB, 0xB37F8BC073D55030, 0x0E2E3591487BC537 }, // CryptGetHashParam
        { 0x04B6E067AE35CEF7, 0xE009015BBB558D1E, 0x99DCA0D4D95616B5 }, // CryptHashData
        { 0xD0850B88090F8D81, 0x1ECFE1493FF6DE12, 0xAF82AA225567AA48 }, // CryptDestroyHash
        { 0xEE7DE621C28FA074, 0x41252C966AB64519, 0xC4FDE9574C0B980D }, // CryptImportKey
        { 0xA6B92B9EDED891B3, 0xBBC77F4D4C9F6622, 0x128791C921FC7F3D }, // CryptSetKeyParam
        { 0x7877D5D429180A3E, 0xEA409B53F00E75B3, 0xC10D507F5B675A5A }, // CryptEncrypt
        { 0xDF51786F7585A937, 0x6EB2FB49A3EA8901, 0x23ACC4ADF57F71C8 }, // CryptDecrypt
        { 0x81A9DD1891A0B37D, 0xBCA59C1124951985, 0x5C3EF6F56744B1E2 }, // CryptDestroyKey
        { 0xCE673261B7235F0C, 0xE5F99AB76164C991, 0xD92E0734B071DFDA }, // CryptSignHashA
        { 0xEA2B2384AFD2A96D, 0xB475E30ADAA479D9, 0xEE5CE4DB4859F811 }, // CryptVerifySignatureA
    };
#elif _WIN32
    {
        { 0x5985FEC7, 0x070B9EB5, 0xBEAFA370 }, // CryptAcquireContextA
        { 0x2A0E7859, 0xE5E4A413, 0x046D26C1 }, // CryptReleaseContext
        { 0xA7DB5AA9, 0x73CF8409, 0x830D3537 }, // CryptGenRandom
        { 0xDF1BE7D0, 0xDDD40A08, 0x10874E83 }, // CryptGenKey
        { 0xB09C8CFE, 0x76DF4FAD, 0xA4762C49 }, // CryptExportKey
        { 0x3BB01C54, 0xD9AD5D20, 0x5A153264 }, // CryptCreateHash
        { 0xE15CD1D7, 0x1E66EEE4, 0xB89CB8A4 }, // CryptSetHashParam
        { 0xF1922AC5, 0x2E9C3BD2, 0xB231823C }, // CryptGetHashParam
        { 0xDAB7BBAE, 0xC1394F7F, 0x42FF6BB3 }, // CryptHashData
        { 0x2CBC1294, 0xB5E650E0, 0x18083A06 }, // CryptDestroyHash
        { 0xA38B7321, 0x8F8DA970, 0xA3424AEA }, // CryptImportKey
        { 0x9731631A, 0xCDCA3093, 0x66FC8B85 }, // CryptSetKeyParam
        { 0x354457F3, 0xCDECFAC3, 0xC888E171 }, // CryptEncrypt
        { 0xE9120B1B, 0xC25604AE, 0x9A769A74 }, // CryptDecrypt
        { 0xE687A129, 0x338E62F6, 0xA7909B6F }, // CryptDestroyKey
        { 0x364AECE6, 0xAA2C4959, 0xB21A3BC2 }, // CryptSignHashA
        { 0x4E0660BB, 0xD985014B, 0xD924E471 }, // CryptVerifySignatureA
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item = list[i];
        void*  proc = FindAPI_ML(module->IMOML, item.mHash, item.pHash, item.hKey);
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
    module->CryptExportKey        = list[0x04].proc;
    module->CryptCreateHash       = list[0x05].proc;
    module->CryptSetHashParam     = list[0x06].proc;
    module->CryptGetHashParam     = list[0x07].proc;
    module->CryptHashData         = list[0x08].proc;
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
static errno isValidRSAPrivateKey(databuf* key)
{
    if (key->len < sizeof(RSAPUBKEYHEADER))
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_LENGTH;
    }
    RSAPUBKEYHEADER* hdr = key->buf;
    if (hdr->header.bType != PRIVATEKEYBLOB)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_TYPE;
    }
    if (hdr->header.bVersion != CUR_BLOB_VERSION)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_VERSION;
    }
    ALG_ID aid = hdr->header.aiKeyAlg;
    if (aid != CALG_RSA_SIGN && aid != CALG_RSA_KEYX)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_ALG_ID;
    }
    if (hdr->rsaPubKey.magic != MAGIC_RSA2)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_MAGIC;
    }
    return NO_ERROR;
}

__declspec(noinline)
static errno isValidRSAPublicKey(databuf* key)
{
    if (key->len < sizeof(RSAPUBKEYHEADER))
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_LENGTH;
    }
    RSAPUBKEYHEADER* hdr = key->buf;
    if (hdr->header.bType != PUBLICKEYBLOB)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_TYPE;
    }
    if (hdr->header.bVersion != CUR_BLOB_VERSION)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_VERSION;
    }
    ALG_ID aid = hdr->header.aiKeyAlg;
    if (aid != CALG_RSA_SIGN && aid != CALG_RSA_KEYX)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_ALG_ID;
    }
    if (hdr->rsaPubKey.magic != MAGIC_RSA1)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_MAGIC;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno WC_RandBuffer(databuf* data)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RandBuffer: 0x%zX, %zu", data->buf, data->len);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        if (!module->CryptGenRandom(hProv, (DWORD)(data->len), data->buf))
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
errno WC_Hash(ALG_ID aid, databuf* data, databuf* hash)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "Hash: 0x%X, 0x%zX, %zu", aid, data->buf, data->len);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    void* buffer = NULL;
    DWORD length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        if (!module->CryptCreateHash(hProv, aid, NULL, 0, &hHash))
        {
            break;
        }
        if (!module->CryptHashData(hHash, data->buf, (DWORD)(data->len), 0))
        {
            break;
        }
        if (!module->CryptGetHashParam(hHash, HP_HASHVAL, NULL, &length, 0))
        {
            break;
        }
        buffer = module->malloc(length);
        if (!module->CryptGetHashParam(hHash, HP_HASHVAL, buffer, &length, 0))
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
        module->free(buffer);
        return lastErr;
    }
    hash->buf = buffer;
    hash->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_HMAC(ALG_ID aid, databuf* data, databuf* key, databuf* hash)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "HMAC: 0x%X, 0x%zX, %zu", aid, data->buf, data->len);

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    HCRYPTHASH hHash = NULL;
    void* buffer = NULL;
    DWORD length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // import key to context
        byte buf[sizeof(KEYHEADER) + 128];
        mem_init(buf, sizeof(buf));
        KEYHEADER* header = (KEYHEADER*)buf;
        header->header.bType = PLAINTEXTKEYBLOB;
        header->header.bVersion = CUR_BLOB_VERSION;
        header->header.reserved = 0;
        header->header.aiKeyAlg = CALG_RC2;
        header->dwKeySize = (DWORD)(key->len);
        mem_copy(buf + sizeof(KEYHEADER), key->buf, key->len);
        if (!module->CryptImportKey(
            hProv, buf, sizeof(buf), NULL, CRYPT_IPSEC_HMAC_KEY, &hKey
        )){
            break;
        }
        if (!module->CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash))
        {
            break;
        }
        // set hash algorithm id
        HMAC_INFO info;
        mem_init(&info, sizeof(HMAC_INFO));
        info.HashAlgid = aid;
        if (!module->CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)(&info), 0))
        {
            break;
        }
        if (!module->CryptHashData(hHash, data->buf, (DWORD)(data->len), 0))
        {
            break;
        }
        if (!module->CryptGetHashParam(hHash, HP_HASHVAL, NULL, &length, 0))
        {
            break;
        }
        buffer = module->malloc(length);
        if (!module->CryptGetHashParam(hHash, HP_HASHVAL, buffer, &length, 0))
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
        module->free(buffer);
        return lastErr;
    }
    hash->buf = buffer;
    hash->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_AESEncrypt(databuf* data, databuf* key, databuf* output)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "AESEncrypt: 0x%zX, 0x%zX, 0x%zX", data, key, output);

    // check the data length is valid
    if (data->len < 1)
    {
        return ERR_WIN_CRYPTO_EMPTY_PLAIN_DATA;
    }
    // check the key length is valid
    switch (key->len)
    {
    case 16: case 24: case 32:
        break;
    default:
        return ERR_WIN_CRYPTO_INVALID_KEY_LENGTH;
    }

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    byte* buffer = NULL;
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
        byte buf[sizeof(KEYHEADER) + 32];
        mem_init(buf, sizeof(buf));
        KEYHEADER* header = (KEYHEADER*)buf;
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
        mem_copy(buf + sizeof(KEYHEADER), key->buf, key->len);
        // import AES key to context
        if (!module->CryptImportKey(hProv, buf, sizeof(buf), NULL, 0, &hKey))
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
        buffer = module->malloc(length);
        mem_copy(buffer + WC_AES_IV_SIZE, data->buf, data->len);
        // generate random IV and set it
        if (!module->CryptGenRandom(hProv, WC_AES_IV_SIZE, buffer))
        {
            break;
        }
        if (!module->CryptSetKeyParam(hKey, KP_IV, buffer, 0))
        {
            break;
        }
        // encrypt data
        DWORD inputLen = (DWORD)(data->len);
        DWORD dataLen  = (DWORD)length - WC_AES_IV_SIZE;
        if (!module->CryptEncrypt(
            hKey, NULL, true, 0, buffer + WC_AES_IV_SIZE, &inputLen, dataLen
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
        module->free(buffer);
        return lastErr;
    }
    output->buf = buffer;
    output->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_AESDecrypt(databuf* data, databuf* key, databuf* output)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "AESDecrypt: 0x%zX, 0x%zX, 0x%zX", data, key, output);

    // check the cipher data length is valid
    if (data->len % 16 != 0)
    {
        return ERR_WIN_CRYPTO_INVALID_CIPHER_DATA;
    }
    // check the key length is valid
    switch (key->len)
    {
    case 16: case 24: case 32:
        break;
    default:
        return ERR_WIN_CRYPTO_INVALID_KEY_LENGTH;
    }

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    void* buffer = NULL;
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
        byte buf[sizeof(KEYHEADER) + 32];
        mem_init(buf, sizeof(buf));
        KEYHEADER* header = (KEYHEADER*)buf;
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
        mem_copy(buf + sizeof(KEYHEADER), key->buf, key->len);
        // import AES key to context
        if (!module->CryptImportKey(hProv, buf, sizeof(buf), NULL, 0, &hKey))
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
        buffer = module->malloc(len);
        mem_copy(buffer, src, len);
        DWORD plainLen = (DWORD)len;
        if (!module->CryptDecrypt(hKey, NULL, true, 0, buffer, &plainLen))
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
        module->free(buffer);
        return lastErr;
    }
    output->buf = buffer;
    output->len = length;
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
    void* buffer = NULL;
    uint  length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
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
        buffer = module->malloc(outputLen);
        if (!module->CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, buffer, &outputLen))
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
        module->free(buffer);
        return lastErr;
    }
    key->buf = buffer;
    key->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_RSAPubKey(databuf* key, databuf* output)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RSAPubKey: 0x%zX, 0x%zX", key, output);

    errno err = isValidRSAPrivateKey(key);
    if (err != NO_ERROR)
    {
        return err;
    }

    // export public key from private key
    RSAPUBKEYHEADER* priKey = key->buf;
    uint  length = sizeof(RSAPUBKEYHEADER) + priKey->rsaPubKey.bitlen / 8;
    void* buffer = module->malloc(length);
    mem_copy(buffer, key->buf, length);

    // reset type and magic
    RSAPUBKEYHEADER* pubKey = buffer;
    pubKey->header.bType = PUBLICKEYBLOB;
    pubKey->rsaPubKey.magic = MAGIC_RSA1;

    output->buf = buffer;
    output->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_RSASign(ALG_ID aid, databuf* data, databuf* key, databuf* signature)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RSASign: 0x%zX, 0x%zX, 0x%zX", data, key, signature);

    if (data->len < 1)
    {
        return ERR_WIN_CRYPTO_EMPTY_MESSAGE;
    }

    errno err = isValidRSAPrivateKey(key);
    if (err != NO_ERROR)
    {
        return err;
    }
    RSAPUBKEYHEADER* hdr = key->buf;
    if (hdr->header.aiKeyAlg != CALG_RSA_SIGN)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_ALG_ID;
    }

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    HCRYPTHASH hHash = NULL;
    void* buffer = NULL;
    DWORD length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // import private key to context
        if (!module->CryptImportKey(hProv, key->buf, (DWORD)(key->len), NULL, 0, &hKey))
        {
            break;
        }
        // calculate hash of data
        if (!module->CryptCreateHash(hProv, aid, NULL, 0, &hHash))
        {
            break;
        }
        if (!module->CryptHashData(hHash, data->buf, (DWORD)(data->len), 0))
        {
            break;
        }
        // get message signature length
        if (!module->CryptSignHashA(hHash, AT_SIGNATURE, NULL, 0, NULL, &length))
        {
            break;
        }
        // sign the hash of message
        buffer = module->malloc(length);
        if (!module->CryptSignHashA(hHash, AT_SIGNATURE, NULL, 0, buffer, &length))
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
        module->free(buffer);
        return lastErr;
    }
    signature->buf = buffer;
    signature->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_RSAVerify(ALG_ID aid, databuf* data, databuf* key, databuf* signature)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RSAVerify: 0x%zX, 0x%zX, 0x%zX", data, key, signature);

    if (data->len < 1)
    {
        return ERR_WIN_CRYPTO_EMPTY_MESSAGE;
    }
    if (signature->len < 1)
    {
        return ERR_WIN_CRYPTO_EMPTY_SIGNATURE;
    }

    errno err = isValidRSAPublicKey(key);
    if (err != NO_ERROR)
    {
        return err;
    }
    RSAPUBKEYHEADER* hdr = key->buf;
    if (hdr->header.aiKeyAlg != CALG_RSA_SIGN)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_ALG_ID;
    }

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
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // import public key to context
        if (!module->CryptImportKey(hProv, key->buf, (DWORD)(key->len), NULL, 0, &hKey))
        {
            break;
        }
        // calculate hash of data
        if (!module->CryptCreateHash(hProv, aid, NULL, 0, &hHash))
        {
            break;
        }
        if (!module->CryptHashData(hHash, data->buf, (DWORD)(data->len), 0))
        {
            break;
        }
        // verify signature about data hash
        if (!module->CryptVerifySignatureA(
            hHash, signature->buf, (DWORD)(signature->len), hKey, NULL, 0
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
errno WC_RSAEncrypt(databuf* data, databuf* key, databuf* output)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RSAEncrypt: 0x%zX, 0x%zX, 0x%zX", data, key, output);

    if (data->len < 1)
    {
        return ERR_WIN_CRYPTO_EMPTY_PLAIN_DATA;
    }

    errno err = isValidRSAPublicKey(key);
    if (err != NO_ERROR)
    {
        return err;
    }
    RSAPUBKEYHEADER* hdr = key->buf;
    if (hdr->header.aiKeyAlg != CALG_RSA_KEYX)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_ALG_ID;
    }

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    void* buffer = NULL;
    uint  length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // import RSA public key to context
        if (!module->CryptImportKey(hProv, key->buf, (DWORD)(key->len), NULL, 0, &hKey))
        {
            break;
        }
        // calculate the cipher data size
        DWORD outputLen = (DWORD)(data->len);
        if (!module->CryptEncrypt(hKey, NULL, true, 0, NULL, &outputLen, 0))
        {
            break;
        }
        // allocate buffer and copy plain data
        buffer = module->malloc(outputLen);
        mem_copy(buffer, data->buf, data->len);
        // encrypt data
        DWORD inputLen = (DWORD)(data->len);
        if (!module->CryptEncrypt(hKey, NULL, true, 0, buffer, &inputLen, outputLen))
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
        module->free(buffer);
        return lastErr;
    }
    output->buf = buffer;
    output->len = length;
    return NO_ERROR;
}

__declspec(noinline)
errno WC_RSADecrypt(databuf* data, databuf* key, databuf* output)
{
    WinCrypto* module = getModulePointer();

    dbg_log("[WinCrypto]", "RSADecrypt: 0x%zX, 0x%zX, 0x%zX", data, key, output);

    if (data->len < 1)
    {
        return ERR_WIN_CRYPTO_INVALID_CIPHER_DATA;
    }

    errno err = isValidRSAPrivateKey(key);
    if (err != NO_ERROR)
    {
        return err;
    }
    RSAPUBKEYHEADER* hdr = key->buf;
    if (hdr->header.aiKeyAlg != CALG_RSA_KEYX)
    {
        return ERR_WIN_CRYPTO_INVALID_KEY_ALG_ID;
    }

    if (!initWinCryptoEnv())
    {
        return GetLastErrno();
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    void* buffer = NULL;
    uint  length = 0;

    bool success = false;
    for (;;)
    {
        if (!module->CryptAcquireContextA(
            &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
        )){
            break;
        }
        // import RSA private key to context
        if (!module->CryptImportKey(hProv, key->buf, (DWORD)(key->len), NULL, 0, &hKey))
        {
            break;
        }
        // copy cipher data and decrypt it
        buffer = module->malloc(data->len);
        mem_copy(buffer, data->buf, data->len);
        DWORD plainLen = (DWORD)(data->len);
        if (!module->CryptDecrypt(hKey, NULL, true, 0, buffer, &plainLen))
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
        module->free(buffer);
        return lastErr;
    }
    output->buf = buffer;
    output->len = length;
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
