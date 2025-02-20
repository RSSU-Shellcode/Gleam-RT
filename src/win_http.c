#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_winhttp.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "win_http.h"
#include "debug.h"

#define DEFAULT_TIMEOUT (60*1000) // 60s

#ifdef RELEASE_MODE
    #define CHUNK_SIZE 4096
#else
    #define CHUNK_SIZE 64
#endif

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    WinHttpCrackUrl_t           WinHttpCrackUrl;
    WinHttpOpen_t               WinHttpOpen;
    WinHttpConnect_t            WinHttpConnect;
    WinHttpSetOption_t          WinHttpSetOption;
    WinHttpSetTimeouts_t        WinHttpSetTimeouts;
    WinHttpOpenRequest_t        WinHttpOpenRequest;
    WinHttpSetCredentials_t     WinHttpSetCredentials;
    WinHttpSendRequest_t        WinHttpSendRequest;
    WinHttpReceiveResponse_t    WinHttpReceiveResponse;
    WinHttpQueryHeaders_t       WinHttpQueryHeaders;
    WinHttpQueryDataAvailable_t WinHttpQueryDataAvailable;
    WinHttpReadData_t           WinHttpReadData;
    WinHttpCloseHandle_t        WinHttpCloseHandle;

    LoadLibraryA_t        LoadLibraryA;
    FreeLibrary_t         FreeLibrary;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;
    Sleep_t               Sleep;

    // submodules method
    mt_malloc_t  malloc;
    mt_calloc_t  calloc;
    mt_realloc_t realloc;
    mt_free_t    free;
    mt_msize_t   msize;

    // protect data
    HMODULE hModule; // winhttp.dll
    int32   counter; // call counter
    HANDLE  hMutex;  // global mutex
} WinHTTP;

// methods for user
errno WH_Get(HTTP_Request* req, HTTP_Response* resp);
errno WH_Post(HTTP_Request* req, HTTP_Response* resp);
errno WH_Do(UTF16 method, HTTP_Request* req, HTTP_Response* resp);
void  WH_Init(HTTP_Request* req);
errno WH_Free();

// methods for runtime
bool  WH_Lock();
bool  WH_Unlock();
errno WH_Clean();
errno WH_Uninstall();

// hard encoded address in getModulePointer for replacement
#ifdef _WIN64
    #define MODULE_POINTER 0x7FABCDEF111111E3
#elif _WIN32
    #define MODULE_POINTER 0x7FABCDE3
#endif
static WinHTTP* getModulePointer();

static bool wh_lock();
static bool wh_unlock();

static bool initModuleAPI(WinHTTP* module, Context* context);
static bool updateModulePointer(WinHTTP* module);
static bool recoverModulePointer(WinHTTP* module);
static bool initModuleEnvironment(WinHTTP* module, Context* context);
static void eraseModuleMethods(Context* context);

static bool initWinHTTPEnv();
static bool findWinHTTPAPI();
static bool tryToFreeLibrary();
static bool increaseCounter();
static bool decreaseCounter();

WinHTTP_M* InitWinHTTP(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr moduleAddr = address + 20000 + RandUintN(address, 128);
    uintptr methodAddr = address + 21000 + RandUintN(address, 128);
    // initialize module
    WinHTTP* module = (WinHTTP*)moduleAddr;
    mem_init(module, sizeof(WinHTTP));
    // store options
    module->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initModuleAPI(module, context))
        {
            errno = ERR_WIN_HTTP_INIT_API;
            break;
        }
        if (!updateModulePointer(module))
        {
            errno = ERR_WIN_HTTP_UPDATE_PTR;
            break;
        }
        if (!initModuleEnvironment(module, context))
        {
            errno = ERR_WIN_HTTP_INIT_ENV;
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
    WinHTTP_M* method = (WinHTTP_M*)methodAddr;
    method->Get  = GetFuncAddr(&WH_Get);
    method->Post = GetFuncAddr(&WH_Post);
    method->Do   = GetFuncAddr(&WH_Do);
    method->Init = GetFuncAddr(&WH_Init);
    method->Free = GetFuncAddr(&WH_Free);
    // methods for runtime
    method->Lock      = GetFuncAddr(&WH_Lock);
    method->Unlock    = GetFuncAddr(&WH_Unlock);
    method->Clean     = GetFuncAddr(&WH_Clean);
    method->Uninstall = GetFuncAddr(&WH_Uninstall);
    return method;
}

static bool initModuleAPI(WinHTTP* module, Context* context)
{
    module->LoadLibraryA        = context->LoadLibraryA;
    module->FreeLibrary         = context->FreeLibrary;
    module->ReleaseMutex        = context->ReleaseMutex;
    module->WaitForSingleObject = context->WaitForSingleObject;
    module->CloseHandle         = context->CloseHandle;
    module->Sleep               = context->Sleep;
    return true;
}

// CANNOT merge updateModulePointer and recoverModulePointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

static bool updateModulePointer(WinHTTP* module)
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

static bool recoverModulePointer(WinHTTP* module)
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

static bool initModuleEnvironment(WinHTTP* module, Context* context)
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
static WinHTTP* getModulePointer()
{
    uintptr pointer = MODULE_POINTER;
    return (WinHTTP*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool wh_lock()
{
    WinHTTP* module = getModulePointer();

    DWORD event = module->WaitForSingleObject(module->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool wh_unlock()
{
    WinHTTP* module = getModulePointer();

    return module->ReleaseMutex(module->hMutex);
}

__declspec(noinline)
static bool initWinHTTPEnv()
{
    WinHTTP* module = getModulePointer();

    if (!wh_lock())
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
        // decrypt to "winhttp.dll\0"
        byte dllName[] = {
            'w'^0xAC, 'i'^0x1F, 'n'^0x49, 'h'^0xC6, 
            't'^0xAC, 't'^0x1F, 'p'^0x49, '.'^0xC6, 
            'd'^0xAC, 'l'^0x1F, 'l'^0x49, 000^0xC6,
        };
        byte key[] = {0xAC, 0x1F, 0x49, 0xC6};
        XORBuf(dllName, sizeof(dllName), key, sizeof(key));
        // load winhttp.dll
        HMODULE hModule = module->LoadLibraryA(dllName);
        if (hModule == NULL)
        {
            break;
        }
        // prepare API address
        if (!findWinHTTPAPI())
        {
            SetLastErrno(ERR_WIN_HTTP_API_NOT_FOUND);
            module->FreeLibrary(hModule);
            break;
        }
        module->hModule = hModule;
        success = true;
        break;
    }

    if (!wh_unlock())
    {
        return false;
    }
    return success;
}

static bool findWinHTTPAPI()
{
    WinHTTP* module = getModulePointer();

    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x62EA4FC32B55857E, 0x6B27C051C7F60422 }, // WinHttpCrackUrl
        { 0x1267A9EEDB99E181, 0xB41CF5D67E16D815 }, // WinHttpOpen
        { 0xA4CFDBCF777FB49E, 0x49B9E3980C8AD1DD }, // WinHttpConnect
        { 0x8242A6CE50212202, 0x2F491ECB0FBF3CA6 }, // WinHttpSetOption
        { 0xE1EB9927C8B0E8EC, 0x345008256D48B401 }, // WinHttpSetTimeouts
        { 0xECE538251C35E9EA, 0x26D21A52453C514A }, // WinHttpOpenRequest
        { 0xCF86A08B3A40FDAB, 0xD0AAF1B60D845011 }, // WinHttpSetCredentials
        { 0xAA71C1860B6CB78D, 0x8FD7A27D14C8254C }, // WinHttpSendRequest
        { 0xBAF3D0185F2E7094, 0xFDA31AE507B6FB12 }, // WinHttpReceiveResponse
        { 0x8D1E52DBB477E02E, 0x61D0554B71E7FD43 }, // WinHttpQueryHeaders
        { 0x5C469E2A43DF4080, 0x5A2F580559E64F36 }, // WinHttpQueryDataAvailable
        { 0x0BF6F5AAF70C8544, 0xDAB6BC2D844D328B }, // WinHttpReadData
        { 0x8BB59C8AEF72DAC1, 0xCA4475F306F5D45C }, // WinHttpCloseHandle
    };
#elif _WIN32
    {
        { 0xA0E97382, 0x86619CBC }, // WinHttpCrackUrl
        { 0xFA3A70B4, 0xA43EA698 }, // WinHttpOpen
        { 0x0BE11F33, 0xCC38EE75 }, // WinHttpConnect
        { 0xE9319484, 0xFC564C7E }, // WinHttpSetOption
        { 0xFA06B187, 0x3942E8ED }, // WinHttpSetTimeouts
        { 0x7F719278, 0x3706020A }, // WinHttpOpenRequest
        { 0x4222DDA2, 0xD5A26D8D }, // WinHttpSetCredentials
        { 0x91688CB4, 0x9986E1B6 }, // WinHttpSendRequest
        { 0xF69E6547, 0xFD292EE8 }, // WinHttpReceiveResponse
        { 0xBD960E7A, 0xD29D7213 }, // WinHttpQueryHeaders
        { 0x549BFA55, 0xB03FE5F9 }, // WinHttpQueryDataAvailable
        { 0x38C41147, 0xDBD59C70 }, // WinHttpReadData
        { 0x173816BB, 0x52FA19B1 }, // WinHttpCloseHandle
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
    module->WinHttpCrackUrl           = list[0x00].proc;
    module->WinHttpOpen               = list[0x01].proc;
    module->WinHttpConnect            = list[0x02].proc;
    module->WinHttpSetOption          = list[0x03].proc;
    module->WinHttpSetTimeouts        = list[0x04].proc;
    module->WinHttpOpenRequest        = list[0x05].proc;
    module->WinHttpSetCredentials     = list[0x06].proc;
    module->WinHttpSendRequest        = list[0x07].proc;
    module->WinHttpReceiveResponse    = list[0x08].proc;
    module->WinHttpQueryHeaders       = list[0x09].proc;
    module->WinHttpQueryDataAvailable = list[0x0A].proc;
    module->WinHttpReadData           = list[0x0B].proc;
    module->WinHttpCloseHandle        = list[0x0C].proc;
    return true;
}

__declspec(noinline)
static bool tryToFreeLibrary()
{
    WinHTTP* module = getModulePointer();

    bool success = false;
    for (;;)
    {
        if (module->hModule == NULL)
        {
            success = true;
            break;
        }
        if (module->counter > 0)
        {
            SetLastErrno(ERR_WIN_HTTP_MODULE_BUSY);
            break;
        }
        if (!module->FreeLibrary(module->hModule))
        {
            break;
        }
        module->hModule = NULL;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool increaseCounter()
{
    WinHTTP* module = getModulePointer();

    if (!wh_lock())
    {
        return false;
    }
    module->counter++;
    // prevent unexpected status
    if (module->counter < 1)
    {
        module->counter = 1;
    }
    if (!wh_unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
static bool decreaseCounter()
{
    WinHTTP* module = getModulePointer();

    if (!wh_lock())
    {
        return false;
    }
    module->counter--;
    // prevent unexpected status
    if (module->counter < 0)
    {
        module->counter = 0;
    }
    if (!wh_unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
errno WH_Get(HTTP_Request* req, HTTP_Response* resp)
{
    // build "GET" string
    uint16 method[] = {
        L'G'^0x12AC, L'E'^0xDA1F, L'T'^0x4C7D, 0000^0x9A1E, 
    };
    uint16 key[] = { 0x12AC, 0xDA1F, 0x4C7D, 0x9A1E};
    XORBuf(method, sizeof(method), key, sizeof(key));
    return WH_Do(method, req, resp);
}

__declspec(noinline)
errno WH_Post(HTTP_Request* req, HTTP_Response* resp)
{
    // build "POST" string
    uint16 method[] = {
        L'P'^0x49C7, L'O'^0xC48D, L'S'^0xAB12, L'T'^0x49C2, 
        0000^0x49C7, 
    };
    uint16 key[] = { 0x49C7, 0xC48D, 0xAB12, 0x49C2 };
    XORBuf(method, sizeof(method), key, sizeof(key));
    return WH_Do(method, req, resp);
}

__declspec(noinline)
errno WH_Do(UTF16 method, HTTP_Request* req, HTTP_Response* resp)
{
    WinHTTP* module = getModulePointer();

    dbg_log("[WinHTTP]", "%ls %ls", method, req->URL);

    if (!initWinHTTPEnv())
    {
        return GetLastErrno();
    }
    if (!increaseCounter())
    {
        return GetLastErrno();
    }

    // parse input URL
    uint16* scheme   = module->calloc(16,   sizeof(uint16));
    uint16* hostname = module->calloc(256,  sizeof(uint16));
    uint16* username = module->calloc(256,  sizeof(uint16));
    uint16* password = module->calloc(256,  sizeof(uint16));
    uint16* path     = module->calloc(4096, sizeof(uint16));
    uint16* extra    = module->calloc(4096, sizeof(uint16));
    uint16* reqPath  = module->calloc(8192, sizeof(uint16));

    URL_COMPONENTS url_com;
    mem_init(&url_com, sizeof(url_com));
    url_com.dwStructSize      = sizeof(url_com);
    url_com.lpszScheme        = scheme;
    url_com.dwSchemeLength    = (DWORD)module->msize(scheme)/sizeof(uint16);
    url_com.lpszHostName      = hostname;
    url_com.dwHostNameLength  = (DWORD)module->msize(hostname)/sizeof(uint16);
    url_com.lpszUserName      = username;
    url_com.dwUserNameLength  = (DWORD)module->msize(username)/sizeof(uint16);
    url_com.lpszPassword      = password;
    url_com.dwPasswordLength  = (DWORD)module->msize(password)/sizeof(uint16);
    url_com.lpszUrlPath       = path;
    url_com.dwUrlPathLength   = (DWORD)module->msize(path)/sizeof(uint16);
    url_com.lpszExtraInfo     = extra;
    url_com.dwExtraInfoLength = (DWORD)module->msize(extra)/sizeof(uint16);

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    UTF16 headerBuf = NULL;
    byte* bodyBuf   = NULL;

    bool success = false;
    for (;;)
    {
        // split input url
        if (!module->WinHttpCrackUrl(req->URL, 0, 0, &url_com))
        {
            break;
        }
        switch (url_com.nScheme)
        {
        case INTERNET_SCHEME_HTTP:
            break;
        case INTERNET_SCHEME_HTTPS:
            break;
        default:
            goto exit_loop;
        }
        // create session
        hSession = module->WinHttpOpen(
            req->UserAgent, req->AccessType, NULL, NULL, 0
        );
        if (hSession == NULL)
        {
            break;
        }
        // set timeouts
        int connectTimeout = (int)(req->ConnectTimeout);
        int sendTimeout    = (int)(req->SendTimeout);
        int receiveTimeout = (int)(req->ReceiveTimeout);
        if (!module->WinHttpSetTimeouts(
            hSession, 0, connectTimeout, sendTimeout, receiveTimeout
        )){
            break;
        }
        // try to enable compression
        DWORD optFlag = WINHTTP_DECOMPRESSION_FLAG_ALL;
        module->WinHttpSetOption(
            hSession, WINHTTP_OPTION_DECOMPRESSION, &optFlag, sizeof(optFlag)
        );
        // create connection
        hConnect = module->WinHttpConnect(
            hSession, hostname, url_com.nPort, 0
        );
        if (hConnect == NULL)
        {
            break;
        }
        // build request path  
        strcpy_w(reqPath, path);
        strcpy_w(reqPath + url_com.dwUrlPathLength, extra);
        // build flag
        DWORD flags = 0;
        if (url_com.nScheme == INTERNET_SCHEME_HTTPS)
        {
            flags = WINHTTP_FLAG_SECURE;
        }
        hRequest = module->WinHttpOpenRequest(
            hConnect, method, reqPath, NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, flags
        );
        if (hRequest == NULL)
        {
            break;
        }
        // send request
        LPCWSTR headers    = WINHTTP_NO_ADDITIONAL_HEADERS;
        DWORD   headersLen = 0;
        if (req->Headers != NULL)
        {
            headers    = req->Headers;
            headersLen = (DWORD)(-1);
        }
        LPVOID body    = WINHTTP_NO_REQUEST_DATA;
        DWORD  bodyLen = 0;
        if (req->Body != NULL && req->Body->len != 0)
        {
            body    = req->Body->buf;
            bodyLen = (DWORD)(req->Body->len);
        }
        if (!module->WinHttpSendRequest(
            hRequest, headers, headersLen, body, bodyLen, bodyLen, NULL
        )){
            break;
        }
        // receive response
        if (!module->WinHttpReceiveResponse(hRequest, NULL))
        {
            break;
        }
        // get response status code
        DWORD statusCodeLen = sizeof(DWORD);
        if (!module->WinHttpQueryHeaders(
            hRequest, WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &resp->StatusCode, &statusCodeLen,
            WINHTTP_NO_HEADER_INDEX
        )) {
            break;
        }
        // get response header
        DWORD headerLen;
        module->WinHttpQueryHeaders(
            hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, 
            NULL, &headerLen, WINHTTP_NO_HEADER_INDEX
        );
        if (GetLastErrno() != ERROR_INSUFFICIENT_BUFFER)
        {
            break;
        }
        headerBuf = module->malloc(headerLen);
        if (!module->WinHttpQueryHeaders(
            hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
            headerBuf, &headerLen, WINHTTP_NO_HEADER_INDEX
        )) {
            break;
        }
        // read body data
        uint bodySize = 0;
        for (;;)
        {
            DWORD size;
            if (!module->WinHttpQueryDataAvailable(hRequest, &size))
            {
                goto exit_loop;
            }
            if (size == 0)
            {
                break;
            }
            // allocate buffer
            bodyBuf = module->realloc(bodyBuf, bodySize+(uint)size);
            if (bodyBuf == NULL)
            {
                goto exit_loop;
            }
            if (!module->WinHttpReadData(hRequest, bodyBuf+bodySize, size, &size))
            {
                goto exit_loop;
            }
            bodySize += (uint)size;
        }
        resp->Headers  = headerBuf;
        resp->Body.buf = bodyBuf;
        resp->Body.len = bodySize;
        success = true;
        break;
    }
exit_loop:

    errno errno = NO_ERROR;
    if (!success)
    {
        errno = GetLastErrno();
        module->free(headerBuf);
        module->free(bodyBuf);
    }

    if (hRequest != NULL)
    {
        if (!module->WinHttpCloseHandle(hRequest) && errno == NO_ERROR)
        {
            errno = GetLastErrno();
        }
    }
    if (hConnect != NULL)
    {
        if (!module->WinHttpCloseHandle(hConnect) && errno == NO_ERROR)
        {
            errno = GetLastErrno();
        }
    }
    if (hSession != NULL)
    {
        if (!module->WinHttpCloseHandle(hSession) && errno == NO_ERROR)
        {
            errno = GetLastErrno();
        }
    }
    module->free(scheme);
    module->free(hostname);
    module->free(username);
    module->free(password);
    module->free(path);
    module->free(extra);
    module->free(reqPath);

    if (!decreaseCounter())
    {
        return GetLastErrno();
    }
    return errno;
}

__declspec(noinline)
void WH_Init(HTTP_Request* req)
{
    req->URL            = NULL;
    req->Headers        = NULL;
    req->UserAgent      = NULL;
    req->ProxyURL       = NULL;
    req->MaxBodySize    = 0;
    req->ConnectTimeout = DEFAULT_TIMEOUT;
    req->SendTimeout    = DEFAULT_TIMEOUT;
    req->ReceiveTimeout = DEFAULT_TIMEOUT;
    req->AccessType     = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
    req->Body           = NULL;
}

__declspec(noinline)
errno WH_Free()
{
    if (!wh_lock())
    {
        return GetLastErrno();
    }

    errno lastErr = NO_ERROR;
    if (!tryToFreeLibrary())
    {
        lastErr = GetLastErrno();
    }

    if (!wh_unlock())
    {
        return GetLastErrno();
    }

    SetLastErrno(lastErr);
    return lastErr;
}

__declspec(noinline)
bool WH_Lock()
{
    WinHTTP* module = getModulePointer();

    // maximum sleep 10s 
    for (int i = 0; i < 1000; i++)
    {
        if (!wh_lock())
        {
            return false;
        }
        if (module->counter < 1)
        {
            return true;
        }
        if (!wh_unlock())
        {
            return false;
        }
        module->Sleep(10);
    }

    // if timeout, reset counter
    if (!wh_lock())
    {
        return false;
    }
    module->counter = 0;
    return true;
}

__declspec(noinline)
bool WH_Unlock()
{
    return wh_unlock();
}

__declspec(noinline)
errno WH_Clean()
{
    if (!tryToFreeLibrary())
    {
        return GetLastErrno();
    }
    return NO_ERROR;
}

__declspec(noinline)
errno WH_Uninstall()
{
    WinHTTP* module = getModulePointer();

    errno errno = NO_ERROR;

    // free winhttp.dll
    if (module->hModule != NULL)
    {
        if (!module->FreeLibrary(module->hModule) && errno == NO_ERROR)
        {
            errno = ERR_WIN_HTTP_FREE_LIBRARY;
        }
    }

    // close mutex
    if (!module->CloseHandle(module->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_WIN_HTTP_CLOSE_MUTEX;
    }

    // recover instructions
    if (module->NotEraseInstruction)
    {
        if (!recoverModulePointer(module) && errno == NO_ERROR)
        {
            errno = ERR_WIN_HTTP_RECOVER_INST;
        }
    }
    return errno;
}
