#ifndef WIN_HTTP_H
#define WIN_HTTP_H

#include "c_types.h"
#include "lib_string.h"
#include "errno.h"
#include "context.h"

// The HTTP_Body.Buf allocated from WinHTTP must call Runtime_M.Memory.Free().

typedef struct {
    void* Buf;
    uint  Size;
} HTTP_Body;

typedef struct {
    UTF16  Headers;     // split by "\r\n"
    UTF16  ContentType; // for POST method
    UTF16  UserAgent;   // default User-Agent
    UTF16  ProxyURL;    // http://user:pass@host.com/
    uint   MaxBodySize; // default is no limit
    uint32 Timeout;     // millseconds
    uint8  AccessType;  // reference document about WinHttpOpen

    HTTP_Body* Body;
} HTTP_Opts;

typedef struct {
    int32 StatusCode;
    UTF16 Headers;

    HTTP_Body Body;
} HTTP_Resp;

typedef errno (*WHGet_t)(UTF16 url, HTTP_Opts* opts, HTTP_Resp* resp);
typedef errno (*WHPost_t)(UTF16 url, HTTP_Body* body, HTTP_Opts* opts, HTTP_Resp* resp);
typedef errno (*WHDo_t)(UTF16 url, UTF16 method, HTTP_Opts* opts, HTTP_Resp* resp);
typedef errno (*WHFree_t)();

typedef bool  (*WHLock_t)();
typedef bool  (*WHUnlock_t)();
typedef errno (*WHClean_t)();
typedef errno (*WHUninstall_t)();

typedef struct {
    WHGet_t  Get;
    WHPost_t Post;
    WHDo_t   Do;
    WHFree_t Free;

    WHLock_t      Lock;
    WHUnlock_t    Unlock;
    WHClean_t     Clean;
    WHUninstall_t Uninstall;
} WinHTTP_M;

WinHTTP_M* InitWinHTTP(Context* context);

#endif // WIN_HTTP_H
