#ifndef WIN_HTTP_H
#define WIN_HTTP_H

#include "c_types.h"
#include "lib_string.h"
#include "errno.h"
#include "context.h"

// The databuf allocated from HTTP_Response must call Runtime_M.Memory.Free().
// The Headers in HTTP_Response must call Runtime_M.Memory.Free() after use.
// 
// Init is used to initialize a HTTP request structure.
// Free is used to try to free winhttp.dll after use.

typedef struct {
    UTF16 URL; // https://www.example.com/test.txt

    UTF16 Headers;        // split by "\r\n"
    UTF16 UserAgent;      // default User-Agent
    UTF16 ProxyURL;       // http://user:pass@host.com/
    uint  MaxBodySize;    // zero is no limit
    uint  ConnectTimeout; // millseconds
    uint  SendTimeout;    // millseconds
    uint  ReceiveTimeout; // millseconds
    uint8 AccessType;     // reference document about WinHttpOpen

    databuf* Body;
} HTTP_Request;

typedef struct {
    int32 StatusCode; // example 200, 404
    UTF16 Headers;    // split by "\r\n"

    databuf Body;
} HTTP_Response;

typedef errno (*WHGet_t)(HTTP_Request* req, HTTP_Response* resp);
typedef errno (*WHPost_t)(HTTP_Request* req, HTTP_Response* resp);
typedef errno (*WHDo_t)(UTF16 method, HTTP_Request* req, HTTP_Response* resp);

typedef void  (*WHInit_t)(HTTP_Request* req);
typedef errno (*WHFree_t)();

typedef bool  (*WHLock_t)();
typedef bool  (*WHUnlock_t)();
typedef errno (*WHClean_t)();
typedef errno (*WHUninstall_t)();

typedef struct {
    WHGet_t  Get;
    WHPost_t Post;
    WHDo_t   Do;

    WHInit_t Init;
    WHFree_t Free;

    WHLock_t      Lock;
    WHUnlock_t    Unlock;
    WHClean_t     Clean;
    WHUninstall_t Uninstall;
} WinHTTP_M;

WinHTTP_M* InitWinHTTP(Context* context);

#endif // WIN_HTTP_H
