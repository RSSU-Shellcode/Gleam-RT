#ifndef WIN_HTTP_H
#define WIN_HTTP_H

#include "c_types.h"
#include "lib_string.h"
#include "errno.h"
#include "context.h"

// The databuf allocated from HTTP_Response must call Runtime_M.Memory.Free().
// The Headers in HTTP_Response must call Runtime_M.Memory.Free() after use.
// NOT add "/" at the last of ProxyURL.
// 
// Init is used to initialize a HTTP request structure.
// Free is used to try to free winhttp.dll after use.

#pragma pack(1)
typedef struct {
    UTF16 URL; // https://user:pass@www.example.com/test.txt

    UTF16  Headers;        // split by "\r\n"
    UTF16  UserAgent;      // default User-Agent
    UTF16  ProxyURL;       // http://www.example.com:8080
    UTF16  ProxyUser;      // proxy server username
    UTF16  ProxyPass;      // proxy server password
    uint32 ConnectTimeout; // milliseconds, default is 60s
    uint32 SendTimeout;    // milliseconds, default is 600s
    uint32 ReceiveTimeout; // milliseconds, default is 600s
    uint32 MaxBodySize;    // zero is no limit
    uint8  AccessType;     // reference document about WinHttpOpen

    databuf* Body;
} HTTP_Request;
#pragma pack()

typedef struct {
    int32 StatusCode; // example 200, 404
    UTF16 Headers;    // split by "\r\n"

    databuf Body;
} HTTP_Response;

typedef void  (*WHInit_t)(HTTP_Request* req);
typedef errno (*WHGet_t)(HTTP_Request* req, HTTP_Response* resp);
typedef errno (*WHPost_t)(HTTP_Request* req, HTTP_Response* resp);
typedef errno (*WHDo_t)(UTF16 method, HTTP_Request* req, HTTP_Response* resp);
typedef errno (*WHFreeDLL_t)();

typedef bool  (*WHLock_t)();
typedef bool  (*WHUnlock_t)();
typedef errno (*WHClean_t)();
typedef errno (*WHUninstall_t)();

typedef struct {
    WHInit_t    Init;
    WHGet_t     Get;
    WHPost_t    Post;
    WHDo_t      Do;
    WHFreeDLL_t FreeDLL;

    WHLock_t      Lock;
    WHUnlock_t    Unlock;
    WHClean_t     Clean;
    WHUninstall_t Uninstall;
} WinHTTP_M;

WinHTTP_M* InitWinHTTP(Context* context);

#endif // WIN_HTTP_H
