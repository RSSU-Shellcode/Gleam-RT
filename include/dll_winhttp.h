#ifndef DLL_WINHTTP_H
#define DLL_WINHTTP_H

#include "c_types.h"
#include "win_types.h"

typedef HANDLE HINTERNET;

#define INTERNET_SCHEME_HTTP  1
#define INTERNET_SCHEME_HTTPS 2

#define WINHTTP_OPTION_DECOMPRESSION 0x00000076

#define WINHTTP_DECOMPRESSION_FLAG_GZIP    1
#define WINHTTP_DECOMPRESSION_FLAG_DEFLATE 2
#define WINHTTP_DECOMPRESSION_FLAG_ALL     3

#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY   0
#define WINHTTP_ACCESS_TYPE_NO_PROXY        1
#define WINHTTP_ACCESS_TYPE_NAMED_PROXY     3
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4

#define WINHTTP_NO_REFERER            NULL
#define WINHTTP_DEFAULT_ACCEPT_TYPES  NULL
#define WINHTTP_NO_ADDITIONAL_HEADERS NULL
#define WINHTTP_NO_REQUEST_DATA       NULL

#define WINHTTP_FLAG_SECURE 0x00800000

#define WINHTTP_HEADER_NAME_BY_INDEX NULL
#define WINHTTP_NO_OUTPUT_BUFFER     NULL
#define WINHTTP_NO_HEADER_INDEX      NULL

#define WINHTTP_QUERY_FLAG_NUMBER      0x20000000
#define WINHTTP_QUERY_STATUS_CODE      19
#define WINHTTP_QUERY_RAW_HEADERS_CRLF 22

typedef struct {
    DWORD  dwStructSize;
    LPWSTR lpszScheme;
    DWORD  dwSchemeLength;
    DWORD  nScheme;
    LPWSTR lpszHostName;
    DWORD  dwHostNameLength;
    WORD   nPort;
    LPWSTR lpszUserName;
    DWORD  dwUserNameLength;
    LPWSTR lpszPassword;
    DWORD  dwPasswordLength;
    LPWSTR lpszUrlPath;
    DWORD  dwUrlPathLength;
    LPWSTR lpszExtraInfo;
    DWORD  dwExtraInfoLength;
} URL_COMPONENTS;

typedef BOOL (*WinHttpCrackUrl_t)
(
    LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags,
    URL_COMPONENTS* lpUrlComponents
);

typedef HINTERNET (*WinHttpOpen_t)
(
    LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW, DWORD dwFlags
);

typedef HINTERNET (*WinHttpConnect_t)
(
    HINTERNET hSession, LPCWSTR pswzServerName, WORD nServerPort,
    DWORD dwReserved
);

typedef BOOL (*WinHttpSetOption_t)
(
    HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength
);

typedef BOOL (*WinHttpSetTimeouts_t)
(
    HINTERNET hInternet, int nResolveTimeout, int nConnectTimeout,
    int nSendTimeout, int nReceiveTimeout
);

typedef HINTERNET (*WinHttpOpenRequest_t)
(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, 
    DWORD dwFlags
);

typedef BOOL (*WinHttpSetCredentials_t)
(
    HINTERNET hRequest, DWORD AuthTargets, DWORD AuthScheme,
    LPCWSTR pwszUserName, LPCWSTR pwszPassword, LPVOID pAuthParams
);

typedef BOOL (*WinHttpSendRequest_t)
(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
    DWORD* dwContext
);

typedef BOOL (*WinHttpReceiveResponse_t)
(
    HINTERNET hRequest, LPVOID lpReserved
);

typedef BOOL (*WinHttpQueryHeaders_t)
(
    HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName,
    LPVOID lpBuffer, DWORD* lpdwBufferLength, DWORD* lpdwIndex
);

typedef BOOL (*WinHttpQueryDataAvailable_t)
(
    HINTERNET hRequest, DWORD* lpdwNumberOfBytesAvailable
);

typedef BOOL (*WinHttpReadData_t)
(
    HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, 
    DWORD* lpdwNumberOfBytesRead
);

typedef BOOL (*WinHttpCloseHandle_t)
(
    HINTERNET hInternet
);

#endif // DLL_WINHTTP_H
