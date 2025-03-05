#ifndef DLL_WS2_32_H
#define DLL_WS2_32_H

#include "c_types.h"
#include "win_types.h"

#define INVALID_SOCKET ((SOCKET)(-1))
#define SOCKET_ERROR   (-1)

#define WSASYSNOTREADY 10091
#define WSAEINPROGRESS 10036

typedef HANDLE SOCKET;

typedef int (*WSAStartup_t)
(
    WORD wVersionRequired, POINTER lpWSAData
);

typedef int (*WSACleanup_t)();

typedef SOCKET (*WSASocketA_t)
(
    int af, int type, int protocol, POINTER lpProtocolInfo, 
    POINTER g, DWORD dwFlags
);

typedef SOCKET (*WSASocketW_t)
(
    int af, int type, int protocol, POINTER lpProtocolInfo, 
    POINTER g, DWORD dwFlags
);

typedef SOCKET (*socket_t)
(
    int af, int type, int protocol
);

typedef SOCKET (*accept_t)
(
    SOCKET s, POINTER addr, int* addrlen
);

typedef int (*closesocket_t)
(
    SOCKET s
);

#endif // DLL_WS2_32_H
