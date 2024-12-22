#ifndef DLL_WS2_32_H
#define DLL_WS2_32_H

#include "c_types.h"
#include "win_types.h"

#define WSASYSNOTREADY 10091
#define WSAEINPROGRESS 10036

typedef int(*WSAStartup_t)
(
    WORD wVersionRequired, POINTER lpWSAData
);

typedef int (*WSACleanup_t)();

#endif // DLL_WS2_32_H
