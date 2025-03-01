#ifndef DLL_MSWSOCK_H
#define DLL_MSWSOCK_H

#include "c_types.h"
#include "win_types.h"

typedef HANDLE SOCKET;

typedef BOOL (*AcceptEx_t)
(
    SOCKET sListenSocket, SOCKET sAcceptSocket, PVOID lpOutputBuffer,
    DWORD dwReceiveDataLength, DWORD dwLocalAddressLength,
    DWORD dwRemoteAddressLength, DWORD* lpdwBytesReceived, POINTER lpOverlapped
);

#endif // DLL_MSWSOCK_H
