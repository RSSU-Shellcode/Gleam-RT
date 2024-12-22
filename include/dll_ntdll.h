#ifndef DLL_NTDLL_H
#define DLL_NTDLL_H

#include "c_types.h"
#include "windows_t.h"

typedef LPVOID (*RtlAllocateHeap_t)
(
    HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes
);

typedef LPVOID (*RtlReAllocateHeap_t)
(
    HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes
);

typedef BOOL (*RtlFreeHeap_t)
(
    HANDLE hHeap, DWORD dwFlags, LPVOID lpMem
);

typedef SIZE_T (*RtlSizeHeap_t)
(
    HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem
);

#endif // DLL_NTDLL_H
