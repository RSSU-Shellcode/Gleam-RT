#ifndef DLL_PSAPI_H
#define DLL_PSAPI_H

#include "c_types.h"
#include "win_types.h"

typedef union {
    ULONG_PTR Flags;
    union {
        struct {
            ULONG_PTR Valid           :1;
            ULONG_PTR ShareCount      :3;
            ULONG_PTR Win32Protection :11;
            ULONG_PTR Shared          :1;
            ULONG_PTR Node            :6;
            ULONG_PTR Locked          :1;
            ULONG_PTR LargePage       :1;
            ULONG_PTR Reserved        :7;
            ULONG_PTR Bad             :1;
            ULONG_PTR ReservedUlong   :32;
        };
        struct {
            ULONG_PTR Valid         :1;
            ULONG_PTR Reserved0     :14;
            ULONG_PTR Shared        :1;
            ULONG_PTR Reserved1     :15;
            ULONG_PTR Bad           :1;
            ULONG_PTR ReservedUlong :32;
        } Invalid;
    };
} PSAPI_WORKING_SET_EX_BLOCK;

typedef struct {
  PVOID                      VirtualAddress;
  PSAPI_WORKING_SET_EX_BLOCK VirtualAttributes;
} PSAPI_WORKING_SET_EX_INFORMATION;

typedef BOOL (*QueryWorkingSetEx_t)
(
    HANDLE hProcess, PVOID pv, DWORD cb
);

#endif // DLL_PSAPI_H
