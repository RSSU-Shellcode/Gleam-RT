#ifndef WINDOWS_T_H
#define WINDOWS_T_H

#include "c_types.h"

/* 
* Documents:
* https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
* https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo
* https://learn.microsoft.com/zh-cn/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
* https://learn.microsoft.com/zh-cn/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw
* https://learn.microsoft.com/zh-cn/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa
* https://learn.microsoft.com/zh-cn/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw
* https://learn.microsoft.com/zh-cn/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary
* https://learn.microsoft.com/zh-cn/windows/win32/api/libloaderapi/nf-libloaderapi-freelibraryandexitthread
* https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
* https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
* https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
* https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitthread
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadid
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache
* https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexa
* https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-releasemutex
* https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
* https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
* https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
*/

#ifndef _WINDOWS_
#define _WINDOWS_

typedef byte*   LPCSTR;
typedef uint16* LPCWSTR;
typedef uint    HMODULE;
typedef uint    HANDLE;
typedef HANDLE* LPHANDLE;

typedef struct {
    uint32  dwOEMID;
    uint32  dwPageSize;
    uintptr lpMinimumApplicationAddress;
    uintptr lpMaximumApplicationAddress;
    uintptr dwActiveProcessorMask;
    uint32  dwNumberOfProcessors;
    uint32  dwProcessorType;
    uint32  dwAllocationGranularity;
    uint16  wProcessorLevel;
    uint16  wProcessorRevision;
} SYSTEM_INFO;

#define CURRENT_PROCESS (HANDLE)(-1)
#define CURRENT_THREAD  (HANDLE)(-2)

#define MEM_COMMIT   0x00001000
#define MEM_RESERVE  0x00002000
#define MEM_DECOMMIT 0x00004000
#define MEM_RELEASE  0x00008000

#define PAGE_NOACCESS          0x00000001
#define PAGE_READONLY          0x00000002
#define PAGE_READWRITE         0x00000004
#define PAGE_WRITECOPY         0x00000008
#define PAGE_EXECUTE           0x00000010
#define PAGE_EXECUTE_READ      0x00000020
#define PAGE_EXECUTE_READWRITE 0x00000040
#define PAGE_EXECUTE_WRITECOPY 0x00000080

#define INFINITE      0xFFFFFFFF
#define WAIT_OBJECT_0 0x00000000

#define DUPLICATE_SAME_ACCESS 0x00000002

#define MAX_PATH 260

#endif // _WINDOWS_

typedef void (*GetSystemInfo_t)
(
    SYSTEM_INFO* lpSystemInfo
);

typedef HMODULE (*LoadLibraryA_t)
(
    LPCSTR lpLibFileName
);

typedef HMODULE (*LoadLibraryW_t)
(
    LPCWSTR lpLibFileName
);

typedef HMODULE (*LoadLibraryExA_t)
(
    LPCSTR lpLibFileName, HANDLE hFile, uint32 dwFlags
);

typedef HMODULE(*LoadLibraryExW_t)
(
    LPCWSTR lpLibFileName, HANDLE hFile, uint32 dwFlags
);

typedef bool (*FreeLibrary_t)
(
    HMODULE hLibModule
);

typedef void (*FreeLibraryAndExitThread_t)
(
    HMODULE hLibModule, uint32 dwExitCode
);

typedef uintptr (*GetProcAddress_t)
(
    HMODULE hModule, LPCSTR lpProcName
);

typedef uintptr (*VirtualAlloc_t)
(
    uintptr lpAddress, uint dwSize, uint32 flAllocationType, uint32 flProtect
);

typedef bool (*VirtualFree_t)
(
    uintptr lpAddress, uint dwSize, uint32 dwFreeType
);

typedef bool (*VirtualProtect_t)
(
    uintptr lpAddress, uint dwSize, uint32 flNewProtect, uint32* lpflOldProtect
);

typedef HANDLE (*CreateThread_t)
(
    uintptr lpThreadAttributes, uint dwStackSize, uintptr lpStartAddress,
    uintptr lpParameter, uint32 dwCreationFlags, uint32* lpThreadId
);

typedef void (*ExitThread_t)
(
    uint32 dwExitCode
);

typedef uint32 (*SuspendThread_t)
(
    HANDLE hThread
);

typedef uint32 (*ResumeThread_t)
(
    HANDLE hThread
);

typedef uint32 (*GetThreadID_t)
(
    HANDLE hThread
);

typedef uint32 (*GetCurrentThreadID_t)();

typedef bool (*TerminateThread_t)
(
    HANDLE hThread, uint32 dwExitCode
);

typedef bool (*FlushInstructionCache_t)
(
    HANDLE hProcess, uintptr lpBaseAddress, uint dwSize
);

typedef HANDLE (*CreateMutexA_t)
(
    uintptr lpMutexAttributes, bool bInitialOwner, LPCSTR lpName
);

typedef bool (*ReleaseMutex_t)
(
    HANDLE hMutex
);

typedef uint32 (*WaitForSingleObject_t)
(
    HANDLE hHandle, uint32 dwMilliseconds
);

typedef bool (*DuplicateHandle_t)
(
    HANDLE hSourceProcessHandle, HANDLE hSourceHandle,
    HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle,
    uint32 dwDesiredAccess, bool bInheritHandle, uint32 dwOptions
);

typedef bool (*CloseHandle_t)
(
    HANDLE hObject
);

#endif // WINDOWS_T_H
