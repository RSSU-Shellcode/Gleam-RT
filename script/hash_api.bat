@echo off

echo =====================================================================
echo Build HashAPI tool from https://github.com/RSSU-Shellcode/GRT-Develop
echo =====================================================================
echo.

echo ------------------------x64------------------------

echo [Runtime Core]
hash_api -fmt 64 -conc -proc GetSystemInfo
hash_api -fmt 64 -conc -proc LoadLibraryA
hash_api -fmt 64 -conc -proc FreeLibrary
hash_api -fmt 64 -conc -proc GetProcAddress
hash_api -fmt 64 -conc -proc VirtualAlloc
hash_api -fmt 64 -conc -proc VirtualFree
hash_api -fmt 64 -conc -proc VirtualProtect
hash_api -fmt 64 -conc -proc FlushInstructionCache
hash_api -fmt 64 -conc -proc SuspendThread
hash_api -fmt 64 -conc -proc ResumeThread
hash_api -fmt 64 -conc -proc ExitThread
hash_api -fmt 64 -conc -proc CreateMutexA
hash_api -fmt 64 -conc -proc ReleaseMutex
hash_api -fmt 64 -conc -proc CreateEventA
hash_api -fmt 64 -conc -proc SetEvent
hash_api -fmt 64 -conc -proc CreateWaitableTimerA
hash_api -fmt 64 -conc -proc SetWaitableTimer
hash_api -fmt 64 -conc -proc WaitForSingleObject
hash_api -fmt 64 -conc -proc WaitForMultipleObjects
hash_api -fmt 64 -conc -proc DuplicateHandle
hash_api -fmt 64 -conc -proc CloseHandle
hash_api -fmt 64 -conc -proc SetCurrentDirectoryA
hash_api -fmt 64 -conc -proc SetCurrentDirectoryW
hash_api -fmt 64 -conc -proc SleepEx
hash_api -fmt 64 -conc -proc ExitProcess
echo.

echo [Runtime IAT Hooks]
hash_api -fmt 64 -conc -proc GetProcAddress
hash_api -fmt 64 -conc -proc SetCurrentDirectoryA
hash_api -fmt 64 -conc -proc SetCurrentDirectoryW
hash_api -fmt 64 -conc -proc Sleep
hash_api -fmt 64 -conc -proc SleepEx
echo.

echo [Runtime Methods]
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc GetProcAddressByName
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc GetProcAddressByHash
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc GetProcAddressOriginal
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc GetMetrics
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc ExitProcess
echo.

echo [Library Tracker]
hash_api -fmt 64 -conc -proc LoadLibraryA
hash_api -fmt 64 -conc -proc LoadLibraryW
hash_api -fmt 64 -conc -proc LoadLibraryExA
hash_api -fmt 64 -conc -proc LoadLibraryExW
hash_api -fmt 64 -conc -proc FreeLibrary
hash_api -fmt 64 -conc -proc FreeLibraryAndExitThread
echo.

echo [Memory Tracker]
hash_api -fmt 64 -conc -proc VirtualAlloc
hash_api -fmt 64 -conc -proc VirtualFree
hash_api -fmt 64 -conc -proc VirtualProtect
hash_api -fmt 64 -conc -proc VirtualQuery
hash_api -fmt 64 -conc -proc GetProcessHeap
hash_api -fmt 64 -conc -proc GetProcessHeaps
hash_api -fmt 64 -conc -proc HeapCreate
hash_api -fmt 64 -conc -proc HeapDestroy
hash_api -fmt 64 -conc -proc HeapAlloc
hash_api -fmt 64 -conc -proc HeapReAlloc
hash_api -fmt 64 -conc -proc HeapFree
hash_api -fmt 64 -conc -proc HeapSize
hash_api -fmt 64 -conc -proc HeapLock
hash_api -fmt 64 -conc -proc HeapUnlock
hash_api -fmt 64 -conc -proc HeapWalk
hash_api -fmt 64 -conc -proc GlobalAlloc
hash_api -fmt 64 -conc -proc GlobalReAlloc
hash_api -fmt 64 -conc -proc GlobalFree
hash_api -fmt 64 -conc -proc LocalAlloc
hash_api -fmt 64 -conc -proc LocalReAlloc
hash_api -fmt 64 -conc -proc LocalFree
hash_api -fmt 64 -conc -mod "ntdll.dll" -proc RtlAllocateHeap
hash_api -fmt 64 -conc -mod "ntdll.dll" -proc RtlReAllocateHeap
hash_api -fmt 64 -conc -mod "ntdll.dll" -proc RtlFreeHeap
hash_api -fmt 64 -conc -mod "ntdll.dll" -proc RtlSizeHeap
hash_api -fmt 64 -conc -mod "msvcrt.dll" -proc malloc
hash_api -fmt 64 -conc -mod "msvcrt.dll" -proc calloc
hash_api -fmt 64 -conc -mod "msvcrt.dll" -proc realloc
hash_api -fmt 64 -conc -mod "msvcrt.dll" -proc free
hash_api -fmt 64 -conc -mod "msvcrt.dll" -proc _msize
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc malloc
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc calloc
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc realloc
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc free
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _msize
echo.

echo [Thread Tracker]
hash_api -fmt 64 -conc -proc CreateThread
hash_api -fmt 64 -conc -proc ExitThread
hash_api -fmt 64 -conc -proc SuspendThread
hash_api -fmt 64 -conc -proc ResumeThread
hash_api -fmt 64 -conc -proc SwitchToThread
hash_api -fmt 64 -conc -proc GetThreadContext
hash_api -fmt 64 -conc -proc SetThreadContext
hash_api -fmt 64 -conc -proc GetThreadId
hash_api -fmt 64 -conc -proc GetCurrentThreadId
hash_api -fmt 64 -conc -proc TerminateThread
hash_api -fmt 64 -conc -proc TlsAlloc
hash_api -fmt 64 -conc -proc TlsFree
hash_api -fmt 64 -conc -proc CreateWaitableTimerA
hash_api -fmt 64 -conc -proc SetWaitableTimer
hash_api -fmt 64 -conc -mod "ntdll.dll" -proc RtlExitUserThread
echo.

echo [Resource Tracker]
hash_api -fmt 64 -conc -proc CreateMutexA
hash_api -fmt 64 -conc -proc CreateMutexW
hash_api -fmt 64 -conc -proc CreateMutexExA
hash_api -fmt 64 -conc -proc CreateMutexExW
hash_api -fmt 64 -conc -proc CreateEventA
hash_api -fmt 64 -conc -proc CreateEventW
hash_api -fmt 64 -conc -proc CreateEventExA
hash_api -fmt 64 -conc -proc CreateEventExW
hash_api -fmt 64 -conc -proc CreateSemaphoreA
hash_api -fmt 64 -conc -proc CreateSemaphoreW
hash_api -fmt 64 -conc -proc CreateSemaphoreExA
hash_api -fmt 64 -conc -proc CreateSemaphoreExW
hash_api -fmt 64 -conc -proc CreateWaitableTimerA
hash_api -fmt 64 -conc -proc CreateWaitableTimerW
hash_api -fmt 64 -conc -proc CreateWaitableTimerExA
hash_api -fmt 64 -conc -proc CreateWaitableTimerExW
hash_api -fmt 64 -conc -proc CreateFileA
hash_api -fmt 64 -conc -proc CreateFileW
hash_api -fmt 64 -conc -proc FindFirstFileA
hash_api -fmt 64 -conc -proc FindFirstFileW
hash_api -fmt 64 -conc -proc FindFirstFileExA
hash_api -fmt 64 -conc -proc FindFirstFileExW
hash_api -fmt 64 -conc -proc FindClose
hash_api -fmt 64 -conc -proc CreateIoCompletionPort
hash_api -fmt 64 -conc -proc CancelIoEx
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc RegCreateKeyA
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc RegCreateKeyW
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc RegCreateKeyExA
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc RegCreateKeyExW
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc RegOpenKeyA
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc RegOpenKeyW
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc RegOpenKeyExA
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc RegOpenKeyExW
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc RegCloseKey
hash_api -fmt 64 -conc -mod "ws2_32.dll" -proc WSAStartup
hash_api -fmt 64 -conc -mod "ws2_32.dll" -proc WSACleanup
hash_api -fmt 64 -conc -mod "ws2_32.dll" -proc WSASocketA
hash_api -fmt 64 -conc -mod "ws2_32.dll" -proc WSASocketW
hash_api -fmt 64 -conc -mod "ws2_32.dll" -proc WSAIoctl
hash_api -fmt 64 -conc -mod "ws2_32.dll" -proc socket
hash_api -fmt 64 -conc -mod "ws2_32.dll" -proc accept
hash_api -fmt 64 -conc -mod "ws2_32.dll" -proc shutdown
hash_api -fmt 64 -conc -mod "ws2_32.dll" -proc closesocket
hash_api -fmt 64 -conc -mod "mswsock.dll" -proc AcceptEx
echo.

echo [Argument Store]
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc AS_GetValue
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc AS_GetPointer
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc AS_Erase
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc AS_EraseAll
echo.

echo [In-Memory Storage]
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc IMS_SetValue
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc IMS_GetValue
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc IMS_GetPointer
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc IMS_Delete
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc IMS_DeleteAll
echo.

echo [WinBase Module]
hash_api -fmt 64 -conc -proc MultiByteToWideChar
hash_api -fmt 64 -conc -proc WideCharToMultiByte
echo.

echo [WinFile Module]
hash_api -fmt 64 -conc -proc CreateFileA
hash_api -fmt 64 -conc -proc CreateFileW
hash_api -fmt 64 -conc -proc GetFileSizeEx
hash_api -fmt 64 -conc -proc ReadFile
hash_api -fmt 64 -conc -proc WriteFile
echo.

echo [WinHTTP Module]
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpCrackUrl
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpOpen
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpConnect
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpSetOption
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpSetTimeouts
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpOpenRequest
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpSetCredentials
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpSendRequest
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpReceiveResponse
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpQueryHeaders
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpQueryDataAvailable
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpReadData
hash_api -fmt 64 -conc -mod "winhttp.dll" -proc WinHttpCloseHandle
echo.

echo [WinCrypto Module]
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptAcquireContextA
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptReleaseContext
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptGenRandom
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptGenKey
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptExportKey
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptCreateHash
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptSetHashParam
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptGetHashParam
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptHashData
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptDestroyHash
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptImportKey
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptSetKeyParam
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptEncrypt
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptDecrypt
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptDestroyKey
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptSignHashA
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc CryptVerifySignatureA
echo.

echo [Sysmon Module]
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc SM_Pause
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc SM_Continue
echo.

echo [Watchdog Module]
hash_api -fmt 64 -conc -proc ResetEvent
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_Kick
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_Enable
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_Disable
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_IsEnabled
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_SetHandler
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_Pause
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_Continue
echo.

echo ------------------------x86------------------------

echo [Runtime Core]
hash_api -fmt 32 -conc -proc GetSystemInfo
hash_api -fmt 32 -conc -proc LoadLibraryA
hash_api -fmt 32 -conc -proc FreeLibrary
hash_api -fmt 32 -conc -proc GetProcAddress
hash_api -fmt 32 -conc -proc VirtualAlloc
hash_api -fmt 32 -conc -proc VirtualFree
hash_api -fmt 32 -conc -proc VirtualProtect
hash_api -fmt 32 -conc -proc FlushInstructionCache
hash_api -fmt 32 -conc -proc SuspendThread
hash_api -fmt 32 -conc -proc ResumeThread
hash_api -fmt 32 -conc -proc ExitThread
hash_api -fmt 32 -conc -proc CreateMutexA
hash_api -fmt 32 -conc -proc ReleaseMutex
hash_api -fmt 32 -conc -proc CreateEventA
hash_api -fmt 32 -conc -proc SetEvent
hash_api -fmt 32 -conc -proc CreateWaitableTimerA
hash_api -fmt 32 -conc -proc SetWaitableTimer
hash_api -fmt 32 -conc -proc WaitForSingleObject
hash_api -fmt 32 -conc -proc WaitForMultipleObjects
hash_api -fmt 32 -conc -proc DuplicateHandle
hash_api -fmt 32 -conc -proc CloseHandle
hash_api -fmt 32 -conc -proc SetCurrentDirectoryA
hash_api -fmt 32 -conc -proc SetCurrentDirectoryW
hash_api -fmt 32 -conc -proc SleepEx
hash_api -fmt 32 -conc -proc ExitProcess
echo.

echo [Runtime IAT Hooks]
hash_api -fmt 32 -conc -proc GetProcAddress
hash_api -fmt 32 -conc -proc SetCurrentDirectoryA
hash_api -fmt 32 -conc -proc SetCurrentDirectoryW
hash_api -fmt 32 -conc -proc Sleep
hash_api -fmt 32 -conc -proc SleepEx
echo.

echo [Runtime Methods]
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc GetProcAddressByName
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc GetProcAddressByHash
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc GetProcAddressOriginal
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc GetMetrics
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc ExitProcess
echo.

echo [Library Tracker]
hash_api -fmt 32 -conc -proc LoadLibraryA
hash_api -fmt 32 -conc -proc LoadLibraryW
hash_api -fmt 32 -conc -proc LoadLibraryExA
hash_api -fmt 32 -conc -proc LoadLibraryExW
hash_api -fmt 32 -conc -proc FreeLibrary
hash_api -fmt 32 -conc -proc FreeLibraryAndExitThread
echo.

echo [Memory Tracker]
hash_api -fmt 32 -conc -proc VirtualAlloc
hash_api -fmt 32 -conc -proc VirtualFree
hash_api -fmt 32 -conc -proc VirtualProtect
hash_api -fmt 32 -conc -proc VirtualQuery
hash_api -fmt 32 -conc -proc GetProcessHeap
hash_api -fmt 32 -conc -proc GetProcessHeaps
hash_api -fmt 32 -conc -proc HeapCreate
hash_api -fmt 32 -conc -proc HeapDestroy
hash_api -fmt 32 -conc -proc HeapAlloc
hash_api -fmt 32 -conc -proc HeapReAlloc
hash_api -fmt 32 -conc -proc HeapFree
hash_api -fmt 32 -conc -proc HeapSize
hash_api -fmt 32 -conc -proc HeapLock
hash_api -fmt 32 -conc -proc HeapUnlock
hash_api -fmt 32 -conc -proc HeapWalk
hash_api -fmt 32 -conc -proc GlobalAlloc
hash_api -fmt 32 -conc -proc GlobalReAlloc
hash_api -fmt 32 -conc -proc GlobalFree
hash_api -fmt 32 -conc -proc LocalAlloc
hash_api -fmt 32 -conc -proc LocalReAlloc
hash_api -fmt 32 -conc -proc LocalFree
hash_api -fmt 32 -conc -mod "ntdll.dll" -proc RtlAllocateHeap
hash_api -fmt 32 -conc -mod "ntdll.dll" -proc RtlReAllocateHeap
hash_api -fmt 32 -conc -mod "ntdll.dll" -proc RtlFreeHeap
hash_api -fmt 32 -conc -mod "ntdll.dll" -proc RtlSizeHeap
hash_api -fmt 32 -conc -mod "msvcrt.dll" -proc malloc
hash_api -fmt 32 -conc -mod "msvcrt.dll" -proc calloc
hash_api -fmt 32 -conc -mod "msvcrt.dll" -proc realloc
hash_api -fmt 32 -conc -mod "msvcrt.dll" -proc free
hash_api -fmt 32 -conc -mod "msvcrt.dll" -proc _msize
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc malloc
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc calloc
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc realloc
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc free
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _msize
echo.

echo [Thread Tracker]
hash_api -fmt 32 -conc -proc CreateThread
hash_api -fmt 32 -conc -proc ExitThread
hash_api -fmt 32 -conc -proc SuspendThread
hash_api -fmt 32 -conc -proc ResumeThread
hash_api -fmt 32 -conc -proc SwitchToThread
hash_api -fmt 32 -conc -proc GetThreadContext
hash_api -fmt 32 -conc -proc SetThreadContext
hash_api -fmt 32 -conc -proc GetThreadId
hash_api -fmt 32 -conc -proc GetCurrentThreadId
hash_api -fmt 32 -conc -proc TerminateThread
hash_api -fmt 32 -conc -proc TlsAlloc
hash_api -fmt 32 -conc -proc TlsFree
hash_api -fmt 32 -conc -proc CreateWaitableTimerA
hash_api -fmt 32 -conc -proc SetWaitableTimer
hash_api -fmt 32 -conc -mod "ntdll.dll" -proc RtlExitUserThread
echo.

echo [Resource Tracker]
hash_api -fmt 32 -conc -proc CreateMutexA
hash_api -fmt 32 -conc -proc CreateMutexW
hash_api -fmt 32 -conc -proc CreateMutexExA
hash_api -fmt 32 -conc -proc CreateMutexExW
hash_api -fmt 32 -conc -proc CreateEventA
hash_api -fmt 32 -conc -proc CreateEventW
hash_api -fmt 32 -conc -proc CreateEventExA
hash_api -fmt 32 -conc -proc CreateEventExW
hash_api -fmt 32 -conc -proc CreateSemaphoreA
hash_api -fmt 32 -conc -proc CreateSemaphoreW
hash_api -fmt 32 -conc -proc CreateSemaphoreExA
hash_api -fmt 32 -conc -proc CreateSemaphoreExW
hash_api -fmt 32 -conc -proc CreateWaitableTimerA
hash_api -fmt 32 -conc -proc CreateWaitableTimerW
hash_api -fmt 32 -conc -proc CreateWaitableTimerExA
hash_api -fmt 32 -conc -proc CreateWaitableTimerExW
hash_api -fmt 32 -conc -proc CreateFileA
hash_api -fmt 32 -conc -proc CreateFileW
hash_api -fmt 32 -conc -proc FindFirstFileA
hash_api -fmt 32 -conc -proc FindFirstFileW
hash_api -fmt 32 -conc -proc FindFirstFileExA
hash_api -fmt 32 -conc -proc FindFirstFileExW
hash_api -fmt 32 -conc -proc FindClose
hash_api -fmt 32 -conc -proc CreateIoCompletionPort
hash_api -fmt 32 -conc -proc CancelIoEx
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc RegCreateKeyA
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc RegCreateKeyW
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc RegCreateKeyExA
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc RegCreateKeyExW
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc RegOpenKeyA
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc RegOpenKeyW
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc RegOpenKeyExA
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc RegOpenKeyExW
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc RegCloseKey
hash_api -fmt 32 -conc -mod "ws2_32.dll" -proc WSAStartup
hash_api -fmt 32 -conc -mod "ws2_32.dll" -proc WSACleanup
hash_api -fmt 32 -conc -mod "ws2_32.dll" -proc WSASocketA
hash_api -fmt 32 -conc -mod "ws2_32.dll" -proc WSASocketW
hash_api -fmt 32 -conc -mod "ws2_32.dll" -proc WSAIoctl
hash_api -fmt 32 -conc -mod "ws2_32.dll" -proc socket
hash_api -fmt 32 -conc -mod "ws2_32.dll" -proc accept
hash_api -fmt 32 -conc -mod "ws2_32.dll" -proc shutdown
hash_api -fmt 32 -conc -mod "ws2_32.dll" -proc closesocket
hash_api -fmt 32 -conc -mod "mswsock.dll" -proc AcceptEx
echo.

echo [Argument Store]
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc AS_GetValue
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc AS_GetPointer
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc AS_Erase
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc AS_EraseAll
echo.

echo [In-Memory Storage]
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc IMS_SetValue
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc IMS_GetValue
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc IMS_GetPointer
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc IMS_Delete
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc IMS_DeleteAll
echo.

echo [WinBase Module]
hash_api -fmt 32 -conc -proc MultiByteToWideChar
hash_api -fmt 32 -conc -proc WideCharToMultiByte
echo.

echo [WinFile Module]
hash_api -fmt 32 -conc -proc CreateFileA
hash_api -fmt 32 -conc -proc CreateFileW
hash_api -fmt 32 -conc -proc GetFileSizeEx
hash_api -fmt 32 -conc -proc ReadFile
hash_api -fmt 32 -conc -proc WriteFile
echo.

echo [WinHTTP Module]
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpCrackUrl
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpOpen
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpConnect
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpSetOption
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpSetTimeouts
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpOpenRequest
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpSetCredentials
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpSendRequest
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpReceiveResponse
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpQueryHeaders
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpQueryDataAvailable
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpReadData
hash_api -fmt 32 -conc -mod "winhttp.dll" -proc WinHttpCloseHandle
echo.

echo [WinCrypto Module]
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptAcquireContextA
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptReleaseContext
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptGenRandom
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptGenKey
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptExportKey
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptCreateHash
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptSetHashParam
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptGetHashParam
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptHashData
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptDestroyHash
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptImportKey
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptSetKeyParam
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptEncrypt
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptDecrypt
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptDestroyKey
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptSignHashA
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc CryptVerifySignatureA
echo.

echo [Sysmon Module]
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc SM_Pause
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc SM_Continue
echo.

echo [Watchdog Module]
hash_api -fmt 32 -conc -proc ResetEvent
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_Kick
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_Enable
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_Disable
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_IsEnabled
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_SetHandler
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_Pause
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_Continue
echo.

pause
