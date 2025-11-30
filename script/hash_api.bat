@echo off

echo =====================================================================
echo Build HashAPI tool from https://github.com/RSSU-Shellcode/GRT-Develop
echo =====================================================================
echo.

echo ------------------------x64------------------------

echo [Runtime Core]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetSystemInfo
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetTickCount
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LoadLibraryA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FreeLibrary
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetProcAddress
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualFree
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualProtect
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualQuery
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FlushInstructionCache
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SuspendThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ResumeThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetThreadContext
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ExitThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateMutexA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ReleaseMutex
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateEventA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SetEvent
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateWaitableTimerA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SetWaitableTimer
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc WaitForSingleObject
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc WaitForMultipleObjects
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc DuplicateHandle
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CloseHandle
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SetCurrentDirectoryA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SetCurrentDirectoryW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SetErrorMode
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SleepEx
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ExitProcess
echo.

echo [API Redirector]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetProcAddress
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SetCurrentDirectoryA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SetCurrentDirectoryW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SetErrorMode
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc Sleep
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SleepEx
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LoadLibraryA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LoadLibraryW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LoadLibraryExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LoadLibraryExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FreeLibrary
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FreeLibraryAndExitThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualFree
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualProtect
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualQuery
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapCreate
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapDestroy
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapReAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapFree
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapSize
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GlobalAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GlobalReAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GlobalFree
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LocalAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LocalReAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LocalFree
hash_api -fmt 64 -conc -mod "ntdll.dll"	-proc RtlAllocateHeap
hash_api -fmt 64 -conc -mod "ntdll.dll"	-proc RtlReAllocateHeap
hash_api -fmt 64 -conc -mod "ntdll.dll"	-proc RtlFreeHeap
hash_api -fmt 64 -conc -mod "ntdll.dll"	-proc RtlSizeHeap
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ExitThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SuspendThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ResumeThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SwitchToThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetThreadContext
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SetThreadContext
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc TerminateThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc TlsAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc TlsFree
hash_api -fmt 64 -conc -mod "ntdll.dll"	-proc RtlExitUserThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateMutexA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateMutexW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateMutexExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateMutexExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateEventA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateEventW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateEventExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateEventExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateSemaphoreA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateSemaphoreW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateSemaphoreExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateSemaphoreExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateWaitableTimerA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateWaitableTimerW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateWaitableTimerExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateWaitableTimerExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateFileA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateFileW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FindFirstFileA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FindFirstFileW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FindFirstFileExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FindFirstFileExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateIoCompletionPort
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CloseHandle
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FindClose
echo.

echo [Runtime Methods]
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc RT_GetProcAddressByName
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc RT_GetProcAddressByHash
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc RT_GetProcAddressByHashML
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc RT_GetProcAddressOriginal
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc RT_GetPEB
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc RT_GetTEB
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc RT_GetIMOML
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc RT_GetMetrics
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc RT_Sleep
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc RT_ExitProcess
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc AS_GetValue
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc AS_GetPointer
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc AS_Erase
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc AS_EraseAll
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc IS_SetValue
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc IS_GetValue
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc IS_GetPointer
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc IS_Delete
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc IS_DeleteAll
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc DT_Detect
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc DT_Status
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc SM_Status
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_SetHandler
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_Kick
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_Enable
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_Disable
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_IsEnabled
hash_api -fmt 64 -conc -mod "GleamRT.dll" -proc WD_Status
echo.

echo [Lazy API Redirector]
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
echo.

echo [Detector]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc K32QueryWorkingSetEx
hash_api -fmt 64 -conc -mod "psapi.dll" -proc QueryWorkingSetEx
echo.

echo [Library Tracker]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LoadLibraryW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LoadLibraryExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LoadLibraryExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FreeLibraryAndExitThread
echo.

echo [Memory Tracker]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetProcessHeap
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetProcessHeaps
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapCreate
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapDestroy
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapReAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapFree
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapSize
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapLock
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapUnlock
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc HeapWalk
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GlobalAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GlobalReAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GlobalFree
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LocalAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LocalReAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LocalFree
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
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SwitchToThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc SetThreadContext
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetThreadId
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetCurrentThreadId
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc TerminateThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc TlsAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc TlsFree
echo.

echo [Resource Tracker]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateMutexA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateMutexW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateMutexExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateMutexExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateEventA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateEventW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateEventExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateEventExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateSemaphoreA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateSemaphoreW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateSemaphoreExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateSemaphoreExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateWaitableTimerA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateWaitableTimerW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateWaitableTimerExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateWaitableTimerExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateFileA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateFileW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FindFirstFileA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FindFirstFileW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FindFirstFileExA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FindFirstFileExW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FindClose
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateIoCompletionPort
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
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CancelIoEx
hash_api -fmt 64 -conc -mod "advapi32.dll" -proc RegCloseKey
hash_api -fmt 64 -conc -mod "ws2_32.dll"   -proc shutdown
hash_api -fmt 64 -conc -mod "ws2_32.dll"   -proc closesocket
echo.

echo [WinBase Module]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc MultiByteToWideChar
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc WideCharToMultiByte
echo.

echo [WinFile Module]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateFileA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateFileW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetFileSizeEx
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ReadFile
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc WriteFile
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

echo [Watchdog Module]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ResetEvent
echo.

echo ------------------------x86------------------------

echo [Runtime Core]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetSystemInfo
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetTickCount
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LoadLibraryA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FreeLibrary
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetProcAddress
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualFree
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualProtect
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualQuery
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FlushInstructionCache
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SuspendThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ResumeThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetThreadContext
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ExitThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateMutexA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ReleaseMutex
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateEventA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SetEvent
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateWaitableTimerA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SetWaitableTimer
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc WaitForSingleObject
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc WaitForMultipleObjects
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc DuplicateHandle
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CloseHandle
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SetCurrentDirectoryA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SetCurrentDirectoryW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SetErrorMode
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SleepEx
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ExitProcess
echo.

echo [API Redirector]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetProcAddress
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SetCurrentDirectoryA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SetCurrentDirectoryW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SetErrorMode
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc Sleep
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SleepEx
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LoadLibraryA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LoadLibraryW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LoadLibraryExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LoadLibraryExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FreeLibrary
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FreeLibraryAndExitThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualFree
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualProtect
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualQuery
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapCreate
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapDestroy
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapReAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapFree
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapSize
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GlobalAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GlobalReAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GlobalFree
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LocalAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LocalReAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LocalFree
hash_api -fmt 32 -conc -mod "ntdll.dll"	-proc RtlAllocateHeap
hash_api -fmt 32 -conc -mod "ntdll.dll"	-proc RtlReAllocateHeap
hash_api -fmt 32 -conc -mod "ntdll.dll"	-proc RtlFreeHeap
hash_api -fmt 32 -conc -mod "ntdll.dll"	-proc RtlSizeHeap
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ExitThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SuspendThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ResumeThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SwitchToThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetThreadContext
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SetThreadContext
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc TerminateThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc TlsAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc TlsFree
hash_api -fmt 32 -conc -mod "ntdll.dll"	-proc RtlExitUserThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateMutexA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateMutexW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateMutexExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateMutexExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateEventA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateEventW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateEventExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateEventExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateSemaphoreA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateSemaphoreW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateSemaphoreExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateSemaphoreExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateWaitableTimerA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateWaitableTimerW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateWaitableTimerExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateWaitableTimerExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateFileA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateFileW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FindFirstFileA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FindFirstFileW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FindFirstFileExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FindFirstFileExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateIoCompletionPort
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CloseHandle
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FindClose
echo.

echo [Runtime Methods]
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc RT_GetProcAddressByName
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc RT_GetProcAddressByHash
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc RT_GetProcAddressByHashML
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc RT_GetProcAddressOriginal
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc RT_GetPEB
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc RT_GetTEB
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc RT_GetIMOML
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc RT_GetMetrics
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc RT_Sleep
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc RT_ExitProcess
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc AS_GetValue
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc AS_GetPointer
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc AS_Erase
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc AS_EraseAll
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc IS_SetValue
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc IS_GetValue
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc IS_GetPointer
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc IS_Delete
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc IS_DeleteAll
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc DT_Detect
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc DT_Status
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc SM_Status
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_SetHandler
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_Kick
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_Enable
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_Disable
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_IsEnabled
hash_api -fmt 32 -conc -mod "GleamRT.dll" -proc WD_Status
echo.

echo [Lazy API Redirector]
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
echo.

echo [Detector]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc K32QueryWorkingSetEx
hash_api -fmt 32 -conc -mod "psapi.dll" -proc QueryWorkingSetEx
echo.

echo [Library Tracker]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LoadLibraryW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LoadLibraryExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LoadLibraryExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FreeLibraryAndExitThread
echo.

echo [Memory Tracker]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetProcessHeap
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetProcessHeaps
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapCreate
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapDestroy
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapReAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapFree
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapSize
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapLock
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapUnlock
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc HeapWalk
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GlobalAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GlobalReAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GlobalFree
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LocalAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LocalReAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LocalFree
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
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SwitchToThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc SetThreadContext
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetThreadId
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetCurrentThreadId
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc TerminateThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc TlsAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc TlsFree
echo.

echo [Resource Tracker]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateMutexA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateMutexW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateMutexExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateMutexExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateEventA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateEventW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateEventExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateEventExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateSemaphoreA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateSemaphoreW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateSemaphoreExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateSemaphoreExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateWaitableTimerA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateWaitableTimerW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateWaitableTimerExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateWaitableTimerExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateFileA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateFileW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FindFirstFileA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FindFirstFileW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FindFirstFileExA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FindFirstFileExW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FindClose
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateIoCompletionPort
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
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CancelIoEx
hash_api -fmt 32 -conc -mod "advapi32.dll" -proc RegCloseKey
hash_api -fmt 32 -conc -mod "ws2_32.dll"   -proc shutdown
hash_api -fmt 32 -conc -mod "ws2_32.dll"   -proc closesocket
echo.

echo [WinBase Module]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc MultiByteToWideChar
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc WideCharToMultiByte
echo.

echo [WinFile Module]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateFileA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateFileW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetFileSizeEx
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ReadFile
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc WriteFile
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

echo [Watchdog Module]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ResetEvent
echo.

pause
