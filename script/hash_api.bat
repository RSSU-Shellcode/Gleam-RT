@echo off

echo =====================================================================
echo Build HashAPI tool from https://github.com/RSSU-Shellcode/GRT-Develop
echo =====================================================================
echo.

echo ------------------------x64------------------------

echo [Runtime Core]
hash_api -fmt 64 -conc -func GetSystemInfo
hash_api -fmt 64 -conc -func LoadLibraryA
hash_api -fmt 64 -conc -func FreeLibrary
hash_api -fmt 64 -conc -func GetProcAddress
hash_api -fmt 64 -conc -func VirtualAlloc
hash_api -fmt 64 -conc -func VirtualFree
hash_api -fmt 64 -conc -func VirtualProtect
hash_api -fmt 64 -conc -func FlushInstructionCache
hash_api -fmt 64 -conc -func CreateMutexA
hash_api -fmt 64 -conc -func ReleaseMutex
hash_api -fmt 64 -conc -func CreateWaitableTimerA
hash_api -fmt 64 -conc -func SetWaitableTimer
hash_api -fmt 64 -conc -func WaitForSingleObject
hash_api -fmt 64 -conc -func DuplicateHandle
hash_api -fmt 64 -conc -func CloseHandle
hash_api -fmt 64 -conc -func SetCurrentDirectoryA
hash_api -fmt 64 -conc -func SetCurrentDirectoryW
hash_api -fmt 64 -conc -func SleepEx
hash_api -fmt 64 -conc -func ExitProcess
echo.

echo [Runtime IAT Hooks]
hash_api -fmt 64 -conc -func GetProcAddress
hash_api -fmt 64 -conc -func SetCurrentDirectoryA
hash_api -fmt 64 -conc -func SetCurrentDirectoryW
hash_api -fmt 64 -conc -func Sleep
hash_api -fmt 64 -conc -func SleepEx
echo.

echo [Runtime Methods]
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func GetProcAddressByName
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func GetProcAddressByHash
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func GetProcAddressOriginal
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func ExitProcess
echo.

echo [Library Tracker]
hash_api -fmt 64 -conc -func LoadLibraryA
hash_api -fmt 64 -conc -func LoadLibraryW
hash_api -fmt 64 -conc -func LoadLibraryExA
hash_api -fmt 64 -conc -func LoadLibraryExW
hash_api -fmt 64 -conc -func FreeLibrary
hash_api -fmt 64 -conc -func FreeLibraryAndExitThread
echo.

echo [Memory Tracker]
hash_api -fmt 64 -conc -func VirtualAlloc
hash_api -fmt 64 -conc -func VirtualFree
hash_api -fmt 64 -conc -func VirtualProtect
hash_api -fmt 64 -conc -func VirtualQuery
hash_api -fmt 64 -conc -func GetProcessHeap
hash_api -fmt 64 -conc -func GetProcessHeaps
hash_api -fmt 64 -conc -func HeapCreate
hash_api -fmt 64 -conc -func HeapDestroy
hash_api -fmt 64 -conc -func HeapAlloc
hash_api -fmt 64 -conc -func HeapReAlloc
hash_api -fmt 64 -conc -func HeapFree
hash_api -fmt 64 -conc -func HeapSize
hash_api -fmt 64 -conc -func HeapLock
hash_api -fmt 64 -conc -func HeapUnlock
hash_api -fmt 64 -conc -func HeapWalk
hash_api -fmt 64 -conc -func GlobalAlloc
hash_api -fmt 64 -conc -func GlobalReAlloc
hash_api -fmt 64 -conc -func GlobalFree
hash_api -fmt 64 -conc -func LocalAlloc
hash_api -fmt 64 -conc -func LocalReAlloc
hash_api -fmt 64 -conc -func LocalFree
hash_api -fmt 64 -conc -mod "ntdll.dll" -func RtlAllocateHeap
hash_api -fmt 64 -conc -mod "ntdll.dll" -func RtlReAllocateHeap
hash_api -fmt 64 -conc -mod "ntdll.dll" -func RtlFreeHeap
hash_api -fmt 64 -conc -mod "ntdll.dll" -func RtlSizeHeap
hash_api -fmt 64 -conc -mod "msvcrt.dll" -func malloc
hash_api -fmt 64 -conc -mod "msvcrt.dll" -func calloc
hash_api -fmt 64 -conc -mod "msvcrt.dll" -func realloc
hash_api -fmt 64 -conc -mod "msvcrt.dll" -func free
hash_api -fmt 64 -conc -mod "msvcrt.dll" -func _msize
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func malloc
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func calloc
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func realloc
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func free
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -func _msize
echo.

echo [Thread Tracker]
hash_api -fmt 64 -conc -func CreateThread
hash_api -fmt 64 -conc -func ExitThread
hash_api -fmt 64 -conc -func SuspendThread
hash_api -fmt 64 -conc -func ResumeThread
hash_api -fmt 64 -conc -func GetThreadContext
hash_api -fmt 64 -conc -func SetThreadContext
hash_api -fmt 64 -conc -func GetThreadId
hash_api -fmt 64 -conc -func GetCurrentThreadId
hash_api -fmt 64 -conc -func TerminateThread
hash_api -fmt 64 -conc -func TlsAlloc
hash_api -fmt 64 -conc -func TlsFree
hash_api -fmt 64 -conc -func CreateWaitableTimerA
hash_api -fmt 64 -conc -func SetWaitableTimer
hash_api -fmt 64 -conc -mod "ntdll.dll" -func RtlExitUserThread
echo.

echo [Resource Tracker]
hash_api -fmt 64 -conc -func CreateMutexA
hash_api -fmt 64 -conc -func CreateMutexW
hash_api -fmt 64 -conc -func CreateMutexExA
hash_api -fmt 64 -conc -func CreateMutexExW
hash_api -fmt 64 -conc -func CreateEventA
hash_api -fmt 64 -conc -func CreateEventW
hash_api -fmt 64 -conc -func CreateEventExA
hash_api -fmt 64 -conc -func CreateEventExW
hash_api -fmt 64 -conc -func CreateSemaphoreA
hash_api -fmt 64 -conc -func CreateSemaphoreW
hash_api -fmt 64 -conc -func CreateSemaphoreExA
hash_api -fmt 64 -conc -func CreateSemaphoreExW
hash_api -fmt 64 -conc -func CreateWaitableTimerA
hash_api -fmt 64 -conc -func CreateWaitableTimerW
hash_api -fmt 64 -conc -func CreateWaitableTimerExA
hash_api -fmt 64 -conc -func CreateWaitableTimerExW
hash_api -fmt 64 -conc -func CreateFileA
hash_api -fmt 64 -conc -func CreateFileW
hash_api -fmt 64 -conc -func FindFirstFileA
hash_api -fmt 64 -conc -func FindFirstFileW
hash_api -fmt 64 -conc -func FindFirstFileExA
hash_api -fmt 64 -conc -func FindFirstFileExW
hash_api -fmt 64 -conc -func FindClose
hash_api -fmt 64 -conc -func CreateIoCompletionPort
hash_api -fmt 64 -conc -mod "advapi32.dll" -func RegCreateKeyA
hash_api -fmt 64 -conc -mod "advapi32.dll" -func RegCreateKeyW
hash_api -fmt 64 -conc -mod "advapi32.dll" -func RegCreateKeyExA
hash_api -fmt 64 -conc -mod "advapi32.dll" -func RegCreateKeyExW
hash_api -fmt 64 -conc -mod "advapi32.dll" -func RegOpenKeyA
hash_api -fmt 64 -conc -mod "advapi32.dll" -func RegOpenKeyW
hash_api -fmt 64 -conc -mod "advapi32.dll" -func RegOpenKeyExA
hash_api -fmt 64 -conc -mod "advapi32.dll" -func RegOpenKeyExW
hash_api -fmt 64 -conc -mod "advapi32.dll" -func RegCloseKey
hash_api -fmt 64 -conc -mod "ws2_32.dll" -func WSAStartup
hash_api -fmt 64 -conc -mod "ws2_32.dll" -func WSACleanup
hash_api -fmt 64 -conc -mod "ws2_32.dll" -func WSASocketA
hash_api -fmt 64 -conc -mod "ws2_32.dll" -func WSASocketW
hash_api -fmt 64 -conc -mod "ws2_32.dll" -func socket
hash_api -fmt 64 -conc -mod "ws2_32.dll" -func accept
hash_api -fmt 64 -conc -mod "ws2_32.dll" -func closesocket
hash_api -fmt 64 -conc -mod "mswsock.dll" -func AcceptEx
echo.

echo [Argument Store]
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func AS_GetValue
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func AS_GetPointer
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func AS_Erase
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func AS_EraseAll
echo.

echo [In-Memory Storage]
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func IMS_SetValue
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func IMS_GetValue
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func IMS_GetPointer
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func IMS_Delete
hash_api -fmt 64 -conc -mod "GleamRT.dll" -func IMS_DeleteAll
echo.

echo [WinBase Module]
hash_api -fmt 64 -conc -func MultiByteToWideChar
hash_api -fmt 64 -conc -func WideCharToMultiByte
echo.

echo [WinFile Module]
hash_api -fmt 64 -conc -func CreateFileA
hash_api -fmt 64 -conc -func CreateFileW
hash_api -fmt 64 -conc -func GetFileSizeEx
hash_api -fmt 64 -conc -func ReadFile
hash_api -fmt 64 -conc -func WriteFile
echo.

echo [WinHTTP Module]
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpCrackUrl
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpOpen
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpConnect
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpSetOption
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpSetTimeouts
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpOpenRequest
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpSetCredentials
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpSendRequest
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpReceiveResponse
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpQueryHeaders
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpQueryDataAvailable
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpReadData
hash_api -fmt 64 -conc -mod "winhttp.dll" -func WinHttpCloseHandle
echo.

echo [WinCrypto Module]
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptAcquireContextA
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptReleaseContext
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptGenRandom
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptGenKey
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptExportKey
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptCreateHash
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptSetHashParam
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptGetHashParam
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptHashData
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptDestroyHash
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptImportKey
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptSetKeyParam
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptEncrypt
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptDecrypt
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptDestroyKey
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptSignHashA
hash_api -fmt 64 -conc -mod "advapi32.dll" -func CryptVerifySignatureA
echo.

echo ------------------------x86------------------------

echo [Runtime Core]
hash_api -fmt 32 -conc -func GetSystemInfo
hash_api -fmt 32 -conc -func LoadLibraryA
hash_api -fmt 32 -conc -func FreeLibrary
hash_api -fmt 32 -conc -func GetProcAddress
hash_api -fmt 32 -conc -func VirtualAlloc
hash_api -fmt 32 -conc -func VirtualFree
hash_api -fmt 32 -conc -func VirtualProtect
hash_api -fmt 32 -conc -func FlushInstructionCache
hash_api -fmt 32 -conc -func CreateMutexA
hash_api -fmt 32 -conc -func ReleaseMutex
hash_api -fmt 32 -conc -func CreateWaitableTimerA
hash_api -fmt 32 -conc -func SetWaitableTimer
hash_api -fmt 32 -conc -func WaitForSingleObject
hash_api -fmt 32 -conc -func DuplicateHandle
hash_api -fmt 32 -conc -func CloseHandle
hash_api -fmt 32 -conc -func SetCurrentDirectoryA
hash_api -fmt 32 -conc -func SetCurrentDirectoryW
hash_api -fmt 32 -conc -func SleepEx
hash_api -fmt 32 -conc -func ExitProcess
echo.

echo [Runtime IAT Hooks]
hash_api -fmt 32 -conc -func GetProcAddress
hash_api -fmt 32 -conc -func SetCurrentDirectoryA
hash_api -fmt 32 -conc -func SetCurrentDirectoryW
hash_api -fmt 32 -conc -func Sleep
hash_api -fmt 32 -conc -func SleepEx
echo.

echo [Runtime Methods]
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func GetProcAddressByName
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func GetProcAddressByHash
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func GetProcAddressOriginal
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func ExitProcess
echo.

echo [Library Tracker]
hash_api -fmt 32 -conc -func LoadLibraryA
hash_api -fmt 32 -conc -func LoadLibraryW
hash_api -fmt 32 -conc -func LoadLibraryExA
hash_api -fmt 32 -conc -func LoadLibraryExW
hash_api -fmt 32 -conc -func FreeLibrary
hash_api -fmt 32 -conc -func FreeLibraryAndExitThread
echo.

echo [Memory Tracker]
hash_api -fmt 32 -conc -func VirtualAlloc
hash_api -fmt 32 -conc -func VirtualFree
hash_api -fmt 32 -conc -func VirtualProtect
hash_api -fmt 32 -conc -func VirtualQuery
hash_api -fmt 32 -conc -func GetProcessHeap
hash_api -fmt 32 -conc -func GetProcessHeaps
hash_api -fmt 32 -conc -func HeapCreate
hash_api -fmt 32 -conc -func HeapDestroy
hash_api -fmt 32 -conc -func HeapAlloc
hash_api -fmt 32 -conc -func HeapReAlloc
hash_api -fmt 32 -conc -func HeapFree
hash_api -fmt 32 -conc -func HeapSize
hash_api -fmt 32 -conc -func HeapLock
hash_api -fmt 32 -conc -func HeapUnlock
hash_api -fmt 32 -conc -func HeapWalk
hash_api -fmt 32 -conc -func GlobalAlloc
hash_api -fmt 32 -conc -func GlobalReAlloc
hash_api -fmt 32 -conc -func GlobalFree
hash_api -fmt 32 -conc -func LocalAlloc
hash_api -fmt 32 -conc -func LocalReAlloc
hash_api -fmt 32 -conc -func LocalFree
hash_api -fmt 32 -conc -mod "ntdll.dll" -func RtlAllocateHeap
hash_api -fmt 32 -conc -mod "ntdll.dll" -func RtlReAllocateHeap
hash_api -fmt 32 -conc -mod "ntdll.dll" -func RtlFreeHeap
hash_api -fmt 32 -conc -mod "ntdll.dll" -func RtlSizeHeap
hash_api -fmt 32 -conc -mod "msvcrt.dll" -func malloc
hash_api -fmt 32 -conc -mod "msvcrt.dll" -func calloc
hash_api -fmt 32 -conc -mod "msvcrt.dll" -func realloc
hash_api -fmt 32 -conc -mod "msvcrt.dll" -func free
hash_api -fmt 32 -conc -mod "msvcrt.dll" -func _msize
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func malloc
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func calloc
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func realloc
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func free
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -func _msize
echo.

echo [Thread Tracker]
hash_api -fmt 32 -conc -func CreateThread
hash_api -fmt 32 -conc -func ExitThread
hash_api -fmt 32 -conc -func SuspendThread
hash_api -fmt 32 -conc -func ResumeThread
hash_api -fmt 32 -conc -func GetThreadContext
hash_api -fmt 32 -conc -func SetThreadContext
hash_api -fmt 32 -conc -func GetThreadId
hash_api -fmt 32 -conc -func GetCurrentThreadId
hash_api -fmt 32 -conc -func TerminateThread
hash_api -fmt 32 -conc -func TlsAlloc
hash_api -fmt 32 -conc -func TlsFree
hash_api -fmt 32 -conc -func CreateWaitableTimerA
hash_api -fmt 32 -conc -func SetWaitableTimer
hash_api -fmt 32 -conc -mod "ntdll.dll" -func RtlExitUserThread
echo.

echo [Resource Tracker]
hash_api -fmt 32 -conc -func CreateMutexA
hash_api -fmt 32 -conc -func CreateMutexW
hash_api -fmt 32 -conc -func CreateMutexExA
hash_api -fmt 32 -conc -func CreateMutexExW
hash_api -fmt 32 -conc -func CreateEventA
hash_api -fmt 32 -conc -func CreateEventW
hash_api -fmt 32 -conc -func CreateEventExA
hash_api -fmt 32 -conc -func CreateEventExW
hash_api -fmt 32 -conc -func CreateSemaphoreA
hash_api -fmt 32 -conc -func CreateSemaphoreW
hash_api -fmt 32 -conc -func CreateSemaphoreExA
hash_api -fmt 32 -conc -func CreateSemaphoreExW
hash_api -fmt 32 -conc -func CreateWaitableTimerA
hash_api -fmt 32 -conc -func CreateWaitableTimerW
hash_api -fmt 32 -conc -func CreateWaitableTimerExA
hash_api -fmt 32 -conc -func CreateWaitableTimerExW
hash_api -fmt 32 -conc -func CreateFileA
hash_api -fmt 32 -conc -func CreateFileW
hash_api -fmt 32 -conc -func FindFirstFileA
hash_api -fmt 32 -conc -func FindFirstFileW
hash_api -fmt 32 -conc -func FindFirstFileExA
hash_api -fmt 32 -conc -func FindFirstFileExW
hash_api -fmt 32 -conc -func FindClose
hash_api -fmt 32 -conc -func CreateIoCompletionPort
hash_api -fmt 32 -conc -mod "advapi32.dll" -func RegCreateKeyA
hash_api -fmt 32 -conc -mod "advapi32.dll" -func RegCreateKeyW
hash_api -fmt 32 -conc -mod "advapi32.dll" -func RegCreateKeyExA
hash_api -fmt 32 -conc -mod "advapi32.dll" -func RegCreateKeyExW
hash_api -fmt 32 -conc -mod "advapi32.dll" -func RegOpenKeyA
hash_api -fmt 32 -conc -mod "advapi32.dll" -func RegOpenKeyW
hash_api -fmt 32 -conc -mod "advapi32.dll" -func RegOpenKeyExA
hash_api -fmt 32 -conc -mod "advapi32.dll" -func RegOpenKeyExW
hash_api -fmt 32 -conc -mod "advapi32.dll" -func RegCloseKey
hash_api -fmt 32 -conc -mod "ws2_32.dll" -func WSAStartup
hash_api -fmt 32 -conc -mod "ws2_32.dll" -func WSACleanup
hash_api -fmt 32 -conc -mod "ws2_32.dll" -func WSASocketA
hash_api -fmt 32 -conc -mod "ws2_32.dll" -func WSASocketW
hash_api -fmt 32 -conc -mod "ws2_32.dll" -func socket
hash_api -fmt 32 -conc -mod "ws2_32.dll" -func accept
hash_api -fmt 32 -conc -mod "ws2_32.dll" -func closesocket
hash_api -fmt 32 -conc -mod "mswsock.dll" -func AcceptEx
echo.

echo [Argument Store]
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func AS_GetValue
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func AS_GetPointer
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func AS_Erase
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func AS_EraseAll
echo.

echo [In-Memory Storage]
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func IMS_SetValue
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func IMS_GetValue
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func IMS_GetPointer
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func IMS_Delete
hash_api -fmt 32 -conc -mod "GleamRT.dll" -func IMS_DeleteAll
echo.

echo [WinBase Module]
hash_api -fmt 32 -conc -func MultiByteToWideChar
hash_api -fmt 32 -conc -func WideCharToMultiByte
echo.

echo [WinFile Module]
hash_api -fmt 32 -conc -func CreateFileA
hash_api -fmt 32 -conc -func CreateFileW
hash_api -fmt 32 -conc -func GetFileSizeEx
hash_api -fmt 32 -conc -func ReadFile
hash_api -fmt 32 -conc -func WriteFile
echo.

echo [WinHTTP Module]
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpCrackUrl
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpOpen
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpConnect
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpSetOption
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpSetTimeouts
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpOpenRequest
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpSetCredentials
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpSendRequest
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpReceiveResponse
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpQueryHeaders
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpQueryDataAvailable
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpReadData
hash_api -fmt 32 -conc -mod "winhttp.dll" -func WinHttpCloseHandle
echo.

echo [WinCrypto Module]
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptAcquireContextA
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptReleaseContext
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptGenRandom
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptGenKey
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptExportKey
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptCreateHash
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptSetHashParam
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptGetHashParam
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptHashData
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptDestroyHash
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptImportKey
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptSetKeyParam
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptEncrypt
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptDecrypt
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptDestroyKey
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptSignHashA
hash_api -fmt 32 -conc -mod "advapi32.dll" -func CryptVerifySignatureA
echo.

pause
