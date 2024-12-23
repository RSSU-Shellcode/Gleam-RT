#include <stdio.h>
#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_msvcrt.h"
#include "dll_ucrtbase.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

static bool TestMemory_Virtual();
static bool TestMemory_Heap();
static bool TestMemory_GlobalHeap();
static bool TestMemory_LocalHeap();
static bool TestMemory_msvcrt();
static bool TestMemory_ucrtbase();

bool TestRuntime_Memory()
{
    test_t tests[] = {
        { TestMemory_Virtual    },
        { TestMemory_Heap       },
        { TestMemory_GlobalHeap },
        { TestMemory_LocalHeap  },
        { TestMemory_msvcrt     },
        { TestMemory_ucrtbase   },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        printf_s("--------------------------------\n");
        if (!tests[i]())
        {
            return false;
        }
        printf_s("--------------------------------\n\n");
    }
    return true;
}

bool TestMemory_Virtual()
{
    uint64* test1 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test1 == NULL)
    {
        return false;
    }
    *test1 = 0x1234567812345600;

    uint64* test2 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test2 == NULL)
    {
        return false;
    }
    *test2 = 0x1234567812345601;

    uint64* test3 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test3 == NULL)
    {
        return false;
    }
    *test3 = 0x1234567812345602;

    errno errno = runtime->Core.Hide();
    if (errno != NO_ERROR)
    {
        printf_s("failed to hide: 0x%X\n", errno);
        return false;
    }
    errno = runtime->Core.Recover();
    if (errno != NO_ERROR)
    {
        printf_s("failed to recover: 0x%X\n", errno);
        return false;
    }

    uint64* test4 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test4 == NULL)
    {
        return false;
    }
    *test4 = 0x1234567812345603;

    runtime->Memory.Free(test3);
    runtime->Memory.Free(test1);

    uint64* test5 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test5 == NULL)
    {
        return false;
    }
    *test5 = 0x1234567812345600;

    errno = runtime->Core.Hide();
    if (errno != NO_ERROR)
    {
        printf_s("failed to hide: 0x%X\n", errno);
        return false;
    }
    errno = runtime->Core.Recover();
    if (errno != NO_ERROR)
    {
        printf_s("failed to recover: 0x%X\n", errno);
        return false;
    }
    errno = runtime->Core.Sleep(100);
    if (errno != NO_ERROR)
    {
        printf_s("failed to call Core.Sleep: 0x%X\n", errno);
        return false;
    }

    runtime->Memory.Free(test2);
    runtime->Memory.Free(test4);
    runtime->Memory.Free(test5);

    printf_s("test Memory_Virtual passed\n");
    return true;
}

static bool TestMemory_Heap()
{
    HMODULE hKernel32 = runtime->Library.LoadA("kernel32.dll");
    HMODULE hNtdll    = runtime->Library.LoadA("ntdll.dll");

    HeapAlloc_t   HeapAlloc   = runtime->Library.GetProc(hKernel32, "HeapAlloc");
    HeapReAlloc_t HeapReAlloc = runtime->Library.GetProc(hKernel32, "HeapReAlloc");
    HeapFree_t    HeapFree    = runtime->Library.GetProc(hKernel32, "HeapFree");
    HeapSize_t    HeapSize    = runtime->Library.GetProc(hKernel32, "HeapSize");

    GetProcessHeap_t GetProcessHeap = runtime->Library.GetProc(hKernel32, "GetProcessHeap");
    HANDLE hHeap = GetProcessHeap();

    // test HeapAlloc
    uint* mem = HeapAlloc(hHeap, 0, 16);
    *mem = 0x12345678;
    if (HeapSize(hHeap, 0, mem) != 16)
    {
        printf_s("incorrect allocated heap block size\n");
        return false;
    }
    if (!HeapFree(hHeap, 0, mem))
    {
        printf_s("failed to free heap 0x%X\n", GetLastErrno());
        return false;
    }
    // zero size
    mem = HeapAlloc(hHeap, 0, 0);
    if (mem == NULL)
    {
        printf_s("failed to alloc heap with zero size\n");
        return false;
    }
    if (HeapSize(hHeap, 0, mem) != 0)
    {
        printf_s("incorrect allocated heap block size\n");
        return false;
    }
    if (!HeapFree(hHeap, 0, mem))
    {
        printf_s("failed to free heap with zero size 0x%X\n", GetLastErrno());
        return false;
    }
    runtime->Core.Sleep(10);

    // test HeapReAlloc
    mem = HeapAlloc(hHeap, 0, 16);
    *mem = 0x12345678;
    mem = HeapReAlloc(hHeap, 0, mem, 8);
    if (*mem != 0x12345678)
    {
        printf_s("incorrect heap block data after HeapReAlloc\n");
        return false;
    }
    if (HeapSize(hHeap, 0, mem) != 8)
    {
        printf_s("incorrect reallocated heap block size\n");
        return false;
    }
    mem = HeapReAlloc(hHeap, 0, mem, 32);
    if (*mem != 0x12345678)
    {
        printf_s("incorrect heap block data after HeapReAlloc\n");
        return false;
    }
    if (HeapSize(hHeap, 0, mem) != 32)
    {
        printf_s("incorrect reallocated heap block size\n");
        return false;
    }
    if (!HeapFree(hHeap, 0, mem))
    {
        printf_s("failed to free heap 0x%X\n", GetLastErrno());
        return false;
    }
    // zero size
    mem = HeapAlloc(hHeap, 0, 16);
    *mem = 0x12345678;
    mem = HeapReAlloc(hHeap, 0, mem, 0);
    if (mem == NULL)
    {
        printf_s("failed to realloc heap with zero size\n");
        return false;
    }
    if (HeapSize(hHeap, 0, mem) != 0)
    {
        printf_s("incorrect reallocated heap block size\n");
        return false;
    }
    if (!HeapFree(hHeap, 0, mem))
    {
        printf_s("failed to free heap with zero size 0x%X\n", GetLastErrno());
        return false;
    }
    runtime->Core.Sleep(10);

    // test HeapFree
    if (!HeapFree(hHeap, 0, NULL))
    {
        printf_s("failed to free heap with NULL0x%X\n", GetLastErrno());
        return false;
    }
    runtime->Core.Sleep(10);

    // compare the hook function address
    HeapAlloc_t   RtlAllocateHeap   = runtime->Library.GetProc(hNtdll, "RtlAllocateHeap");
    HeapReAlloc_t RtlReAllocateHeap = runtime->Library.GetProc(hNtdll, "RtlReAllocateHeap");
    HeapFree_t    RtlFreeHeap       = runtime->Library.GetProc(hNtdll, "RtlFreeHeap");
    HeapSize_t    RtlSizeHeap       = runtime->Library.GetProc(hNtdll, "RtlSizeHeap");

    if (RtlAllocateHeap != HeapAlloc)
    {
        printf_s("incorrect RtlAllocateHeap address\n");
        return false;
    }
    if (RtlReAllocateHeap != HeapReAlloc)
    {
        printf_s("incorrect RtlReAllocateHeap address\n");
        return false;
    }
    if (RtlFreeHeap != HeapFree)
    {
        printf_s("incorrect RtlFreeHeap address\n");
        return false;
    }
    if (RtlSizeHeap != HeapSize)
    {
        printf_s("incorrect RtlSizeHeap address\n");
        return false;
    }

    if (!runtime->Library.Free(hKernel32))
    {
        printf_s("failed to free kernel32.dll: 0x%X\n", GetLastErrno());
        return false;
    }
    if (!runtime->Library.Free(hNtdll))
    {
        printf_s("failed to free ntdll.dll: 0x%X\n", GetLastErrno());
        return false;
    }

    printf_s("test Memory_Heap passed\n");
    return true;
}

static bool TestMemory_GlobalHeap()
{
    HMODULE hKernel32 = runtime->Library.LoadA("kernel32.dll");

    GlobalAlloc_t   GlobalAlloc   = runtime->Library.GetProc(hKernel32, "GlobalAlloc");
    GlobalReAlloc_t GlobalReAlloc = runtime->Library.GetProc(hKernel32, "GlobalReAlloc");
    GlobalFree_t    GlobalFree    = runtime->Library.GetProc(hKernel32, "GlobalFree");

    HGLOBAL hGlobal = GlobalAlloc(GPTR, 4);
    if (hGlobal == NULL)
    {
        printf_s("failed to alloc global heap 0x%X\n", GetLastErrno());
        return false;
    }
    *(uint*)hGlobal = 0x1234;

    hGlobal = GlobalReAlloc(hGlobal, 8, GPTR);
    if (hGlobal == NULL)
    {
        printf_s("failed to realloc global heap 0x%X\n", GetLastErrno());
        return false;
    }
    *(uint*)hGlobal = 0x5678;

    if (GlobalFree(hGlobal) != NULL)
    {
        printf_s("failed to free global heap 0x%X\n", GetLastErrno());
        return false;
    }

    if (!runtime->Library.Free(hKernel32))
    {
        printf_s("failed to free kernel32.dll: 0x%X\n", GetLastErrno());
        return false;
    }

    printf_s("test Memory_GlobalHeap passed\n");
    return true;
}

static bool TestMemory_LocalHeap()
{
    HMODULE hKernel32 = runtime->Library.LoadA("kernel32.dll");

    LocalAlloc_t   LocalAlloc   = runtime->Library.GetProc(hKernel32, "LocalAlloc");
    LocalReAlloc_t LocalReAlloc = runtime->Library.GetProc(hKernel32, "LocalReAlloc");
    LocalFree_t    LocalFree    = runtime->Library.GetProc(hKernel32, "LocalFree");

    HLOCAL hLocal = LocalAlloc(LPTR, 4);
    if (hLocal == NULL)
    {
        printf_s("failed to alloc local heap 0x%X\n", GetLastErrno());
        return false;
    }
    *(uint*)hLocal = 0x1234;

    hLocal = LocalReAlloc(hLocal, 8, LPTR);
    if (hLocal == NULL)
    {
        printf_s("failed to realloc local heap 0x%X\n", GetLastErrno());
        return false;
    }
    *(uint*)hLocal = 0x5678;

    if (LocalFree(hLocal) != NULL)
    {
        printf_s("failed to free local heap 0x%X\n", GetLastErrno());
        return false;
    }

    if (!runtime->Library.Free(hKernel32))
    {
        printf_s("failed to free kernel32.dll: 0x%X\n", GetLastErrno());
        return false;
    }

    printf_s("test Memory_LocalHeap passed\n");
    return true;
}

static bool TestMemory_msvcrt()
{
    HMODULE hMsvcrt = runtime->Library.LoadA("msvcrt.dll");

    msvcrt_malloc_t  malloc  = runtime->Library.GetProc(hMsvcrt, "malloc");
    msvcrt_calloc_t  calloc  = runtime->Library.GetProc(hMsvcrt, "calloc");
    msvcrt_realloc_t realloc = runtime->Library.GetProc(hMsvcrt, "realloc");
    msvcrt_free_t    free    = runtime->Library.GetProc(hMsvcrt, "free");
    msvcrt_msize_t   msize   = runtime->Library.GetProc(hMsvcrt, "_msize");

    uint* test1 = malloc(8);
    if (msize(test1) != 8)
    {
        printf_s("incorrect memory block size");
        return false;
    }

    uint* test2 = calloc(4, 8);
    uint* test3 = realloc(test1, 27);
    *test2 = 0x5678;
    *test3 = 0x1212;
    if (msize(test3) != 27)
    {
        printf_s("incorrect memory block size");
        return false;
    }

    runtime->Core.Sleep(10);
    free(test2);
    runtime->Core.Sleep(10);
    free(test3);
    runtime->Core.Sleep(10);

    // not free
    test1 = malloc(8);
    *test1 = 0x1234;
    runtime->Core.Sleep(10);

    if (!runtime->Library.Free(hMsvcrt))
    {
        printf_s("failed to free msvcrt.dll: 0x%X\n", GetLastErrno());
        return false;
    }

    printf_s("test Memory_msvcrt passed\n");
    return true;
}

static bool TestMemory_ucrtbase()
{
    HMODULE hUcrtbase = runtime->Library.LoadA("ucrtbase.dll");

    ucrtbase_malloc_t  malloc  = runtime->Library.GetProc(hUcrtbase, "malloc");
    ucrtbase_calloc_t  calloc  = runtime->Library.GetProc(hUcrtbase, "calloc");
    ucrtbase_realloc_t realloc = runtime->Library.GetProc(hUcrtbase, "realloc");
    ucrtbase_free_t    free    = runtime->Library.GetProc(hUcrtbase, "free");
    ucrtbase_msize_t   msize   = runtime->Library.GetProc(hUcrtbase, "_msize");

    uint* test1 = malloc(8);
    if (msize(test1) != 8)
    {
        printf_s("incorrect memory block size");
        return false;
    }

    uint* test2 = calloc(4, 8);
    uint* test3 = realloc(test1, 27);
    *test2 = 0x5678;
    *test3 = 0x1212;
    if (msize(test3) != 27)
    {
        printf_s("incorrect memory block size");
        return false;
    }

    runtime->Core.Sleep(10);
    free(test2);
    runtime->Core.Sleep(10);
    free(test3);
    runtime->Core.Sleep(10);

    // not free
    test1 = malloc(8);
    *test1 = 0x1234;
    runtime->Core.Sleep(10);

    if (!runtime->Library.Free(hUcrtbase))
    {
        printf_s("failed to free ucrtbase.dll: 0x%X\n", GetLastErrno());
        return false;
    }

    printf_s("test Memory_ucrtbase passed\n");
    return true;
}
