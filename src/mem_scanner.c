#include "c_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_match.h"
#include "hash_api.h"
#include "mem_scanner.h"

#ifdef _WIN64
    #define END_ADDRESS 0xFFFFFFFFFFFFFFFF
#elif _WIN32
    #define END_ADDRESS 0xFFFFFFFF
#endif

static bool isPageReadable(DWORD protect);

#pragma optimize("t", on)

uint MemScan(byte* pattern, uintptr* results, uint maxItem)
{
    VirtualQuery_t VirtualQuery;
#ifdef _WIN64
    VirtualQuery = FindAPI(0x7E3FFDE2F6882D52, 0x118655CA8CAE6F48);
#elif _WIN32
    VirtualQuery = FindAPI(0x786F453F, 0x10579014);
#endif
    if (VirtualQuery == NULL)
    {
        return ERR_MEMSCAN_NOT_FOUND_API;
    }

    MEMORY_BASIC_INFORMATION mbi;
    mem_init(&mbi, sizeof(mbi));

    uintptr address   = 0;
    uint    numResult = 0;
    while (address < END_ADDRESS)
    {
        // query memory region information
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0)
        {
            return ERR_MEMSCAN_VIRTUAL_QUERY;
        }
        if (mbi.RegionSize == 0)
        {
            break;
        }
        // search memory region
        uint size = mbi.RegionSize - (address - (uintptr)(mbi.BaseAddress));
        if (!isPageReadable(mbi.Protect))
        {
            address += size;
            continue;
        }
        address += size;
    }
    return 0;
}

static bool isPageReadable(DWORD protect)
{
    switch (protect)
    {
    case PAGE_NOACCESS:
        return false;
    case PAGE_READONLY:
        return true;
    case PAGE_READWRITE:
        return true;
    case PAGE_WRITECOPY:
        return true;
    case PAGE_EXECUTE:
        return false;
    case PAGE_EXECUTE_READ:
        return true;
    case PAGE_EXECUTE_READWRITE:
        return true;
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

#pragma optimize("t", off)
