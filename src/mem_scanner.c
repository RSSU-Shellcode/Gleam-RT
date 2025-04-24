#include "c_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_match.h"
#include "hash_api.h"
#include "errno.h"
#include "mem_scanner.h"

#ifdef _WIN64
    #define END_ADDRESS 0xFFFFFFFFFFFFFFFF
#elif _WIN32
    #define END_ADDRESS 0xFFFFFFFF
#endif

#define COND_TYPE_EXACT_VAL 0x01
#define COND_TYPE_ARBITRARY 0x02

#define PATTERN_TYPE_ARBITRARY 0xFE
#define PATTERN_TYPE_INVALID   0xFF

static uint parsePattern(byte* pattern, uint16* condition);
static byte charToValue(byte b);
static bool isRegionReadable(DWORD protect);

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
        SetLastErrno(ERR_MEMSCAN_NOT_FOUND_API);
        return (uint)(-1);
    }

    // parse pattern to condition array
    uint16 condition[32];
    mem_init(condition, sizeof(condition));
    uint numCond = parsePattern(pattern, condition);
    if (numCond == 0)
    {
        SetLastErrno(ERR_MEMSCAN_INVALID_CONDITION);
        return (uint)(-1);
    }

    // check can use fast mode
    byte fastValue[32];
    mem_init(fastValue, sizeof(fastValue));
    bool canFast  = true;
    uint condSize = 0;
    for (uint i = 0; i < arrlen(condition); i++)
    {
        uint16 cond = condition[i];
        if (cond == 0x0000)
        {
            break;
        }
        if ((cond >> 8) == COND_TYPE_ARBITRARY)
        {
            canFast = false;
        } else {
            fastValue[i] = cond & 0x00FF;
        }
        condSize++;
    }

    // scan memory region
    MEMORY_BASIC_INFORMATION mbi;
    mem_init(&mbi, sizeof(mbi));
    uintptr address = 0;
    uint numResults = 0;
    while (address < END_ADDRESS)
    {
        // query memory region information
        if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0)
        {
            SetLastErrno(ERR_MEMSCAN_VIRTUAL_QUERY);
            return (uint)(-1);
        }
        if (mbi.RegionSize == 0)
        {
            break;
        }
        uint size = mbi.RegionSize - (address - (uintptr)(mbi.BaseAddress));
        if (mbi.State != MEM_COMMIT || !isRegionReadable(mbi.Protect))
        {
            address += size;
            continue;
        }
        // scan memory region
        uintptr addr = address;
        for (;;)
        {
            if (numResults >= maxItem)
            {
                return numResults;
            }
            int64 s = (int64)(address + size) - (int64)addr;
            if (s < (int64)condSize)
            {
                break;
            }
            if (canFast)
            {
                integer idx = MatchBytes((byte*)addr, s, fastValue, condSize);
                if (idx == -1)
                {
                    break;
                } else {
                    uintptr result = addr + idx;
                    // skip fake result from fastValue in the stack
                    if ((byte*)result != fastValue)
                    {
                        *results = result;
                        results++;
                        numResults++;
                    }
                    addr = result + condSize;
                }
            } else {
                addr++;
            }
        }
        address += size;
    }
    return numResults;
}

static uint parsePattern(byte* pattern, uint16* condition)
{
    uint numCond   = 0;
    bool arbitrary = false;
    for (;;)
    {
        // parse first character
        byte pat = *pattern;
        if (pat == 0x00)
        {
            break;
        }
        byte val1 = charToValue(pat);
        switch (val1)
        {
        default:
            break;
        case PATTERN_TYPE_ARBITRARY:
            arbitrary = true;
            break;
        case PATTERN_TYPE_INVALID:
            return 0;
        }
        // parse the second character
        pattern++;
        byte val2 = charToValue(*pattern);
        // process invalid type with "?A"
        if (arbitrary && val2 != PATTERN_TYPE_ARBITRARY)
        {
            return 0;
        }
        switch (val2)
        {
        default:
            break;
        case PATTERN_TYPE_ARBITRARY:
            // process invalid type with "A?"
            if (!arbitrary)
            {
                return 0;
            }
            break;
        case PATTERN_TYPE_INVALID:
            return 0;
        }
        // generate the condition
        if (arbitrary)
        {
            *condition = (COND_TYPE_ARBITRARY << 8) + 0;
        } else {
            byte exactVal = val1 * 16 + val2;
            *condition = (COND_TYPE_EXACT_VAL << 8) + exactVal;
        }
        numCond++;
        // parse the third character
        pattern++;
        switch (*pattern)
        {
        case ' ':
            break;
        case 0x00:
            return numCond;
        default:
            return 0;
        }
        // reset status
        arbitrary = false;
        // update pointer
        pattern++;
        condition++;
    }
    return numCond;
}

static byte charToValue(byte b)
{
    if (b >= '0' && b <= '9')
    {
        return b - '0';
    }
    if (b >= 'A' && b <= 'F')
    {
        return b - 'A' + 10;
    }
    if (b >= 'a' && b <= 'f')
    {
        return b - 'a' + 10;
    }
    if (b == '?')
    {
        return PATTERN_TYPE_ARBITRARY;
    }
    return PATTERN_TYPE_INVALID;
}

static bool isRegionReadable(DWORD protect)
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
