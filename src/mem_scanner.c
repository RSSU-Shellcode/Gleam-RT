#include "c_types.h"
#include "lib_memory.h"
#include "lib_match.h"
#include "dll_kernel32.h"
#include "errno.h"
#include "mem_scanner.h"

#define MAX_NUM_CONDITION 64

#define COND_TYPE_EXACT_VAL  0x01
#define COND_TYPE_HALF_LEFT  0x02
#define COND_TYPE_HALF_RIGHT 0x03
#define COND_TYPE_ARBITRARY  0x04

#define PATTERN_TYPE_ARBITRARY 0xFE
#define PATTERN_TYPE_INVALID   0xFF

static uint scanRegion(uintptr addr, uint size, uint16* cond, uint num);
static uint parsePattern(byte* pattern, uint16* condition);
static byte charToValue(byte b);
static byte valueToChar(byte b);
static bool isRegionReadable(DWORD protect);

#pragma optimize("t", on)

uint MemScanByValue(MemScan_Ctx* ctx, void* value, uint size, uintptr* results, uint maxItem)
{
    if (size == 0 || size > MAX_NUM_CONDITION)
    {
        SetLastErrno(ERR_MEM_SCANNER_INVALID_VALUE);
        return (uint)(-1);
    }
    byte pattern[MAX_NUM_CONDITION * 3 + 1];
    BinToPattern(value, size, pattern);
    MemScan_Cfg config = {
        .Pattern = pattern,
        .Protect = PAGE_READWRITE,
        .Type    = MEM_PRIVATE,
    };
    return MemScanByConfig(ctx, &config, results, maxItem);
}

uint MemScanByConfig(MemScan_Ctx* ctx, MemScan_Cfg* config, uintptr* results, uint maxItem)
{
    // parse pattern to condition array
    uint16 condition[MAX_NUM_CONDITION];
    mem_init(condition, sizeof(condition));
    uint numCond = parsePattern(config->Pattern, condition);
    if (numCond == 0)
    {
        SetLastErrno(ERR_MEM_SCANNER_INVALID_CONDITION);
        return (uint)(-1);
    }
    // check condition is valid and can use fast mode
    byte fastValue[MAX_NUM_CONDITION];
    mem_init(fastValue, sizeof(fastValue));
    bool canFast  = true;
    bool hasExact = false;
    for (uint i = 0; i < numCond; i++)
    {
        uint16 cond = condition[i];
        if ((cond >> 8) != COND_TYPE_EXACT_VAL)
        {
            canFast = false;
        } else {
            fastValue[i] = (byte)(cond & 0x00FF);
            hasExact = true;
        }
    }
    if (!hasExact)
    {
        SetLastErrno(ERR_MEM_SCANNER_INVALID_CONDITION);
        return (uint)(-1);
    }

    // check memory region protect and type
    if (config->Protect == 0)
    {
        SetLastErrno(ERR_MEM_SCANNER_INVALID_PROTECT);
        return (uint)(-1);
    }
    if (config->Type == 0)
    {
        SetLastErrno(ERR_MEM_SCANNER_INVALID_TYPE);
        return (uint)(-1);
    }

    // scan memory region
    uintptr address    = ctx->MinAddress;
    uintptr endAddress = ctx->MaxAddress;
    MEMORY_BASIC_INFORMATION mbi;
    mem_init(&mbi, sizeof(mbi));
    uint numResults = 0;
    while (address < endAddress)
    {
        // query memory region information
        if (ctx->VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0)
        {
            SetLastErrno(ERR_MEM_SCANNER_VIRTUAL_QUERY);
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
        // compare type and protect
        if ((mbi.Type & config->Type) == 0 || (mbi.Protect & config->Protect) == 0)
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
            integer rem = (integer)(address + size) - (integer)addr;
            if (rem < (integer)numCond)
            {
                break;
            }
            integer offset;
            if (canFast)
            {
                offset = MatchBytes((byte*)addr, rem, fastValue, numCond);
            } else {
                offset = (integer)scanRegion(addr, rem, condition, numCond);
            }
            if (offset == -1)
            {
                break;
            }
            uintptr result = addr + offset;
            // skip fake result from fastValue in the stack
            if ((byte*)result != fastValue)
            {
                results[numResults] = result;
                numResults++;
            }
            addr = result + numCond;
        }
        address += size;
    }
    return numResults;
}

static uint scanRegion(uintptr addr, uint size, uint16* condition, uint numCond)
{
    uintptr offset = 0;
    for (;;)
    {
        if (size - offset < numCond)
        {
            break;
        }
        bool same = true;
        uintptr address = addr + offset;
        for (uint i = 0; i < numCond; i++)
        {
            uint16 cond = condition[i];
            byte typ  = (byte)(cond >> 8);
            byte val  = (byte)(cond & 0x00FF);
            byte data = *(byte*)(address + i);
            switch (typ)
            {
            case COND_TYPE_EXACT_VAL:
                same = data == val;
                break;
            case COND_TYPE_HALF_LEFT:
                same = (data >> 4) == val;
                break;
            case COND_TYPE_HALF_RIGHT:
                same = (data & 0x0F) == val;
                break;
            case COND_TYPE_ARBITRARY:
                break;
            default:
                panic(PANIC_UNREACHABLE_CODE);
                break;
            }
            if (!same)
            {
                break;
            }
        }
        if (same)
        {
            return offset;
        }
        offset++;
    }
    return (uint)(-1);
}

static uint parsePattern(byte* pattern, uint16* condition)
{
    uint numCond = 0;
    bool arb1 = false;
    bool arb2 = false;
    for (;;)
    {
        if (numCond >= MAX_NUM_CONDITION)
        {
            return 0;
        }
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
            arb1 = true;
            break;
        case PATTERN_TYPE_INVALID:
            return 0;
        }
        // parse the second character
        pattern++;
        byte val2 = charToValue(*pattern);
        switch (val2)
        {
        default:
            break;
        case PATTERN_TYPE_ARBITRARY:
            arb2 = true;
            break;
        case PATTERN_TYPE_INVALID:
            return 0;
        }
        // generate the condition
        if (!arb1 && !arb2)
        {
            byte exactVal = val1 * 16 + val2;
            condition[numCond] = (COND_TYPE_EXACT_VAL << 8) + exactVal;
        }
        if (!arb1 && arb2)
        {
            condition[numCond] = (COND_TYPE_HALF_LEFT << 8) + val1;
        }
        if (arb1 && !arb2)
        {
            condition[numCond] = (COND_TYPE_HALF_RIGHT << 8) + val2;
        }
        if (arb1 && arb2)
        {
            condition[numCond] = (COND_TYPE_ARBITRARY << 8) + 0;
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
        arb1 = false;
        arb2 = false;
        // update pointer
        pattern++;
    }
    return numCond;
}

void BinToPattern(void* data, uint size, byte* pattern)
{
    byte* value = (byte*)data;
    for (uint i = 0; i < size; i++)
    {
        byte b = value[i];
        pattern[0] = valueToChar(b >> 4);
        pattern[1] = valueToChar(b & 0x0F);
        pattern[2] = ' ';
        pattern += 3;
    }
    *pattern = 0x00;
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

static byte valueToChar(byte b)
{
    if (b >= 0 && b <= 9)
    {
        return '0' + b;
    }
    return 'A' + (b - 10);
}

static bool isRegionReadable(DWORD protect)
{
    switch (protect)
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

#pragma optimize("t", off)
