#include "c_types.h"
#include "lib_memory.h"

#pragma optimize("t", on)

__declspec(noinline)
void mem_copy(void* dst, void* src, uint num)
{
    if (num == 0)
    {
        return;
    }
    byte* d = (byte*)dst;
    byte* s = (byte*)src;
    if (d == s)
    {
        return;
    }
    for (uint i = 0; i < num; i++)
    {
        d[i] = s[i];
    }
}

__declspec(noinline)
void mem_move(void* dst, void* src, uint num)
{
    if (num == 0)
    {
        return;
    }
    byte* d = (byte*)dst;
    byte* s = (byte*)src;
    if (d == s)
    {
        return;
    }
    if (d < s || d >= s + num)
    {
        for (uint i = 0; i < num; i++)
        {
            d[i] = s[i];
        }
        return;
    }
    for (uint i = num; i > 0; i--)
    {
        d[i - 1] = s[i - 1];
    }
}

#pragma optimize("", off)
void mem_init(void* ptr, uint num)
{
    if (num == 0)
    {
        return;
    }
    mem_set(ptr, 0, num);
}
#pragma optimize("", on)

// prevent link to the internal function "memset"
#pragma optimize("", off)
void mem_set(void* ptr, byte val, uint num)
{
    if (num == 0)
    {
        return;
    }
    byte* p = (byte*)ptr;
    for (uint i = 0; i < num; i++)
    {
        p[i] = val;
    }
}
#pragma optimize("", on)

__declspec(noinline)
int mem_cmp(void* a, void* b, uint num)
{
    if (num == 0)
    {
        return 0;
    }
    byte* p0 = (byte*)a;
    byte* p1 = (byte*)b;
    for (uint i = 0; i < num; i++)
    {
        if (p0[i] == p1[i])
        {
            continue;
        }
        if (p0[i] > p1[i])
        {
            return 1;
        } else {
            return -1;
        }
    }
    return 0;
}

__declspec(noinline)
bool mem_equal(void* a, void* b, uint num)
{
    if (num == 0)
    {
        return true;
    }
    byte* p0 = (byte*)a;
    byte* p1 = (byte*)b;
    for (uint i = 0; i < num; i++)
    {
        if (p0[i] != p1[i])
        {
            return false;
        }
    }
    return true;
}

__declspec(noinline)
bool mem_is_zero(void* ptr, uint num)
{
    if (num == 0)
    {
        return true;
    }
    byte* p = (byte*)ptr;
    for (uint i = 0; i < num; i++)
    {
        if (p[i] != 0)
        {
            return false;
        }
    }
    return true;
}

#pragma optimize("t", off)
