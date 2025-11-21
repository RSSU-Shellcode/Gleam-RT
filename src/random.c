#include "c_types.h"
#include "rel_addr.h"
#include "random.h"

static uint64  rand(uint64 seed, uint64 mod);
static uint64  ror(uint64 value, uint8 bits);
static uintptr getStackAddr();

#pragma optimize("t", on)

byte RandByte(uint64 seed)
{
    if (seed < 4096)
    {
        seed += GenerateSeed();
    }
    return (byte)rand(seed, 256);
}

BOOL RandBool(uint64 seed)
{
    if (seed < 4096)
    {
        seed += GenerateSeed();
    }
    return (BOOL)rand(seed, 2);
}

int RandInt(uint64 seed)
{
    if (seed < 4096)
    {
        seed += GenerateSeed();
    }
#ifdef _WIN64
    return (int)rand(seed, UINT64_MAX);
#elif _WIN32
    return (int)rand(seed, UINT32_MAX);
#endif
}

uint RandUint(uint64 seed)
{
    if (seed < 4096)
    {
        seed += GenerateSeed();
    }
#ifdef _WIN64
    return (uint)rand(seed, UINT64_MAX);
#elif _WIN32
    return (uint)rand(seed, UINT32_MAX);
#endif
}

int64 RandInt64(uint64 seed)
{
    if (seed < 4096)
    {
        seed += GenerateSeed();
    }
    return (int64)rand(seed, UINT64_MAX);
}

uint64 RandUint64(uint64 seed)
{
    if (seed < 4096)
    {
        seed += GenerateSeed();
    }
    return rand(seed, UINT64_MAX);
}

int RandIntN(uint64 seed, int n)
{
    if (seed < 4096)
    {
        seed += GenerateSeed();
    }
    int num = RandInt(seed) % n;
    if (num < 0)
    {
        return -num;
    }
    return num;
}

uint RandUintN(uint64 seed, uint n)
{
    if (seed < 4096)
    {
        seed += GenerateSeed();
    }
    return RandUint(seed) % n;
}

int64 RandInt64N(uint64 seed, int64 n)
{
    if (seed < 4096)
    {
        seed += GenerateSeed();
    }
    int64 num = RandInt64(seed) % n;
    if (num < 0)
    {
        return -num;
    }
    return num;
}

uint64 RandUint64N(uint64 seed, uint64 n)
{
    if (seed < 4096)
    {
        seed += GenerateSeed();
    }
    return RandUint64(seed) % n;
}

void RandBuffer(void* buf, int64 size)
{
    if (size < 1)
    {
        return;
    }
    byte* buffer = buf;
    // limit the max loop times
    int64 times = size;
    if (times > 16)
    {
        times = 16;
    }
    // generate seed from buffer address
    uint64 seed = (uint64)(buffer);
    seed += GenerateSeed();
    for (int64 i = 0; i < times; i++)
    {
        byte b = *(buffer + i);
        if (b == 0)
        {
            b = 170;
        }
        seed += ror(seed, b % 4);
        seed += b;
    }
    for (int64 i = 0; i < size; i++)
    {
        // xor shift
    #ifdef _WIN64
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
    #elif _WIN32
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
    #endif
        // write generate byte
        *(buffer + i) = (byte)seed;
    }
}

void RandSequence(int* array, int n)
{
    // initialize input array
    for (int i = 0; i < n; i++)
    {
        array[i] = i;
    }
    // swap with random index
    uint64 seed = GenerateSeed();
    for (int i = n - 1; i > 0; i--)
    {
        int j = RandIntN(seed, i + 1);
        int valA = array[i];
        int valB = array[j];
        array[i] = valB;
        array[j] = valA;
        // update seed
        seed += ror(seed, (uint8)n);
    }
}

__declspec(noinline)
static uint64 rand(uint64 seed, uint64 mod)
{
    seed += GenerateSeed();
    uint64 a = (uint64)(GetFuncAddr(&ror));
    uint64 c = (uint64)(GetFuncAddr(&getStackAddr));
    int times = 8 + seed % 32;
    for (int i = 0; i < times; i++)
    {
        // just play game
        a += ror(a, 3);
        c += ror(c, 32);
        a += getStackAddr();
        c += getStackAddr();
        seed += ror(seed + a, 3);
        seed += ror(seed + c, 6);
        seed += ror(seed + mod, 9);
        seed += ror(seed, 1);        
        seed += ror(seed, 17);
        seed = (a * seed + c);
        // xor shift 64
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
    }
    return seed % mod;
}

#pragma warning(push)
#pragma warning(disable: 4172)
static uintptr getStackAddr()
{
    uint stack = 0;
    return (uintptr)(&stack);
}
#pragma warning(pop)

static uint64 ror(uint64 value, uint8 bits)
{
    return value >> bits | value << (64 - bits);
}

__declspec(noinline)
uint XORShift(uint seed)
{
#ifdef _WIN64
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
#elif _WIN32
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
#endif
    return seed;
}

__declspec(noinline)
uint32 XORShift32(uint32 seed)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

__declspec(noinline)
uint64 XORShift64(uint64 seed)
{
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    return seed;
}

#pragma optimize("t", off)
