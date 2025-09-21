#include "c_types.h"
#include "lib_memory.h"
#include "hash_api.h"

#ifdef _WIN64
    #define KEY_SIZE 8
    #define ROR_BITS 8
#elif _WIN32
    #define KEY_SIZE 4
    #define ROR_BITS 4
#endif

#define ROR_SEED (ROR_BITS + 1)
#define ROR_KEY  (ROR_BITS + 2)
#define ROR_MOD  (ROR_BITS + 3)
#define ROR_PROC (ROR_BITS + 4)

static uint calcSeedHash(uint key);
static uint calcKeyHash(uint seed, uint key);
static uint ror(uint value, uint bits);

__declspec(noinline)
void* FindAPI(uint module, uint procedure, uint key)
{
    void* list = GetInMemoryOrderModuleList();
    return FindAPI_ML(list, module, procedure, key);
}

__declspec(noinline)
void* FindAPI_ML(void* list, uint module, uint procedure, uint key)
{
    uint seedHash = calcSeedHash(key);
    uint keyHash  = calcKeyHash(seedHash, key);
    uintptr mod = (uintptr)list;
    for (;; mod = *(uintptr*)(mod))
    {
    #ifdef _WIN64
        uintptr modName = *(uintptr*)(mod + 80);
    #elif _WIN32
        uintptr modName = *(uintptr*)(mod + 40);
    #endif    
        if (modName == 0x00)
        {
            break;
        }
    #ifdef _WIN64
        uintptr modBase = *(uintptr*)(mod + 32);
    #elif _WIN32
        uintptr modBase = *(uintptr*)(mod + 16);
    #endif
        uintptr peHeader = modBase + (uintptr)(*(uint32*)(modBase + 60));
    #ifdef _WIN64
        // check this module actually a x64 PE image
        if (*(uint16*)(peHeader + 24) != 0x020B)
        {
            continue;
        }
    #endif
        // get RVA of export address tables(EAT)
    #ifdef _WIN64
        uint32 eatRVA  = *(uint32*)(peHeader + 136);
        uint32 eatSize = *(uint32*)(peHeader + 140);
    #elif _WIN32
        uint32 eatRVA  = *(uint32*)(peHeader + 120);
        uint32 eatSize = *(uint32*)(peHeader + 124);
    #endif
        if (eatRVA == 0 || eatSize == 0)
        {
            continue;
        }
        uintptr eat = modBase + eatRVA;
        // calculate module name hash
        uint modHash = seedHash;
    #ifdef _WIN64
        uint16 nameLen = *(uint16*)(mod + 74);
    #elif _WIN32
        uint16 nameLen = *(uint16*)(mod + 38);
    #endif
        for (uint16 i = 0; i < nameLen - 2; i++)
        {
            byte b = *(byte*)(modName + i);
            if (b >= 'a')
            {
                b -= 0x20;
            }
            modHash = ror(modHash, ROR_MOD);
            modHash += b;
        }
        modHash += seedHash + keyHash;
        if (modHash != module)
        {
            continue;
        }
        // calculate procedure name hash
        uint32  numNames  = *(uint32*)(eat + 24);
        uintptr procNames = modBase + (uintptr)(*(uint32*)(eat + 32));
        for (uint32 i = 0; i < numNames; i++)
        {
            // calculate procedure name address
            uint32 nameRVA  = *(uint32*)(procNames + (uintptr)(i * 4));
            byte*  procName = (byte*)(modBase + nameRVA);
            uint   procHash = seedHash;
            for (;;)
            {
                byte b = *procName;
                if (b == 0x00)
                {
                    break;
                }
                procHash = ror(procHash, ROR_PROC);
                procHash += b;
                procName++;
            }
            // calculate the finally hash and compare it
            procHash += seedHash + keyHash;
            if (procHash != procedure) 
            {
                continue;
            }
            // calculate the AddressOfFunctions
            uintptr funcTable = modBase + (uintptr)(*(uint32*)(eat + 28));
            // calculate the AddressOfNameOrdinals
            uintptr ordinalTable = modBase + (uintptr)(*(uint32*)(eat + 36));
            // calculate offset of ordinal
            uint16 ordinal = *(uint16*)(ordinalTable + (uintptr)(i * 2));
            // calculate the function RVA
            uint32 funcRVA = *(uint32*)(funcTable + (uintptr)(ordinal * 4));
            // check is forwarded export function
            if (funcRVA < eatRVA || funcRVA >= eatRVA + eatSize)
            {
                return (void*)(modBase + funcRVA);
            }
            // search the last "." in function name
            byte* exportName = (byte*)(modBase + funcRVA);
            byte* src = exportName;
            uint  dot = 0;
            for (uint j = 0;; j++)
            {
                byte b = *src;
                if (b == '.')
                {
                    dot = j;
                }
                if (b == 0x00)
                {
                    break;
                }
                src++;
            }
            // use "mem_init" for prevent incorrect compiler
            // optimize and generate incorrect shellcode
            byte dllName[512];
            mem_init(dllName, sizeof(dllName));
            // prevent array bound when call mem_copy
            if (dot > 500)
            {
                dot = 500;
            }
            mem_copy(dllName, exportName, dot + 1);
            // build DLL name
            dllName[dot+1] = 'd';
            dllName[dot+2] = 'l';
            dllName[dot+3] = 'l';
            dllName[dot+4] = 0x00;
            // build module and procedure hash
            procName = (byte*)((uintptr)exportName + dot + 1);
            modHash  = CalcModHash_A(dllName, key);
            procHash = CalcProcHash(procName, key);
            return FindAPI_ML(list, modHash, procHash, key);
        }
    }
    return NULL;
}

static uint calcSeedHash(uint key)
{
    uint  hash = key;
    byte* ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE; i++)
    {
        hash = ror(hash, ROR_SEED);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint calcKeyHash(uint seed, uint key)
{
    uint  hash = seed;
    byte* ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE; i++)
    {
        hash = ror(hash, ROR_KEY);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint ror(uint value, uint bits)
{
#ifdef _WIN64
    return value >> bits | value << (64 - bits);
#elif _WIN32
    return value >> bits | value << (32 - bits);
#endif
}

__declspec(noinline)
void* FindAPI_A(byte* module, byte* procedure)
{
#ifdef _WIN64
    uint key = 0xA6C1B1E79D26D1E7;
#elif _WIN32
    uint key = 0x94645D8B;
#endif
    uint mod  = CalcModHash_A(module, key);
    uint proc = CalcProcHash(procedure, key);
    return FindAPI(mod, proc, key);
}

__declspec(noinline)
void* FindAPI_W(uint16* module, byte* procedure)
{
#ifdef _WIN64
    uint key = 0xA6C1B1E79D26D1E7;
#elif _WIN32
    uint key = 0x94645D8B;
#endif
    uint mod  = CalcModHash_W(module, key);
    uint proc = CalcProcHash(procedure, key);
    return FindAPI(mod, proc, key);
}

__declspec(noinline)
uint CalcModHash_A(byte* module, uint key)
{
#ifdef _WIN64
    return (uint)CalcModHash64_A(module, (uint64)key);
#elif _WIN32
    return (uint)CalcModHash32_A(module, (uint32)key);
#endif
}

__declspec(noinline)
uint CalcModHash_W(uint16* module, uint key)
{
#ifdef _WIN64
    return (uint)CalcModHash64_W(module, (uint64)key);
#elif _WIN32
    return (uint)CalcModHash32_W(module, (uint32)key);
#endif
}

__declspec(noinline)
uint CalcProcHash(byte* procedure, uint key)
{
#ifdef _WIN64
    return (uint)CalcProcHash64(procedure, (uint64)key);
#elif _WIN32
    return (uint)CalcProcHash32(procedure, (uint32)key);
#endif
}

__declspec(noinline)
void* GetInMemoryOrderModuleList()
{
#ifdef _WIN64
    uintptr teb = __readgsqword(0x30);
    uintptr peb = *(uintptr*)(teb + 0x60);
    uintptr ldr = *(uintptr*)(peb + 0x18);
    uintptr mod = *(uintptr*)(ldr + 0x20);
#elif _WIN32
    uintptr teb = __readfsdword(0x18);
    uintptr peb = *(uintptr*)(teb + 0x30);
    uintptr ldr = *(uintptr*)(peb + 0x0C);
    uintptr mod = *(uintptr*)(ldr + 0x14);
#endif
    return (void*)mod;
}

#define KEY_SIZE_32 4
#define ROR_BITS_32 4
#define ROR_SEED_32 (ROR_BITS_32 + 1)
#define ROR_KEY_32  (ROR_BITS_32 + 2)
#define ROR_MOD_32  (ROR_BITS_32 + 3)
#define ROR_PROC_32 (ROR_BITS_32 + 4)

static uint32 calcSeedHash32(uint32 key);
static uint32 calcKeyHash32(uint32 seed, uint32 key);
static uint32 ror32(uint32 value, uint32 bits);

__declspec(noinline)
uint32 CalcModHash32_A(byte* module, uint32 key)
{
    uint32 seedHash = calcSeedHash32(key);
    uint32 keyHash  = calcKeyHash32(seedHash, key);
    uint32 modHash  = seedHash;
    for (;;)
    {
        byte b = *module;
        if (b == 0x00)
        {
            break;
        }
        if (b >= 'a')
        {
            b -= 0x20;
        }
        modHash = ror32(modHash, ROR_MOD_32);
        modHash += b;
        modHash = ror32(modHash, ROR_MOD_32);
        modHash += 0;
        module++;
    }
    return seedHash + keyHash + modHash;
}

__declspec(noinline)
uint32 CalcModHash32_W(uint16* module, uint32 key)
{
    uint32 seedHash = calcSeedHash32(key);
    uint32 keyHash  = calcKeyHash32(seedHash, key);
    uint32 modHash  = seedHash;
    for (;;)
    {
        byte b0 = *(byte*)((uintptr)module + 0);
        byte b1 = *(byte*)((uintptr)module + 1);
        if (b0 == 0x00 && b1 == 0x00)
        {
            break;
        }
        if (b0 >= 'a')
        {
            b0 -= 0x20;
        }
        if (b1 >= 'a')
        {
            b1 -= 0x20;
        }
        modHash = ror32(modHash, ROR_MOD_32);
        modHash += b0;
        modHash = ror32(modHash, ROR_MOD_32);
        modHash += b1;
        module++;
    }
    return seedHash + keyHash + modHash;
}

__declspec(noinline)
uint32 CalcProcHash32(byte* procedure, uint32 key)
{
    uint32 seedHash = calcSeedHash32(key);
    uint32 keyHash  = calcKeyHash32(seedHash, key);
    uint32 procHash = seedHash;
    for (;;)
    {
        byte b = *procedure;
        if (b == 0x00)
        {
            break;
        }
        procHash = ror32(procHash, ROR_PROC_32);
        procHash += b;
        procedure++;
    }
    return seedHash + keyHash + procHash;
}

static uint32 calcSeedHash32(uint32 key)
{
    uint32 hash = key;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE_32; i++)
    {
        hash = ror32(hash, ROR_SEED_32);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint32 calcKeyHash32(uint32 seed, uint32 key)
{
    uint32 hash = seed;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE_32; i++)
    {
        hash = ror32(hash, ROR_KEY_32);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint32 ror32(uint32 value, uint32 bits)
{
    return value >> bits | value << (32 - bits);
}

#define KEY_SIZE_64 8
#define ROR_BITS_64 8
#define ROR_SEED_64 (ROR_BITS_64 + 1)
#define ROR_KEY_64  (ROR_BITS_64 + 2)
#define ROR_MOD_64  (ROR_BITS_64 + 3)
#define ROR_PROC_64 (ROR_BITS_64 + 4)

static uint64 calcSeedHash64(uint64 key);
static uint64 calcKeyHash64(uint64 seed, uint64 key);
static uint64 ror64(uint64 value, uint64 bits);

__declspec(noinline)
uint64 CalcModHash64_A(byte* module, uint64 key)
{
    uint64 seedHash = calcSeedHash64(key);
    uint64 keyHash  = calcKeyHash64(seedHash, key);
    uint64 modHash  = seedHash;
    for (;;)
    {
        byte b = *module;
        if (b == 0x00)
        {
            break;
        }
        if (b >= 'a')
        {
            b -= 0x20;
        }
        modHash = ror64(modHash, ROR_MOD_64);
        modHash += b;
        modHash = ror64(modHash, ROR_MOD_64);
        modHash += 0;
        module++;
    }
    return seedHash + keyHash + modHash;
}

__declspec(noinline)
uint64 CalcModHash64_W(uint16* module, uint64 key)
{
    uint64 seedHash = calcSeedHash64(key);
    uint64 keyHash  = calcKeyHash64(seedHash, key);
    uint64 modHash  = seedHash;
    for (;;)
    {
        byte b0 = *(byte*)((uintptr)module + 0);
        byte b1 = *(byte*)((uintptr)module + 1);
        if (b0 == 0x00 && b1 == 0x00)
        {
            break;
        }
        if (b0 >= 'a')
        {
            b0 -= 0x20;
        }
        if (b1 >= 'a')
        {
            b1 -= 0x20;
        }
        modHash = ror64(modHash, ROR_MOD_64);
        modHash += b0;
        modHash = ror64(modHash, ROR_MOD_64);
        modHash += b1;
        module++;
    }
    return seedHash + keyHash + modHash;
}

__declspec(noinline)
uint64 CalcProcHash64(byte* procedure, uint64 key)
{
    uint64 seedHash = calcSeedHash64(key);
    uint64 keyHash  = calcKeyHash64(seedHash, key);
    uint64 procHash = seedHash;
    for (;;)
    {
        byte b = *procedure;
        if (b == 0x00)
        {
            break;
        }
        procHash = ror64(procHash, ROR_PROC_64);
        procHash += b;
        procedure++;
    }
    return seedHash + keyHash + procHash;
}

static uint64 calcSeedHash64(uint64 key)
{
    uint64 hash = key;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE_64; i++)
    {
        hash = ror64(hash, ROR_SEED_64);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint64 calcKeyHash64(uint64 seed, uint64 key)
{
    uint64 hash = seed;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE_64; i++)
    {
        hash = ror64(hash, ROR_KEY_64);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint64 ror64(uint64 value, uint64 bits)
{
    return value >> bits | value << (64 - bits);
}
