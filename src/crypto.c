#include "build.h"
#include "c_types.h"
#include "lib_memory.h"
#include "random.h"
#include "crypto.h"

// !!!!!!!!  It is NOT cryptographically secure  !!!!!!!!!
// 
// The main purpose of this symmetric encryption algorithm
// is to encrypt the data in the memory so that it looks 
// like there is no obvious pattern. 
// 
// It's main design goal is to be as small as possible and 
// not to use a simple XOR encryption.

#ifndef FAST_CRYPTO

#define PARALLEL_LEVEL 8

static void encryptBuf(byte* buf, uint size, byte* key, byte* iv, byte* sBox);
static void decryptBuf(byte* buf, uint size, byte* key, byte* iv, byte* sBox);
static void initSBox(byte* sBox, byte* key, byte* iv);
static void reverseSBox(byte* sBox);
static byte ror(byte value, uint8 bits);
static byte rol(byte value, uint8 bits);

#pragma optimize("t", on)

void EncryptBuf(void* buf, uint size, byte* key, byte* iv)
{
    if (size == 0)
    {
        return;
    }
    byte sBox[256];
    initSBox(sBox, key, iv);
    encryptBuf(buf, size, key, iv, sBox);
}

static void encryptBuf(byte* buf, uint size, byte* key, byte* iv, byte* sBox)
{
    // just generate from random data
    uint32 seeds[8] = {
        0xFA1C345C, 0xAF16C47C, 0x1C553A02, 0x9EDAC545,
        0xC942A49C, 0x5FE323EC, 0x9A1934AC, 0x2CB443C1,
    };
    // initialize random seeds
    for (int i = 0; i < 8; i++)
    {
        seeds[i] *= (uint32)(key[i * 4 + 0]) << 0;
        seeds[i] *= (uint32)(key[i * 4 + 1]) << 8;
        seeds[i] *= (uint32)(key[i * 4 + 2]) << 16;
        seeds[i] *= (uint32)(key[i * 4 + 3]) << 24;

        seeds[i] ^= (uint32)(key[i * 4 + 0]) << 0;
        seeds[i] ^= (uint32)(key[i * 4 + 1]) << 8;
        seeds[i] ^= (uint32)(key[i * 4 + 2]) << 16;
        seeds[i] ^= (uint32)(key[i * 4 + 3]) << 24;

        seeds[i] ^= (uint32)(iv[i * 2 + 0]) << 8;
        seeds[i] ^= (uint32)(iv[i * 2 + 1]) << 24;
    }

    // load random seeds
    register uint32 seed0 = seeds[0];
    register uint32 seed1 = seeds[1];
    register uint32 seed2 = seeds[2];
    register uint32 seed3 = seeds[3];
    register uint32 seed4 = seeds[4];
    register uint32 seed5 = seeds[5];
    register uint32 seed6 = seeds[6];
    register uint32 seed7 = seeds[7];

    byte last  = 170;
    uint limit = size - (size % PARALLEL_LEVEL);
    for (uint i = 0; i < limit; i += PARALLEL_LEVEL)
    {
        // update seeds
        seed0 = XORShift32(seed0);
        seed1 = XORShift32(seed1);
        seed2 = XORShift32(seed2);
        seed3 = XORShift32(seed3);
        seed4 = XORShift32(seed4);
        seed5 = XORShift32(seed5);
        seed6 = XORShift32(seed6);
        seed7 = XORShift32(seed7);

        // load plain data
        uint64 block = *(uint64*)(buf + i);
        register byte b0 = (byte)(block >> 0);
        register byte b1 = (byte)(block >> 8);
        register byte b2 = (byte)(block >> 16);
        register byte b3 = (byte)(block >> 24);
        register byte b4 = (byte)(block >> 32);
        register byte b5 = (byte)(block >> 40);
        register byte b6 = (byte)(block >> 48);
        register byte b7 = (byte)(block >> 56);

        // substitution
        b0 = sBox[b0];
        b1 = sBox[b1];
        b2 = sBox[b2];
        b3 = sBox[b3];
        b4 = sBox[b4];
        b5 = sBox[b5];
        b6 = sBox[b6];
        b7 = sBox[b7];

        b0 ^= seed0;
        b1 ^= seed1;
        b2 ^= seed2;
        b3 ^= seed3;
        b4 ^= seed4;
        b5 ^= seed5;
        b6 ^= seed6;
        b7 ^= seed7;

        b0 = ror(b0, (seed0 >> 8) % 8);
        b1 = ror(b1, (seed1 >> 8) % 8);
        b2 = ror(b2, (seed2 >> 8) % 8);
        b3 = ror(b3, (seed3 >> 8) % 8);
        b4 = ror(b4, (seed4 >> 8) % 8);
        b5 = ror(b5, (seed5 >> 8) % 8);
        b6 = ror(b6, (seed6 >> 8) % 8);
        b7 = ror(b7, (seed7 >> 8) % 8);

        b0 ^= seed0 >> 8;
        b1 ^= seed1 >> 8;
        b2 ^= seed2 >> 8;
        b3 ^= seed3 >> 8;
        b4 ^= seed4 >> 8;
        b5 ^= seed5 >> 8;
        b6 ^= seed6 >> 8;
        b7 ^= seed7 >> 8;

        b0 = ror(b0, (seed0 >> 16) % 8);
        b1 = ror(b1, (seed1 >> 16) % 8);
        b2 = ror(b2, (seed2 >> 16) % 8);
        b3 = ror(b3, (seed3 >> 16) % 8);
        b4 = ror(b4, (seed4 >> 16) % 8);
        b5 = ror(b5, (seed5 >> 16) % 8);
        b6 = ror(b6, (seed6 >> 16) % 8);
        b7 = ror(b7, (seed7 >> 16) % 8);

        b0 ^= (seed0 >> 16);
        b1 ^= (seed1 >> 16);
        b2 ^= (seed2 >> 16);
        b3 ^= (seed3 >> 16);
        b4 ^= (seed4 >> 16);
        b5 ^= (seed5 >> 16);
        b6 ^= (seed6 >> 16);
        b7 ^= (seed7 >> 16);

        b0 = ror(b0, (seed0 >> 24) % 8);
        b1 = ror(b1, (seed1 >> 24) % 8);
        b2 = ror(b2, (seed2 >> 24) % 8);
        b3 = ror(b3, (seed3 >> 24) % 8);
        b4 = ror(b4, (seed4 >> 24) % 8);
        b5 = ror(b5, (seed5 >> 24) % 8);
        b6 = ror(b6, (seed6 >> 24) % 8);
        b7 = ror(b7, (seed7 >> 24) % 8);

        b0 ^= (seed0 >> 24);
        b1 ^= (seed1 >> 24);
        b2 ^= (seed2 >> 24);
        b3 ^= (seed3 >> 24);
        b4 ^= (seed4 >> 24);
        b5 ^= (seed5 >> 24);
        b6 ^= (seed6 >> 24);
        b7 ^= (seed7 >> 24);

        // substitution
        b0 = sBox[b0];
        b1 = sBox[b1];
        b2 = sBox[b2];
        b3 = sBox[b3];
        b4 = sBox[b4];
        b5 = sBox[b5];
        b6 = sBox[b6];
        b7 = sBox[b7];

        // diffuse cipher data
        b0 ^= last;
        b1 ^= b0;
        b2 ^= b1;
        b3 ^= b2;
        b4 ^= b3;
        b5 ^= b4;
        b6 ^= b5;
        b7 ^= b6;

        // update the last
        last = b7;

        // store cipher data
        block = 0;
        block += (uint64)(b0) << 0;
        block += (uint64)(b1) << 8;
        block += (uint64)(b2) << 16;
        block += (uint64)(b3) << 24;
        block += (uint64)(b4) << 32;
        block += (uint64)(b5) << 40;
        block += (uint64)(b6) << 48;
        block += (uint64)(b7) << 56;
        *(uint64*)(buf + i) = block;

        // diffuse seed
        uint32 diff0 = (uint32)(block >> 0);
        uint32 diff1 = (uint32)(block >> 32);
        seed0 ^= diff0;
        seed1 ^= diff0;
        seed2 ^= diff0;
        seed3 ^= diff0;
        seed4 ^= diff1;
        seed5 ^= diff1;
        seed6 ^= diff1;
        seed7 ^= diff1;
    }

    // update random seeds
    seeds[0] = seed0;
    seeds[1] = seed1;
    seeds[2] = seed2;
    seeds[3] = seed3;
    seeds[4] = seed4;
    seeds[5] = seed5;
    seeds[6] = seed6;
    seeds[7] = seed7;

    // process remaining not aligned data
    for (uint i = limit; i < size; i++)
    {
        // get and update seed
        uint32 seed = seeds[i % 8];
        seed = XORShift32(seed);

        // load plain data
        byte b = buf[i];

        // substitution
        b = sBox[b];

        // xor and ror
        b ^= seed;
        b = ror(b, (seed >> 8) % 8);
        b ^= seed >> 8;
        b = ror(b, (seed >> 16) % 8);
        b ^= (seed >> 16);
        b = ror(b, (seed >> 24) % 8);
        b ^= (seed >> 24);

        // substitution
        b = sBox[b];

        // diffuse cipher data
        b ^= last;

        // update the last
        last = b;

        // store cipher data
        buf[i] = b;
    }
}

void DecryptBuf(void* buf, uint size, byte* key, byte* iv)
{
    if (size == 0)
    {
        return;
    }
    byte sBox[256];
    initSBox(sBox, key, iv);
    reverseSBox(sBox);
    decryptBuf(buf, size, key, iv, sBox);
}

static void decryptBuf(byte* buf, uint size, byte* key, byte* iv, byte* sBox)
{
    // just generate from random data
    uint32 seeds[8] = {
        0xFA1C345C, 0xAF16C47C, 0x1C553A02, 0x9EDAC545,
        0xC942A49C, 0x5FE323EC, 0x9A1934AC, 0x2CB443C1,
    };
    // initialize random seeds
    for (int i = 0; i < 8; i++)
    {
        seeds[i] *= (uint32)(key[i * 4 + 0]) << 0;
        seeds[i] *= (uint32)(key[i * 4 + 1]) << 8;
        seeds[i] *= (uint32)(key[i * 4 + 2]) << 16;
        seeds[i] *= (uint32)(key[i * 4 + 3]) << 24;

        seeds[i] ^= (uint32)(key[i * 4 + 0]) << 0;
        seeds[i] ^= (uint32)(key[i * 4 + 1]) << 8;
        seeds[i] ^= (uint32)(key[i * 4 + 2]) << 16;
        seeds[i] ^= (uint32)(key[i * 4 + 3]) << 24;

        seeds[i] ^= (uint32)(iv[i * 2 + 0]) << 8;
        seeds[i] ^= (uint32)(iv[i * 2 + 1]) << 24;
    }

    // load random seeds
    register uint32 seed0 = seeds[0];
    register uint32 seed1 = seeds[1];
    register uint32 seed2 = seeds[2];
    register uint32 seed3 = seeds[3];
    register uint32 seed4 = seeds[4];
    register uint32 seed5 = seeds[5];
    register uint32 seed6 = seeds[6];
    register uint32 seed7 = seeds[7];

    byte last  = 170;
    uint limit = size - (size % PARALLEL_LEVEL);
    for (uint i = 0; i < limit; i += PARALLEL_LEVEL)
    {
        // update seeds
        seed0 = XORShift32(seed0);
        seed1 = XORShift32(seed1);
        seed2 = XORShift32(seed2);
        seed3 = XORShift32(seed3);
        seed4 = XORShift32(seed4);
        seed5 = XORShift32(seed5);
        seed6 = XORShift32(seed6);
        seed7 = XORShift32(seed7);

        // load cipher data
        uint64 block = *(uint64*)(buf + i);
        register byte b0 = (byte)(block >> 0);
        register byte b1 = (byte)(block >> 8);
        register byte b2 = (byte)(block >> 16);
        register byte b3 = (byte)(block >> 24);
        register byte b4 = (byte)(block >> 32);
        register byte b5 = (byte)(block >> 40);
        register byte b6 = (byte)(block >> 48);
        register byte b7 = (byte)(block >> 56);

        // record cipher data
        byte lastc = b7;

        // diffuse cipher data
        b7 ^= b6;
        b6 ^= b5;
        b5 ^= b4;
        b4 ^= b3;
        b3 ^= b2;
        b2 ^= b1;
        b1 ^= b0;
        b0 ^= last;

        // update the last
        last = lastc;

        // substitution
        b0 = sBox[b0];
        b1 = sBox[b1];
        b2 = sBox[b2];
        b3 = sBox[b3];
        b4 = sBox[b4];
        b5 = sBox[b5];
        b6 = sBox[b6];
        b7 = sBox[b7];

        b0 ^= (seed0 >> 24);
        b1 ^= (seed1 >> 24);
        b2 ^= (seed2 >> 24);
        b3 ^= (seed3 >> 24);
        b4 ^= (seed4 >> 24);
        b5 ^= (seed5 >> 24);
        b6 ^= (seed6 >> 24);
        b7 ^= (seed7 >> 24);

        b0 = rol(b0, (seed0 >> 24) % 8);
        b1 = rol(b1, (seed1 >> 24) % 8);
        b2 = rol(b2, (seed2 >> 24) % 8);
        b3 = rol(b3, (seed3 >> 24) % 8);
        b4 = rol(b4, (seed4 >> 24) % 8);
        b5 = rol(b5, (seed5 >> 24) % 8);
        b6 = rol(b6, (seed6 >> 24) % 8);
        b7 = rol(b7, (seed7 >> 24) % 8);

        b0 ^= (seed0 >> 16);
        b1 ^= (seed1 >> 16);
        b2 ^= (seed2 >> 16);
        b3 ^= (seed3 >> 16);
        b4 ^= (seed4 >> 16);
        b5 ^= (seed5 >> 16);
        b6 ^= (seed6 >> 16);
        b7 ^= (seed7 >> 16);

        b0 = rol(b0, (seed0 >> 16) % 8);
        b1 = rol(b1, (seed1 >> 16) % 8);
        b2 = rol(b2, (seed2 >> 16) % 8);
        b3 = rol(b3, (seed3 >> 16) % 8);
        b4 = rol(b4, (seed4 >> 16) % 8);
        b5 = rol(b5, (seed5 >> 16) % 8);
        b6 = rol(b6, (seed6 >> 16) % 8);
        b7 = rol(b7, (seed7 >> 16) % 8);

        b0 ^= seed0 >> 8;
        b1 ^= seed1 >> 8;
        b2 ^= seed2 >> 8;
        b3 ^= seed3 >> 8;
        b4 ^= seed4 >> 8;
        b5 ^= seed5 >> 8;
        b6 ^= seed6 >> 8;
        b7 ^= seed7 >> 8;

        b0 = rol(b0, (seed0 >> 8) % 8);
        b1 = rol(b1, (seed1 >> 8) % 8);
        b2 = rol(b2, (seed2 >> 8) % 8);
        b3 = rol(b3, (seed3 >> 8) % 8);
        b4 = rol(b4, (seed4 >> 8) % 8);
        b5 = rol(b5, (seed5 >> 8) % 8);
        b6 = rol(b6, (seed6 >> 8) % 8);
        b7 = rol(b7, (seed7 >> 8) % 8);

        b0 ^= seed0;
        b1 ^= seed1;
        b2 ^= seed2;
        b3 ^= seed3;
        b4 ^= seed4;
        b5 ^= seed5;
        b6 ^= seed6;
        b7 ^= seed7;

        // substitution
        b0 = sBox[b0];
        b1 = sBox[b1];
        b2 = sBox[b2];
        b3 = sBox[b3];
        b4 = sBox[b4];
        b5 = sBox[b5];
        b6 = sBox[b6];
        b7 = sBox[b7];

        // diffuse seed
        uint32 diff0 = (uint32)(block >> 0);
        uint32 diff1 = (uint32)(block >> 32);
        seed0 ^= diff0;
        seed1 ^= diff0;
        seed2 ^= diff0;
        seed3 ^= diff0;
        seed4 ^= diff1;
        seed5 ^= diff1;
        seed6 ^= diff1;
        seed7 ^= diff1;

        // store plain data
        block = 0;
        block += (uint64)(b0) << 0;
        block += (uint64)(b1) << 8;
        block += (uint64)(b2) << 16;
        block += (uint64)(b3) << 24;
        block += (uint64)(b4) << 32;
        block += (uint64)(b5) << 40;
        block += (uint64)(b6) << 48;
        block += (uint64)(b7) << 56;
        *(uint64*)(buf + i) = block;
    }

    // update random seeds
    seeds[0] = seed0;
    seeds[1] = seed1;
    seeds[2] = seed2;
    seeds[3] = seed3;
    seeds[4] = seed4;
    seeds[5] = seed5;
    seeds[6] = seed6;
    seeds[7] = seed7;

    // process remaining not aligned data
    for (uint i = limit; i < size; i++)
    {
        // get and update seed
        uint32 seed = seeds[i % 8];
        seed = XORShift32(seed);

        // load cipher data
        byte b = buf[i];

        // record cipher data
        byte lastc = b;

        // diffuse cipher data
        b ^= last;

        // update the last
        last = lastc;

        // substitution
        b = sBox[b];

       // xor and rol
        b ^= (seed >> 24);
        b = rol(b, (seed >> 24) % 8);
        b ^= (seed >> 16);
        b = rol(b, (seed >> 16) % 8);
        b ^= seed >> 8;
        b = rol(b, (seed >> 8) % 8);
        b ^= seed;

        // substitution
        b = sBox[b];

        // store plain data
        buf[i] = b;
    }
}

static void initSBox(byte* sBox, byte* key, byte* iv)
{
    // initialize S-Box byte array
    for (int i = 0; i < 256; i++)
    {
        // + key[0] is used to prevent 
        // incorrect compiler optimization
        sBox[i] = (byte)i + key[0];
    }
    // initialize seed for XOR Shift;
    uint32 seed = 0x2294FD61;
    for (int i = 0; i < CRYPTO_KEY_SIZE; i++)
    {
        seed += *(key + i);
    }
    for (int i = 0; i < CRYPTO_IV_SIZE; i++)
    {
        seed *= *(iv + i);
    }
    // generate S-Box from random index
    for (int i = 0; i < 128; i++)
    {
        // swap array item
        seed = XORShift32(seed);
        byte idx0 = (byte)(seed+32);
        byte idx1 = (byte)(seed+64);
        byte swap = sBox[idx0];
        sBox[idx0] = sBox[idx1];
        sBox[idx1] = swap;
    }
}

static void reverseSBox(byte* sBox)
{
    byte buf[256];
    mem_copy(buf, sBox, sizeof(buf));
    for (int i = 0; i < 256; i++)
    {
        sBox[buf[i]] = (byte)i;
    }
}

static byte ror(byte value, uint8 bits)
{
    return value >> bits | value << (8 - bits);
}

static byte rol(byte value, uint8 bits)
{
    return value << bits | value >> (8 - bits);
}

#pragma optimize("t", off)

#else

void EncryptBuf(void* buf, uint size, byte* key, byte* iv)
{
    byte* buffer = buf;
    byte b = *key + *iv;
    for (uint i = 0; i < size; i++)
    {
        *buffer ^= b;
        buffer++;
    }
}

void DecryptBuf(void* buf, uint size, byte* key, byte* iv)
{
    byte* buffer = buf;
    byte b = *key + *iv;
    for (uint i = 0; i < size; i++)
    {
        *buffer ^= b;
        buffer++;
    }
}

#endif

#pragma optimize("", off)
void XORBuf(void* buf, uint bufSize, void* key, uint keySize)
{
    if (bufSize == 0 || keySize == 0)
    {
        return;
    }
    byte* b = buf;
    byte* k = key;
    uint keyIdx = 0;
    for (uint i = 0; i < bufSize; i++)
    {
        *b ^= *(k + keyIdx);
        keyIdx++;
        if (keyIdx >= keySize)
        {
            keyIdx = 0;
        }
        b++;
    }
}
#pragma optimize("", on)
