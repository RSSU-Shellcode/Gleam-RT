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
static void permuteSBox(byte* sBox);
static byte ror(byte value, uint8 bits);
static byte rol(byte value, uint8 bits);

#pragma optimize("t", on)

void EncryptBuf(byte* buf, uint size, byte* key, byte* iv)
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
    uint32 seed0 = seeds[0];
    uint32 seed1 = seeds[1];
    uint32 seed2 = seeds[2];
    uint32 seed3 = seeds[3];
    uint32 seed4 = seeds[4];
    uint32 seed5 = seeds[5];
    uint32 seed6 = seeds[6];
    uint32 seed7 = seeds[7];

    uintptr i = 0;
    uint limit = size - (size % PARALLEL_LEVEL);
    for (; i < limit; i += PARALLEL_LEVEL)
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
        byte b0 = buf[i + 0];
        byte b1 = buf[i + 1];
        byte b2 = buf[i + 2];
        byte b3 = buf[i + 3];
        byte b4 = buf[i + 4];
        byte b5 = buf[i + 5];
        byte b6 = buf[i + 6];
        byte b7 = buf[i + 7];

        // permutation
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

        // permutation
        b0 = sBox[b0];
        b1 = sBox[b1];
        b2 = sBox[b2];
        b3 = sBox[b3];
        b4 = sBox[b4];
        b5 = sBox[b5];
        b6 = sBox[b6];
        b7 = sBox[b7];

        // store cipher data
        buf[i + 0] = b0;
        buf[i + 1] = b1;
        buf[i + 2] = b2;
        buf[i + 3] = b3;
        buf[i + 4] = b4;
        buf[i + 5] = b5;
        buf[i + 6] = b6;
        buf[i + 7] = b7;
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
    for (; i < size; i++)
    {
        buf[i] = sBox[buf[i]];
    }
}

void DecryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    if (size == 0)
    {
        return;
    }
    byte sBox[256];
    initSBox(sBox, key, iv);
    permuteSBox(sBox);
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
    uint32 seed0 = seeds[0];
    uint32 seed1 = seeds[1];
    uint32 seed2 = seeds[2];
    uint32 seed3 = seeds[3];
    uint32 seed4 = seeds[4];
    uint32 seed5 = seeds[5];
    uint32 seed6 = seeds[6];
    uint32 seed7 = seeds[7];

    uintptr i = 0;
    uint limit = size - (size % PARALLEL_LEVEL);
    for (; i < limit; i += PARALLEL_LEVEL)
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
        byte b0 = buf[i + 0];
        byte b1 = buf[i + 1];
        byte b2 = buf[i + 2];
        byte b3 = buf[i + 3];
        byte b4 = buf[i + 4];
        byte b5 = buf[i + 5];
        byte b6 = buf[i + 6];
        byte b7 = buf[i + 7];

        // permutation
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

        // permutation
        b0 = sBox[b0];
        b1 = sBox[b1];
        b2 = sBox[b2];
        b3 = sBox[b3];
        b4 = sBox[b4];
        b5 = sBox[b5];
        b6 = sBox[b6];
        b7 = sBox[b7];

        // store plain data
        buf[i + 0] = b0;
        buf[i + 1] = b1;
        buf[i + 2] = b2;
        buf[i + 3] = b3;
        buf[i + 4] = b4;
        buf[i + 5] = b5;
        buf[i + 6] = b6;
        buf[i + 7] = b7;
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
    for (; i < size; i++)
    {
        buf[i] = sBox[buf[i]];
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

static void permuteSBox(byte* sBox)
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

void EncryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    byte b = *key + *iv;
    for (uint i = 0; i < size; i++)
    {
        *buf ^= b;
        buf++;
    }
}

void DecryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    byte b = *key + *iv;
    for (uint i = 0; i < size; i++)
    {
        *buf ^= b;
        buf++;
    }
}

#endif
