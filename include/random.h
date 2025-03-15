#ifndef RANDOM_H
#define RANDOM_H

#include "c_types.h"

// [reference]
// https://en.wikipedia.org/wiki/xorshift

// RandBuffer is used to fill random bytes to the memory.
void RandBuffer(void* buf, int64 size);

// RandByte is used to generate random byte.
byte RandByte(uint64 seed);

// RandBool is used to generate random bool.
bool RandBool(uint64 seed);

// RandInt is used to generate random int.
int RandInt(uint64 seed);

// RandUint is used to generate random uint.
uint RandUint(uint64 seed);

// RandInt64 is used to generate random int64.
int64 RandInt64(uint64 seed);

// RandUint64 is used to generate random uint64.
uint64 RandUint64(uint64 seed);

// RandIntN is used to generate random int with range.
int RandIntN(uint64 seed, int n);

// RandUintN is used to generate random uint with range.
uint RandUintN(uint64 seed, uint n);

// RandInt64N is used to generate random int64 with range.
int64 RandInt64N(uint64 seed, int64 n);

// RandUint64N is used to generate random uint64 with range.
uint64 RandUint64N(uint64 seed, uint64 n);

// for generate random data fast.
uint   XORShift(uint seed);
uint32 XORShift32(uint32 seed);
uint64 XORShift64(uint64 seed);

// GenerateSeed is used to generate a seed from CPU context.
#pragma warning(push)
#pragma warning(disable: 4276)
extern uint64 GenerateSeed();
#pragma warning(pop)

#endif // RANDOM_H
