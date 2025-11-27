#ifndef RANDOM_H
#define RANDOM_H

#include "c_types.h"

// [reference]
// https://en.wikipedia.org/wiki/xorshift

// RandInt is used to generate random int.
int RandInt(uint64 seed);

// RandInt8 is used to generate random int8.
int8 RandInt8(uint64 seed);

// RandInt16 is used to generate random int16.
int16 RandInt16(uint64 seed);

// RandInt32 is used to generate random int32.
int32 RandInt32(uint64 seed);

// RandInt64 is used to generate random int64.
int64 RandInt64(uint64 seed);

// RandUint is used to generate random uint.
uint RandUint(uint64 seed);

// RandUint8 is used to generate random uint8.
uint8 RandUint8(uint64 seed);

// RandUint16 is used to generate random uint16.
uint16 RandUint16(uint64 seed);

// RandUint32 is used to generate random uint32.
uint32 RandUint32(uint64 seed);

// RandUint64 is used to generate random uint64.
uint64 RandUint64(uint64 seed);

// RandIntN is used to generate random int with range.
int RandIntN(uint64 seed, int n);

// RandInt8N is used to generate random int8 with range.
int8 RandInt8N(uint64 seed, int8 n);

// RandInt16N is used to generate random int16 with range.
int16 RandInt16N(uint64 seed, int16 n);

// RandInt32N is used to generate random int32 with range.
int32 RandInt32N(uint64 seed, int32 n);

// RandInt64N is used to generate random int64 with range.
int64 RandInt64N(uint64 seed, int64 n);

// RandUintN is used to generate random uint with range.
uint RandUintN(uint64 seed, uint n);

// RandUint8N is used to generate random uint8 with range.
uint8 RandUint8N(uint64 seed, uint8 n);

// RandUint16N is used to generate random uint16 with range.
uint16 RandUint16N(uint64 seed, uint16 n);

// RandUint32N is used to generate random uint32 with range.
uint32 RandUint32N(uint64 seed, uint32 n);

// RandUint64N is used to generate random uint64 with range.
uint64 RandUint64N(uint64 seed, uint64 n);

// RandByte is used to generate random byte.
byte RandByte(uint64 seed);

// RandBool is used to generate random bool.
bool RandBool(uint64 seed);

// RandBOOL is used to generate random BOOL.
BOOL RandBOOL(uint64 seed);

// RandBuffer is used to fill random bytes to the memory.
void RandBuffer(void* buf, int64 size);

// RandSequence is used to generate random sequence with range.
// example: RandSequence(array, 4) will set array like [0, 3, 1, 2]
void RandSequence(int* array, int n);

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
