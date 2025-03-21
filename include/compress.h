#ifndef COMPRESS_H
#define COMPRESS_H

#include "c_types.h"

// Compress is used to compress data with LZSS.
// If return value is -1, window size is invalid.
// If dst is NULL, calculate the compressed length.
uint Compress(void* dst, void* src, uint len, uint window);

// Decompress is used to decompress data with LZSS.
// If dst is NULL, calculate the raw data length.
uint Decompress(void* dst, void* src, uint len);

#endif // COMPRESS_H
