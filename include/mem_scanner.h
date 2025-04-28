#ifndef MEM_SCANNER_H
#define MEM_SCANNER_H

#include "c_types.h"

// MemScanByValue is used to scan data by exact value in the memory
// of the current process.
// The return value is the number of results scanned, if failed to
// scan, it will return -1, use the GetLastErrno for get error code.
uint MemScanByValue(void* value, uint size, uintptr* results, uint maxItem);

// MemScanByPattern is used to scan data by pattern in the memory
// of the current process.
// The return value is the number of results scanned, if failed to
// scan, it will return -1, use the GetLastErrno for get error code.
uint MemScanByPattern(byte* pattern, uintptr* results, uint maxItem);

// BinToPattern is used to convert binary data to pattern for MemScan.
void BinToPattern(void* data, uint size, byte* pattern);

#endif // MEM_SCANNER_H
