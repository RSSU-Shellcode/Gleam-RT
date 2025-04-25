#ifndef MEM_SCANNER_H
#define MEM_SCANNER_H

#include "c_types.h"

// MemScan is used to scans data in the memory of the current process.
// The return value is the number of results scanned, if return -1,
// use the GetLastErrno for get error code.
uint MemScan(byte* pattern, uintptr* results, uint maxItem);

#endif // MEM_SCANNER_H
