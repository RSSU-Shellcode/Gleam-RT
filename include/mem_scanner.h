#ifndef MEM_SCANNER_H
#define MEM_SCANNER_H

#include "c_types.h"

#define ERR_MEMSCAN_NOT_FOUND_API 0x80000001
#define ERR_MEMSCAN_VIRTUAL_QUERY 0x80000002

// MemScan is used to scans data in the memory of the current process.
// The return value is the number of results scanned.
uint MemScan(byte* pattern, uintptr* results, uint maxItem);

#endif // MEM_SCANNER_H
