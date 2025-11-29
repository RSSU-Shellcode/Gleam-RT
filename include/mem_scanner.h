#ifndef MEM_SCANNER_H
#define MEM_SCANNER_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"

typedef struct {
    uintptr MinAddress;
    uintptr MaxAddress;

    VirtualQuery_t VirtualQuery;
} MemScan_Ctx;

typedef struct {
    byte* Pattern;
    DWORD Protect; // default PAGE_READWRITE
    DWORD Type;    // default MEM_PRIVATE
} MemScan_Cfg;

// MemScanByValue is used to scan data by exact value in the memory
// of the current process.
// 
// It will only scan memory page protect with PAGE_READWRITE, if you
// want to scan other protect, use MemScanByConfig.
// 
// The return value is the number of results scanned, if failed to
// scan, it will return -1, use the GetLastErrno for get error code.
uint MemScanByValue(MemScan_Ctx* ctx, void* value, uint size, uintptr* results, uint maxItem);

// MemScanByConfig is used to scan data by config like pattern in
// the memory of the current process.
// 
// The return value is the number of results scanned, if failed to
// scan, it will return -1, use the GetLastErrno for get error code.
uint MemScanByConfig(MemScan_Ctx* ctx, MemScan_Cfg* config, uintptr* results, uint maxItem);

// BinToPattern is used to convert binary data to pattern for MemScan.
// The pattern buffer size must greater the [data size * 3 + 1].
void BinToPattern(void* data, uint size, byte* pattern);

#endif // MEM_SCANNER_H
