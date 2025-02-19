#ifndef WIN_FILE_H
#define WIN_FILE_H

#include "c_types.h"
#include "win_types.h"
#include "errno.h"
#include "context.h"

// The buffer allocated from ReadFile must call Runtime_M.Memory.Free().

typedef errno (*WFReadFileA_t)(LPSTR path, databuf* file);
typedef errno (*WFReadFileW_t)(LPWSTR path, databuf* file);
typedef errno (*WFWriteFileA_t)(LPSTR path, databuf* file);
typedef errno (*WFWriteFileW_t)(LPWSTR path, databuf* file);

typedef errno (*WFUninstall_t)();

typedef struct {
    WFReadFileA_t  ReadFileA;
    WFReadFileW_t  ReadFileW;
    WFWriteFileA_t WriteFileA;
    WFWriteFileW_t WriteFileW;

    WFUninstall_t Uninstall;
} WinFile_M;

WinFile_M* InitWinFile(Context* context);

#endif // WIN_FILE_H
