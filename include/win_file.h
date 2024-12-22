#ifndef WIN_FILE_H
#define WIN_FILE_H

#include "c_types.h"
#include "win_types.h"
#include "context.h"
#include "errno.h"

// The buffer allocated from ReadFile must call Runtime_M.Memory.Free().

typedef errno (*WFReadFileA_t)(LPSTR path, byte** buf, uint* size);
typedef errno (*WFReadFileW_t)(LPWSTR path, byte** buf, uint* size);
typedef errno (*WFWriteFileA_t)(LPSTR path, byte* buf, uint size);
typedef errno (*WFWriteFileW_t)(LPWSTR path, byte* buf, uint size);

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
