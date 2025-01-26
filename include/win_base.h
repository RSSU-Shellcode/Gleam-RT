#ifndef WIN_BASE_H
#define WIN_BASE_H

#include "c_types.h"
#include "lib_string.h"
#include "errno.h"
#include "context.h"

// The buffer allocated from methods must call Runtime_M.Memory.Free().

typedef UTF16 (*WBANSIToUTF16_t)(ANSI s);
typedef ANSI  (*WBUTF16ToANSI_t)(UTF16 s);
typedef UTF16 (*WBANSIToUTF16N_t)(ANSI s, int n);
typedef ANSI  (*WBUTF16ToANSIN_t)(UTF16 s, int n);

typedef errno (*WBUninstall_t)();

typedef struct {
    WBANSIToUTF16_t  ANSIToUTF16;
    WBUTF16ToANSI_t  UTF16ToANSI;
    WBANSIToUTF16N_t ANSIToUTF16N;
    WBUTF16ToANSIN_t UTF16ToANSIN;

    WBUninstall_t Uninstall;
} WinBase_M;

WinBase_M* InitWinBase(Context* context);

#endif // WIN_BASE_H
