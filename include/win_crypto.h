#ifndef WIN_CRYPTO_H
#define WIN_CRYPTO_H

#include "c_types.h"
#include "context.h"
#include "errno.h"

// The allocated buffer must call Runtime_M.Memory.Free().
typedef void (*WCRandBuffer_t)(byte* data, uint len);
typedef void (*WCSHA1_t)(byte* data, uint len, byte* hash);

typedef errno (*WCUninstall_t)();

typedef struct {
    WCRandBuffer_t RandBuffer;
    WCSHA1_t       SHA1;

    WCUninstall_t Uninstall;
} WinCrypto_M;

WinCrypto_M* InitWinCrypto(Context* context);

#endif // WIN_CRYPTO_H
