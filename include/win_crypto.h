#ifndef WIN_CRYPTO_H
#define WIN_CRYPTO_H

#include "c_types.h"
#include "errno.h"
#include "context.h"

// The allocated buffer must call Runtime_M.Memory.Free().
// The AES is use GCM mode with 256 bit key.

typedef errno (*WCRandBuffer_t)(byte* data, uint len);
typedef errno (*WCSHA1_t)(byte* data, uint len, byte* hash);
typedef errno (*WCAESEncrypt_t)(byte* data, uint len, byte* key);
typedef errno (*WCAESDecrypt_t)(byte* data, uint len, byte* key);

typedef errno (*WCUninstall_t)();

typedef struct {
    WCRandBuffer_t RandBuffer;
    WCSHA1_t       SHA1;
    WCAESEncrypt_t AESEncrypt;
    WCAESDecrypt_t AESDecrypt;

    WCUninstall_t  Uninstall;
} WinCrypto_M;

WinCrypto_M* InitWinCrypto(Context* context);

#endif // WIN_CRYPTO_H
