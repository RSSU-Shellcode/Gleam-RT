#ifndef WIN_CRYPTO_H
#define WIN_CRYPTO_H

#include "c_types.h"
#include "errno.h"
#include "context.h"

// The allocated buffer must call Runtime_M.Memory.Free().
// The AES is use CBC mode with 256 bit key and PKCS5.
// 
// +---------+-------------+
// |   IV    | cipher data |
// +---------+-------------+
// | 16 byte |     var     |
// +---------+-------------+

#define WC_AES_KEY_SIZE 32
#define WC_AES_IV_SIZE  16

typedef errno (*WCRandBuffer_t)(byte* data, uint len);
typedef errno (*WCSHA1_t)(byte* data, uint len, byte* hash);
typedef errno (*WCAESEncrypt_t)(byte* data, uint len, byte* key, byte** out, uint* outLen);
typedef errno (*WCAESDecrypt_t)(byte* data, uint len, byte* key, byte** out, uint* outLen);

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
