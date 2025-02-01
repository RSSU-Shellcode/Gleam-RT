#ifndef WIN_CRYPTO_H
#define WIN_CRYPTO_H

#include "c_types.h"
#include "errno.h"
#include "context.h"

// The allocated buffer must call Runtime_M.Memory.Free().
// 
// The AES is use CBC mode with 256 bit key and PKCS#5.
// 
// +---------+-------------+
// |   IV    | cipher data |
// +---------+-------------+
// | 16 byte |     var     |
// +---------+-------------+
//
// The RSA private key length is 4096 bit.

#define WC_SHA1_SIZE    20
#define WC_AES_KEY_SIZE 32
#define WC_AES_IV_SIZE  16

#define WC_RSA_KEY_USAGE_SIGN 1
#define WC_RSA_KEY_USAGE_KEYX 2

typedef errno (*WCRandBuffer_t)(byte* data, uint len);
typedef errno (*WCGenRSAKey_t)(uint bits, byte** data, uint* len, uint usage);
typedef errno (*WCSHA1_t)(byte* data, uint len, byte* hash);
typedef errno (*WCAESEncrypt_t)(byte* data, uint len, byte* key, byte** out, uint* outLen);
typedef errno (*WCAESDecrypt_t)(byte* data, uint len, byte* key, byte** out, uint* outLen);
typedef errno (*WCRSASign_t)(byte* data, uint len, byte* key, byte** sign, uint* signLen);
typedef errno (*WCRSAVerify_t)(byte* data, uint len, byte* sign, uint signLen, byte* key);

typedef errno (*WCUninstall_t)();

typedef struct {
    WCRandBuffer_t RandBuffer;
    WCGenRSAKey_t  GenRSAKey;
    WCSHA1_t       SHA1;
    WCAESEncrypt_t AESEncrypt;
    WCAESDecrypt_t AESDecrypt;
    WCRSASign_t    RSASign;
    WCRSAVerify_t  RSAVerify;

    WCUninstall_t  Uninstall;
} WinCrypto_M;

WinCrypto_M* InitWinCrypto(Context* context);

#endif // WIN_CRYPTO_H
