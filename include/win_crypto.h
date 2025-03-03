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
// The valid AES key length are 16, 24, 32 bytes.

#define WC_SHA1_HASH_SIZE 20
#define WC_AES_BLOCK_SIZE 16
#define WC_AES_IV_SIZE    16

#define WC_RSA_KEY_USAGE_SIGN 1
#define WC_RSA_KEY_USAGE_KEYX 2

typedef errno (*WCRandBuffer_t)(byte* data, uint len);
typedef errno (*WCSHA1_t)(byte* data, uint len, byte* hash);
typedef errno (*WCAESEncrypt_t)(databuf* data, databuf* key, databuf* out);
typedef errno (*WCAESDecrypt_t)(databuf* data, databuf* key, databuf* out);
typedef errno (*WCRSAGenKey_t)(uint usage, uint bits, databuf* key);
typedef errno (*WCRSASign_t)(databuf* data, databuf* key, databuf* sign);
typedef errno (*WCRSAVerify_t)(databuf* data, databuf* key, databuf* sign);

typedef errno (*WCUninstall_t)();

typedef struct {
    WCRandBuffer_t RandBuffer;
    WCSHA1_t       SHA1;
    WCAESEncrypt_t AESEncrypt;
    WCAESDecrypt_t AESDecrypt;
    WCRSAGenKey_t  RSAGenKey;
    WCRSASign_t    RSASign;
    WCRSAVerify_t  RSAVerify;

    WCUninstall_t Uninstall;
} WinCrypto_M;

WinCrypto_M* InitWinCrypto(Context* context);

#endif // WIN_CRYPTO_H
