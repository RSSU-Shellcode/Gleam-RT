#ifndef WIN_CRYPTO_H
#define WIN_CRYPTO_H

#include "c_types.h"
#include "dll_advapi32.h"
#include "errno.h"
#include "context.h"

// The allocated databuf must call Runtime_M.Memory.Free().
// 
// +---------+-------------+
// |   IV    | cipher data |
// +---------+-------------+
// | 16 byte |     var     |
// +---------+-------------+
//
// The AES is use CBC mode with PKCS#5 padding method.
// The valid AES key length are 16, 24, 32 bytes.
// The RSA is use PKCS#1 v1.5 padding method.
//
// The AES Key only contain the key data, not contain header.
// The RSA Private/Public Key contain the header RSAPUBKEYHEADER.

#define WC_AES_BLOCK_SIZE 16
#define WC_AES_IV_SIZE    16

#define WC_RSA_KEY_USAGE_SIGN 1
#define WC_RSA_KEY_USAGE_KEYX 2

typedef errno (*WCRandBuffer_t)(databuf* data);
typedef errno (*WCHash_t)(ALG_ID aid, databuf* data, databuf* hash);
typedef errno (*WCHMAC_t)(ALG_ID aid, databuf* data, databuf* key, databuf* hash);
typedef errno (*WCAESEncrypt_t)(databuf* data, databuf* key, databuf* output);
typedef errno (*WCAESDecrypt_t)(databuf* data, databuf* key, databuf* output);
typedef errno (*WCRSAGenKey_t)(uint usage, uint bits, databuf* key);
typedef errno (*WCRSAPubKey_t)(databuf* key, databuf* output);
typedef errno (*WCRSASign_t)(ALG_ID aid, databuf* data, databuf* key, databuf* sign);
typedef errno (*WCRSAVerify_t)(ALG_ID aid, databuf* data, databuf* key, databuf* sign);
typedef errno (*WCRSAEncrypt_t)(databuf* data, databuf* key, databuf* output);
typedef errno (*WCRSADecrypt_t)(databuf* data, databuf* key, databuf* output);
typedef errno (*WCFreeDLL_t)();

typedef errno (*WCClean_t)();
typedef errno (*WCUninstall_t)();

typedef struct {
    WCRandBuffer_t RandBuffer;
    WCHash_t       Hash;
    WCHMAC_t       HMAC;
    WCAESEncrypt_t AESEncrypt;
    WCAESDecrypt_t AESDecrypt;
    WCRSAGenKey_t  RSAGenKey;
    WCRSAPubKey_t  RSAPubKey;
    WCRSASign_t    RSASign;
    WCRSAVerify_t  RSAVerify;
    WCRSAEncrypt_t RSAEncrypt;
    WCRSADecrypt_t RSADecrypt;
    WCFreeDLL_t    FreeDLL;

    WCClean_t     Clean;
    WCUninstall_t Uninstall;
} WinCrypto_M;

WinCrypto_M* InitWinCrypto(Context* context);

#endif // WIN_CRYPTO_H
