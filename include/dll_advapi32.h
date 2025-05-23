#ifndef DLL_ADVAPI32_H
#define DLL_ADVAPI32_H

#include "c_types.h"
#include "win_types.h"

typedef HANDLE HKEY;
typedef HANDLE HCRYPTPROV;
typedef HANDLE HCRYPTKEY;
typedef HANDLE HCRYPTHASH;

typedef DWORD LSTATUS;
typedef DWORD REGSAM;
typedef DWORD ALG_ID;

#define PROV_RSA_FULL      1
#define PROV_RSA_SIG       2
#define PROV_DSS           3
#define PROV_FORTEZZA      4
#define PROV_MS_EXCHANGE   5
#define PROV_SSL           6
#define PROV_RSA_SCHANNEL  12
#define PROV_DSS_DH        13
#define PROV_EC_ECDSA_SIG  14
#define PROV_EC_ECNRA_SIG  15
#define PROV_EC_ECDSA_FULL 16
#define PROV_EC_ECNRA_FULL 17
#define PROV_DH_SCHANNEL   18
#define PROV_SPYRUS_LYNKS  20
#define PROV_RNG           21
#define PROV_INTEL_SEC     22
#define PROV_REPLACE_OWF   23
#define PROV_RSA_AES       24

#define CRYPT_VERIFYCONTEXT  0xF0000000
#define CRYPT_NEWKEYSET      0x00000008
#define CRYPT_DELETEKEYSET   0x00000010
#define CRYPT_MACHINE_KEYSET 0x00000020
#define CRYPT_SILENT         0x00000040

#define CRYPT_EXPORTABLE     0x00000001
#define CRYPT_USER_PROTECTED 0x00000002
#define CRYPT_CREATE_SALT    0x00000004
#define CRYPT_UPDATE_KEY     0x00000008
#define CRYPT_NO_SALT        0x00000010
#define CRYPT_PREGEN         0x00000040
#define CRYPT_IPSEC_HMAC_KEY 0x00000100
#define CRYPT_SERVER         0x00000400
#define CRYPT_ARCHIVABLE     0x00004000

// CALG_SHA_256/384/512 is not supported until Windows XP SP3
#define CALG_RC2      0x00006602
#define CALG_RC4      0x00006801
#define CALG_MD4      0x00008002
#define CALG_MD5      0x00008003
#define CALG_SHA1     0x00008004
#define CALG_SHA_256  0x0000800C
#define CALG_SHA_384  0x0000800D
#define CALG_SHA_512  0x0000800E
#define CALG_HMAC     0x00008009
#define CALG_AES_128  0x0000660E
#define CALG_AES_192  0x0000660F
#define CALG_AES_256  0x00006610
#define CALG_RSA_SIGN 0x00002400
#define CALG_RSA_KEYX 0x0000A400

#define HP_ALGID     0x0001
#define HP_HASHVAL   0x0002
#define HP_HASHSIZE  0x0004
#define HP_HMAC_INFO 0x0005

#define SIMPLEBLOB           0x01
#define PUBLICKEYBLOB        0x06
#define PRIVATEKEYBLOB       0x07
#define PLAINTEXTKEYBLOB     0x08
#define OPAQUEKEYBLOB        0x09
#define PUBLICKEYBLOBEX      0x0A
#define SYMMETRICWRAPKEYBLOB 0x0B

#define CUR_BLOB_VERSION 2

#define KP_IV          1
#define KP_SALT        2
#define KP_PADDING     3
#define KP_MODE        4
#define KP_MODE_BITS   5
#define KP_PERMISSIONS 6
#define KP_ALGID       7
#define KP_BLOCKLEN    8
#define KP_KEYLEN      9

#define CRYPT_MODE_CBC 1
#define CRYPT_MODE_ECB 2
#define CRYPT_MODE_OFB 3
#define CRYPT_MODE_CFB 4

#define PKCS5_PADDING  1
#define RANDOM_PADDING 2
#define ZERO_PADDING   3

#define AT_KEYEXCHANGE 1
#define AT_SIGNATURE   2

#define MAGIC_RSA1 0x31415352
#define MAGIC_RSA2 0x32415352

typedef struct {
    BYTE   bType;
    BYTE   bVersion;
    WORD   reserved;
    ALG_ID aiKeyAlg;
} BLOBHEADER, PUBLICKEYSTRUC;

typedef struct {
    BLOBHEADER header;
    DWORD      dwKeySize;
} KEYHEADER;

typedef struct {
    DWORD magic;
    DWORD bitlen;
    DWORD pubexp;
} RSAPUBKEY;

typedef struct {
    BLOBHEADER header;
    RSAPUBKEY  rsaPubKey;
} RSAPUBKEYHEADER;

typedef struct {
    ALG_ID HashAlgid;
    BYTE*  pbInnerString;
    DWORD  cbInnerString;
    BYTE*  pbOuterString;
    DWORD  cbOuterString;
} HMAC_INFO;

typedef LSTATUS (*RegCreateKeyA_t)
(
    HKEY hKey, LPCSTR lpSubKey, HKEY* phkResult
);

typedef LSTATUS (*RegCreateKeyW_t)
(
    HKEY hKey, LPCWSTR lpSubKey, HKEY* phkResult
);

typedef LSTATUS (*RegCreateKeyExA_t)
(
    HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, POINTER lpSecurityAttributes,
    HKEY* phkResult, DWORD* lpdwDisposition
);

typedef LSTATUS (*RegCreateKeyExW_t)
(
    HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, POINTER lpSecurityAttributes,
    HKEY* phkResult, DWORD* lpdwDisposition
);

typedef LSTATUS (*RegOpenKeyA_t)
(
    HKEY hKey, LPCSTR lpSubKey, HKEY* phkResult
);

typedef LSTATUS (*RegOpenKeyW_t)
(
    HKEY hKey, LPCWSTR lpSubKey, HKEY* phkResult
);

typedef LSTATUS (*RegOpenKeyExA_t)
(
    HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, 
    REGSAM samDesired, HKEY* phkResult
);

typedef LSTATUS (*RegOpenKeyExW_t)
(
    HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions,
    REGSAM samDesired, HKEY* phkResult
);

typedef LSTATUS (*RegCloseKey_t)
(
    HKEY hKey
);

typedef BOOL (*CryptAcquireContextA_t)
(
    HCRYPTPROV* phProv, LPCSTR szContainer, LPCSTR szProvider,
    DWORD dwProvType, DWORD dwFlags
);

typedef BOOL(*CryptReleaseContext_t)
(
    HCRYPTPROV hProv, DWORD dwFlags
);

typedef BOOL (*CryptGenRandom_t)
(
    HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer
);

typedef BOOL (*CryptGenKey_t)
(
    HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey
);

typedef BOOL (*CryptExportKey_t)
(
    HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType,
    DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen
);

typedef BOOL (*CryptCreateHash_t)
(
    HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey,
    DWORD dwFlags, HCRYPTHASH* phHash
);

typedef BOOL (*CryptSetHashParam_t)
(
   HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData, DWORD dwFlags
);

typedef BOOL (*CryptGetHashParam_t)
(
    HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData,
    DWORD* pdwDataLen, DWORD dwFlags
);

typedef BOOL (*CryptHashData_t)
(
    HCRYPTHASH hHash, BYTE* pbData, DWORD dwDataLen, DWORD dwFlags
);

typedef BOOL (*CryptDestroyHash_t)
(
    HCRYPTHASH hHash
);

typedef BOOL (*CryptImportKey_t)
(
    HCRYPTPROV hProv, BYTE* pbData, DWORD dwDataLen,
    HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey
);

typedef BOOL (*CryptSetKeyParam_t)
(
    HCRYPTKEY hKey, DWORD dwParam, BYTE* pbData, DWORD dwFlags
);

typedef BOOL (*CryptEncrypt_t)
(
    HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags,
    BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen
);

typedef BOOL (*CryptDecrypt_t)
(
    HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags,
    BYTE* pbData, DWORD* pdwDataLen
);

typedef BOOL (*CryptDestroyKey_t)
(
    HCRYPTKEY hKey
);

typedef BOOL (*CryptSignHashA_t)
(
    HCRYPTHASH hHash, DWORD dwKeySpec, LPCSTR szDescription,
    DWORD dwFlags, BYTE* pbSignature, DWORD* pdwSigLen
);

typedef BOOL (*CryptVerifySignatureA_t)
(
    HCRYPTHASH hHash, BYTE* pbSignature, DWORD dwSigLen,
    HCRYPTKEY hPubKey, LPCSTR szDescription, DWORD dwFlags
);

#endif // DLL_ADVAPI32_H
