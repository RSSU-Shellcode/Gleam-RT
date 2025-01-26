#ifndef DLL_ADVAPI32_H
#define DLL_ADVAPI32_H

#include "c_types.h"
#include "win_types.h"

typedef HANDLE HCRYPTPROV;
typedef HANDLE HCRYPTKEY;
typedef HANDLE HCRYPTHASH;

typedef uint ALG_ID;

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

// CALG_SHA_256 is not supported until Windows XP SP3
#define CALG_SHA1     0x00008004
#define CALG_AES_256  0x00006610
#define CALG_RSA_SIGN 0x00002400
#define CALG_RSA_KEYX 0x0000A400

#define HP_ALGID    0x0001
#define HP_HASHVAL  0x0002
#define HP_HASHSIZE 0x0004

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

typedef BOOL (*CryptCreateHash_t)
(
    HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey,
    DWORD dwFlags, HCRYPTHASH* phHash
);

typedef BOOL (*CryptHashData_t)
(
    HCRYPTHASH hHash, BYTE* pbData, DWORD dwDataLen,
    DWORD dwFlags
);

typedef BOOL (*CryptGetHashParam_t)
(
    HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData,
    DWORD* pdwDataLen, DWORD dwFlags
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
    HCRYPTKEY hKey, DWORD dwParam, BYTE *pbData, DWORD dwFlags
);

typedef BOOL (*CryptEncrypt_t)
(
    HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags,
    BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen
);

typedef BOOL (*CryptDecrypt_t)
(
    HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags,
    BYTE *pbData, DWORD *pdwDataLen
);

#endif // DLL_ADVAPI32_H
