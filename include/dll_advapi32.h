#ifndef DLL_ADVAPI32_H
#define DLL_ADVAPI32_H

#include "c_types.h"
#include "win_types.h"

typedef HANDLE HCRYPTPROV;
typedef HANDLE HCRYPTKEY;
typedef HANDLE HCRYPTHASH;

typedef uint ALG_ID;

// CALG_SHA_256 is not supported until Windows XP SP3
#define CALG_SHA1     0x00008004
#define CALG_AES_256  0x00006610
#define CALG_RSA_SIGN 0x00002400
#define CALG_RSA_KEYX 0x0000A400

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
    HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer
);

typedef BOOL (*CryptCreateHash_t)
(
    HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey,
    DWORD dwFlags, HCRYPTHASH *phHash
);

typedef BOOL (*CryptHashData_t)
(
    HCRYPTHASH hHash, BYTE *pbData, DWORD dwDataLen,
    DWORD dwFlags
);

typedef BOOL (*CryptGetHashParam_t)
(
    HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData,
    DWORD *pdwDataLen, DWORD dwFlags
);

typedef BOOL (*CryptDestroyHash_t)
(
    HCRYPTHASH hHash
);

#endif // DLL_ADVAPI32_H
