#include <stdio.h>
#include "c_types.h"
#include "win_types.h"
#include "dll_advapi32.h"
#include "lib_memory.h"
#include "errno.h"
#include "runtime.h"
#include "win_crypto.h"
#include "test.h"

static bool TestWinCrypto_RandBuffer();
static bool TestWinCrypto_Hash();
static bool TestWinCrypto_HMAC();
static bool TestWinCrypto_AESEncrypt();
static bool TestWinCrypto_AESDecrypt();
static bool TestWinCrypto_RSAGenKey();
static bool TestWinCrypto_RSAPubKey();
static bool TestWinCrypto_RSASign();
static bool TestWinCrypto_RSAVerify();
static bool TestWinCrypto_RSAEncrypt();
static bool TestWinCrypto_RSADecrypt();
static bool TestWinCrypto_Golang();

static void printHexBytes(databuf* data);

bool TestRuntime_WinCrypto()
{
    test_t tests[] = {
        { TestWinCrypto_RandBuffer },
        { TestWinCrypto_Hash       },
        { TestWinCrypto_HMAC       },
        { TestWinCrypto_AESEncrypt },
        { TestWinCrypto_AESDecrypt },
        { TestWinCrypto_RSAGenKey  },
        { TestWinCrypto_RSAPubKey  },
        { TestWinCrypto_RSASign    },
        { TestWinCrypto_RSAVerify  },
        { TestWinCrypto_RSAEncrypt },
        { TestWinCrypto_RSADecrypt },
        { TestWinCrypto_Golang     },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        printf_s("--------------------------------\n");
        if (!tests[i]())
        {
            return false;
        }
        printf_s("--------------------------------\n\n");
    }
    return true;
}

static bool TestWinCrypto_RandBuffer()
{
    byte buf[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    databuf data = {
        .buf = buf,
        .len = sizeof(buf),
    };
    errno err = runtime->WinCrypto.RandBuffer(&data);
    if (err != NO_ERROR)
    {
        printf_s("failed to generate random data: 0x%X\n", err);
        return false;
    }

    printHexBytes(&data);
    if (buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[15] == 0)
    {
        printf_s("get incorrect random data\n");
        return false;
    }

    printf_s("test RandBuffer passed\n");
    return true;
}

static bool TestWinCrypto_Hash()
{
    byte buf[] = { 1, 2, 3, 4 };
    databuf data = {
        .buf = buf,
        .len = sizeof(buf),
    };
    databuf hash;
    errno err = runtime->WinCrypto.Hash(CALG_SHA1, &data, &hash);
    if (err != NO_ERROR)
    {
        printf_s("failed to calculate SHA1 hash: 0x%X\n", err);
        return false;
    }

    printHexBytes(&hash);
    byte expected[] = {
        0x12, 0xDA, 0xDA, 0x1F, 0xFF, 0x4D, 0x47, 0x87,
        0xAD, 0xE3, 0x33, 0x31, 0x47, 0x20, 0x2C, 0x3B,
        0x44, 0x3E, 0x37, 0x6F,
    };
    if (hash.len != 20)
    {
        printf_s("invalid SHA1 hash size\n");
        return false;
    }
    if (!mem_equal(expected, hash.buf, hash.len))
    {
        printf_s("get incorrect SHA1 hash\n");
        return false;
    }

    printf_s("test Hash passed\n");
    return true;
}

static bool TestWinCrypto_HMAC()
{
    byte buf[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    databuf data = {
        .buf = buf,
        .len = sizeof(buf),
    };
    databuf key = {
        .buf = buf,
        .len = sizeof(buf),
    };
    databuf hash;
    errno err = runtime->WinCrypto.HMAC(CALG_SHA_256, &data, &key, &hash);
    if (err != NO_ERROR)
    {
        printf_s("failed to calculate HMAC-SHA256 hash: 0x%X\n", err);
        return false;
    }

    printHexBytes(&hash);
    byte expected[] = {
        0xD1, 0x29, 0x0E, 0xB2, 0x59, 0x65, 0x23, 0x3C,
        0x91, 0x3C, 0x3D, 0xEB, 0x22, 0x2E, 0x79, 0x86,
        0x68, 0x4C, 0xE6, 0xB0, 0x8D, 0x93, 0x21, 0xAB, 
        0xC1, 0x11, 0xD8, 0x70, 0x68, 0xE3, 0xD7, 0xF8,
    };
    if (hash.len != 32)
    {
        printf_s("invalid HMAC-SHA256 hash size\n");
        return false;
    }
    if (!mem_equal(expected, hash.buf, hash.len))
    {
        printf_s("get incorrect HMAC-SHA256 hash\n");
        return false;
    }

    printf_s("test HMAC passed\n");
    return true;
}

static bool TestWinCrypto_AESEncrypt()
{
    byte testdata[] = { 
        1, 2, 3, 4 
    };
    databuf data = {
        .buf = testdata,
        .len = sizeof(testdata),
    };
    byte testKey[] = {
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
    };
    databuf key = {
        .buf = testKey,
        .len = sizeof(testKey),
    };
    databuf output;
    errno err = runtime->WinCrypto.AESEncrypt(&data, &key, &output);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data with AES: 0x%X\n", err);
        return false;
    }

    printHexBytes(&output);
    if (output.len != WC_AES_IV_SIZE + WC_AES_BLOCK_SIZE)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }

    runtime->Memory.Free(output.buf);

    printf_s("test AESEncrypt passed\n");
    return true;
};

static bool TestWinCrypto_AESDecrypt()
{
    byte testdata1[] = {
        1, 2, 3, 4 
    };
    databuf data1 = {
        .buf = testdata1,
        .len = sizeof(testdata1),
    };
    byte testKey[] = {
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
    };
    databuf key = {
        .buf = testKey,
        .len = sizeof(testKey),
    };
    databuf cipherData;
    errno err = runtime->WinCrypto.AESEncrypt(&data1, &key, &cipherData);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data with AES: 0x%X\n", err);
        return false;
    }
    if (cipherData.len != WC_AES_IV_SIZE + WC_AES_BLOCK_SIZE)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }
    databuf plainData;
    err = runtime->WinCrypto.AESDecrypt(&cipherData, &key, &plainData);
    if (err != NO_ERROR)
    {
        printf_s("failed to decrypt data: 0x%X\n", err);
        return false;
    }

    printHexBytes(&plainData);
    if (plainData.len != sizeof(testdata1))
    {
        printf_s("invalid plain data length\n");
        return false;
    }
    byte expected1[] = { 1, 2, 3, 4 };
    if (!mem_equal(expected1, plainData.buf, sizeof(expected1)))
    {
        printf_s("get incorrect plain data\n");
        return false;
    }
    if (!mem_equal(expected1, testdata1, sizeof(expected1)))
    {
        printf_s("the original data is changed\n");
        return false;
    }

    runtime->Memory.Free(cipherData.buf);
    runtime->Memory.Free(plainData.buf);

    byte testdata2[] = { 
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    databuf data2 = {
        .buf = testdata2,
        .len = sizeof(testdata2),
    };
    err = runtime->WinCrypto.AESEncrypt(&data2, &key, &cipherData);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data with AES: 0x%X\n", err);
        return false;
    }
    if (cipherData.len != WC_AES_IV_SIZE + WC_AES_BLOCK_SIZE * 2)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }
    err = runtime->WinCrypto.AESDecrypt(&cipherData, &key, &plainData);
    if (err != NO_ERROR)
    {
        printf_s("failed to decrypt data: 0x%X\n", err);
        return false;
    }

    printHexBytes(&plainData);
    if (plainData.len != sizeof(testdata2))
    {
        printf_s("invalid plain data length\n");
        return false;
    }
    byte expected2[] = { 
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    if (!mem_equal(expected2, plainData.buf, sizeof(expected2)))
    {
        printf_s("get incorrect plain data\n");
        return false;
    }
    if (!mem_equal(expected2, testdata2, sizeof(expected2)))
    {
        printf_s("original data is changed\n");
        return false;
    }

    runtime->Memory.Free(cipherData.buf);
    runtime->Memory.Free(plainData.buf);

    printf_s("test AESDecrypt passed\n");
    return true;
};

static bool TestWinCrypto_RSAGenKey()
{
    databuf key;
    errno err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_SIGN, 4096, &key);
    if (err != NO_ERROR)
    {
        printf_s("failed to test generate RSA key pair: 0x%X\n", err);
        return false;
    }
    printHexBytes(&key);
    if (key.len != 2324)
    {
        printf_s("incorrect RSA key pair data length: %zu\n", key.len);
        return false;
    }
    byte header1[] = { 
        0x07, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00,
        0x52, 0x53, 0x41, 0x32, 0x00, 0x10, 0x00, 0x00,
    };
    if (!mem_equal(header1, key.buf, sizeof(header1)))
    {
        printf_s("invalid RSA key pair data\n");
        return false;
    }
    runtime->Memory.Free(key.buf);

    err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_KEYX, 2048, &key);
    if (err != NO_ERROR)
    {
        printf_s("failed to test generate RSA key pair: 0x%X\n", err);
        return false;
    }
    printHexBytes(&key);
    if (key.len != 1172)
    {
        printf_s("incorrect RSA key pair data length: %zu\n", key.len);
        return false;
    }
    byte header2[] = {
        0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00,
        0x52, 0x53, 0x41, 0x32, 0x00, 0x08, 0x00, 0x00,
    };
    if (!mem_equal(header2, key.buf, sizeof(header2)))
    {
        printf_s("invalid RSA key pair data\n");
        return false;
    }
    runtime->Memory.Free(key.buf);

    printf_s("test RSAGenKey passed\n");
    return true;
}

static bool TestWinCrypto_RSAPubKey()
{
    databuf priKey;
    errno err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_SIGN, 2048, &priKey);
    if (err != NO_ERROR)
    {
        printf_s("failed to generate RSA private key: 0x%X\n", err);
        return false;
    }

    databuf pubKey;
    err = runtime->WinCrypto.RSAPubKey(&priKey, &pubKey);
    if (err != NO_ERROR)
    {
        printf_s("failed to export RSA public key: 0x%X\n", err);
        return false;
    }

    printHexBytes(&pubKey);
    if (pubKey.len != sizeof(RSAPUBKEYHEADER) + 256)
    {
        printf_s("incorrect RSA public key length: %zu\n", pubKey.len);
        return false;
    }

    runtime->Memory.Free(priKey.buf);
    runtime->Memory.Free(pubKey.buf);

    printf_s("test RSAPubKey passed\n");
    return true;
}

static bool TestWinCrypto_RSASign()
{
    byte testdata[] = { 
        1, 2, 3, 4, 5, 6, 7, 8, 
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    databuf data = {
        .buf = &testdata[0],
        .len = sizeof(testdata),
    };
    databuf key;
    errno err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_SIGN, 2048, &key);
    if (err != NO_ERROR)
    {
        printf_s("failed to generate RSA key pair: 0x%X\n", err);
        return false;
    }

    databuf signature;
    err = runtime->WinCrypto.RSASign(CALG_SHA1, &data, &key, &signature);
    if (err != NO_ERROR)
    {
        printf_s("failed to sign data with RSA: 0x%X\n", err);
        return false;
    }

    printHexBytes(&signature);
    if (signature.len != 256)
    {
        printf_s("invalid RSA signature length\n");
        return false;
    }

    runtime->Memory.Free(key.buf);
    runtime->Memory.Free(signature.buf);

    printf_s("test RSASign passed\n");
    return true;
}

static bool TestWinCrypto_RSAVerify()
{
    byte testdata[] = { 
        1, 2, 3, 4, 5, 6, 7, 8, 
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    databuf data = {
        .buf = &testdata[0],
        .len = sizeof(testdata),
    };
    databuf priKey;
    errno err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_SIGN, 2048, &priKey);
    if (err != NO_ERROR)
    {
        printf_s("failed to generate RSA key pair: 0x%X\n", err);
        return false;
    }
    databuf signature;
    err = runtime->WinCrypto.RSASign(CALG_SHA_256, &data, &priKey, &signature);
    if (err != NO_ERROR)
    {
        printf_s("failed to sign data with RSA: 0x%X\n", err);
        return false;
    }

    databuf pubKey;
    err = runtime->WinCrypto.RSAPubKey(&priKey, &pubKey);
    if (err != NO_ERROR)
    {
        printf_s("failed to export RSA public key: 0x%X\n", err);
        return false;
    }
    err = runtime->WinCrypto.RSAVerify(CALG_SHA_256, &data, &pubKey, &signature);
    if (err != NO_ERROR)
    {
        printf_s("failed to verify data with RSA: 0x%X\n", err);
        return false;
    }

    // destroy signature
    *(byte*)(signature.buf) += 1;
    err = runtime->WinCrypto.RSAVerify(CALG_SHA_256, &data, &pubKey, &signature);
    if (err == NO_ERROR)
    {
        printf_s("unexpected RSA verify data result\n");
        return false;
    }

    runtime->Memory.Free(priKey.buf);
    runtime->Memory.Free(pubKey.buf);
    runtime->Memory.Free(signature.buf);

    printf_s("test RSAVerify passed\n");
    return true;
}

static bool TestWinCrypto_RSAEncrypt()
{
    byte testdata[] = { 
        1, 2, 3, 4 
    };
    databuf data = {
        .buf = testdata,
        .len = sizeof(testdata),
    };
    databuf priKey;
    errno err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_KEYX, 2048, &priKey);
    if (err != NO_ERROR)
    {
        printf_s("failed to generate RSA key pair: 0x%X\n", err);
        return false;
    }
    databuf pubKey;
    err = runtime->WinCrypto.RSAPubKey(&priKey, &pubKey);
    if (err != NO_ERROR)
    {
        printf_s("failed to export RSA public key: 0x%X\n", err);
        return false;
    }

    databuf output;
    err = runtime->WinCrypto.RSAEncrypt(&data, &pubKey, &output);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data with RSA: 0x%X\n", err);
        return false;
    }

    printHexBytes(&output);
    if (output.len != 256)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }

    runtime->Memory.Free(priKey.buf);
    runtime->Memory.Free(pubKey.buf);
    runtime->Memory.Free(output.buf);

    printf_s("test RSAEncrypt passed\n");
    return true;
}

static bool TestWinCrypto_RSADecrypt()
{
    byte testdata[] = { 
        1, 2, 3, 4 
    };
    databuf data = {
        .buf = testdata,
        .len = sizeof(testdata),
    };
    databuf priKey;
    errno err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_KEYX, 2048, &priKey);
    if (err != NO_ERROR)
    {
        printf_s("failed to generate RSA key pair: 0x%X\n", err);
        return false;
    }
    databuf pubKey;
    err = runtime->WinCrypto.RSAPubKey(&priKey, &pubKey);
    if (err != NO_ERROR)
    {
        printf_s("failed to export RSA public key: 0x%X\n", err);
        return false;
    }

    databuf cipherData;
    err = runtime->WinCrypto.RSAEncrypt(&data, &pubKey, &cipherData);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data with RSA: 0x%X\n", err);
        return false;
    }
    databuf plainData;
    err = runtime->WinCrypto.RSADecrypt(&cipherData, &priKey, &plainData);
    if (err != NO_ERROR)
    {
        printf_s("failed to decrypt data with RSA: 0x%X\n", err);
        return false;
    }

    printHexBytes(&plainData);
    if (plainData.len != sizeof(testdata))
    {
        printf_s("invalid plain data length\n");
        return false;
    }
    byte expected1[] = { 1, 2, 3, 4 };
    if (!mem_equal(expected1, plainData.buf, sizeof(expected1)))
    {
        printf_s("get incorrect plain data\n");
        return false;
    }
    if (!mem_equal(expected1, testdata, sizeof(expected1)))
    {
        printf_s("original data is changed\n");
        return false;
    }

    runtime->Memory.Free(priKey.buf);
    runtime->Memory.Free(pubKey.buf);
    runtime->Memory.Free(cipherData.buf);
    runtime->Memory.Free(plainData.buf);

    printf_s("test RSADecrypt passed\n");
    return true;
}

static bool TestWinCrypto_Golang()
{
    // ================AES Encrypt================
    byte testdata1[] = {
        1, 2, 3, 4
    };
    byte cipherData[] = {
        0xA6, 0x06, 0xE1, 0xCB, 0x32, 0x0E, 0xED, 0x88, 
        0x50, 0x35, 0xEF, 0xFA, 0xEE, 0x9C, 0xA2, 0xDF, 
        0x3F, 0xC5, 0x4B, 0x76, 0x84, 0xB4, 0xB8, 0xAB, 
        0x3F, 0xD1, 0x70, 0x9F, 0x05, 0x76, 0x9C, 0x9E,
    };
    databuf data1 = {
        .buf = cipherData,
        .len = sizeof(cipherData),
    };
    byte testKey[] = {
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
    };
    databuf aesKey = {
        .buf = testKey,
        .len = sizeof(testKey),
    };
    databuf plainData;
    errno err = runtime->WinCrypto.AESDecrypt(&data1, &aesKey, &plainData);
    if (err != NO_ERROR)
    {
        printf_s("failed to decrypt data: 0x%X\n", err);
        return false;
    }
    printHexBytes(&plainData);
    if (plainData.len != sizeof(testdata1))
    {
        printf_s("invalid plain data length\n");
        return false;
    }
    byte expected1[] = { 1, 2, 3, 4 };
    if (!mem_equal(expected1, plainData.buf, sizeof(expected1)))
    {
        printf_s("get incorrect plain data\n");
        return false;
    }
    if (!mem_equal(expected1, testdata1, sizeof(expected1)))
    {
        printf_s("the original data is changed\n");
        return false;
    }
    runtime->Memory.Free(plainData.buf);

    // ================RSA Sign================
    databuf priKeySign;
    err = runtime->WinFile.ReadFileA("testdata/PrivateKey.sign", &priKeySign);
    if (err != NO_ERROR)
    {
        printf_s("failed to read RSA private key: 0x%X\n", err);
        return false;
    }
    databuf pubKeySign;
    err = runtime->WinCrypto.RSAPubKey(&priKeySign, &pubKeySign);
    if (err != NO_ERROR)
    {
        printf_s("failed to export RSA public key: 0x%X\n", err);
        return false;
    }

    databuf data2 = {
        .buf = testdata1,
        .len = sizeof(testdata1),
    };
    byte testSign1[] = {
        0xF4, 0x19, 0x52, 0x24, 0xB2, 0x53, 0x7D, 0x9B,
        0xE9, 0xAD, 0x8F, 0x64, 0x6F, 0x42, 0xFC, 0x12,
        0xA2, 0x87, 0x29, 0x24, 0x5B, 0xB4, 0x7F, 0x63,
        0xB1, 0xED, 0x88, 0x33, 0xA7, 0x46, 0x2E, 0x6B,
        0xDF, 0x79, 0x51, 0xC4, 0x79, 0xD1, 0x0C, 0xA4,
        0x1A, 0x43, 0x81, 0x72, 0x3B, 0xF8, 0x01, 0x64,
        0x0D, 0x43, 0x7E, 0x36, 0x68, 0x06, 0x8C, 0xCA,
        0x7A, 0x06, 0xA8, 0xDA, 0xEE, 0x6B, 0xD3, 0x9C,
        0xDC, 0x1A, 0x71, 0x8D, 0x4C, 0x90, 0xE7, 0x0D,
        0x35, 0x5E, 0x3B, 0x7D, 0x39, 0x04, 0x6D, 0x42,
        0x99, 0xFD, 0x3E, 0xE2, 0xE5, 0x7B, 0x70, 0x84,
        0x9A, 0x2D, 0xD3, 0x07, 0x23, 0x01, 0x08, 0x79,
        0x9F, 0x54, 0x84, 0xEE, 0xC4, 0x85, 0x30, 0x4F,
        0x3F, 0x2C, 0xBD, 0x85, 0xC4, 0x84, 0xF0, 0x81,
        0xD0, 0x2A, 0xF2, 0x6F, 0x99, 0xB4, 0xE1, 0x3B,
        0x08, 0x45, 0xE4, 0xD1, 0xA1, 0x51, 0x9F, 0x2C,
        0x81, 0x49, 0xE1, 0xDF, 0x59, 0x51, 0x6D, 0xB7,
        0x11, 0x4C, 0xDD, 0x9C, 0x27, 0xE0, 0x4A, 0x09,
        0x35, 0xCD, 0xDF, 0x8C, 0xB7, 0x74, 0xF6, 0x91,
        0x67, 0xD8, 0x7B, 0x34, 0x0A, 0x6E, 0x7F, 0xD9,
        0x99, 0x3A, 0xD7, 0xA4, 0xEE, 0xBA, 0xA4, 0x5A,
        0xBE, 0x36, 0xEB, 0x89, 0x5F, 0x00, 0x85, 0xF8,
        0x56, 0xE0, 0x88, 0x8A, 0x5F, 0x11, 0xFE, 0xBD,
        0x49, 0x2F, 0x31, 0x3C, 0xED, 0xDE, 0xAD, 0x1A,
        0x2F, 0x85, 0x02, 0xA0, 0xEC, 0x8A, 0xB3, 0x20,
        0x5B, 0xE8, 0x46, 0x25, 0x3A, 0x9D, 0x5D, 0x0C,
        0x3F, 0x26, 0x9D, 0x7A, 0x08, 0x95, 0x28, 0x1D,
        0xC7, 0x76, 0x97, 0xCD, 0x11, 0x09, 0xE1, 0xC3,
        0xFB, 0x28, 0x08, 0x37, 0xFA, 0x77, 0x56, 0xC4,
        0x71, 0x35, 0x99, 0xCB, 0x8F, 0x60, 0xDE, 0x5B,
        0x22, 0xE1, 0x86, 0x90, 0x80, 0xDD, 0x51, 0x94,
        0x08, 0x1B, 0x2C, 0xAD, 0x6B, 0xA6, 0xA9, 0x87,
    };
    databuf sign1 = {
        .buf = testSign1,
        .len = sizeof(testSign1),
    };
    err = runtime->WinCrypto.RSAVerify(CALG_SHA_256, &data2, &pubKeySign, &sign1);
    if (err != NO_ERROR)
    {
        printf_s("failed to verify message: 0x%X\n", err);
        return false;
    }

    databuf sign2;
    err = runtime->WinCrypto.RSASign(CALG_SHA_256, &data2, &priKeySign, &sign2);
    if (err != NO_ERROR)
    {
        printf_s("failed to verify message: 0x%X\n", err);
        return false;
    }
    if (!mem_equal(sign1.buf, sign2.buf, sign2.len))
    {
        printf_s("invalid RSA signature\n");
        return false;
    }

    runtime->Memory.Free(sign2.buf);
    runtime->Memory.Free(pubKeySign.buf);
    runtime->Memory.Free(priKeySign.buf);

    // ================RSA Encrypt================
    databuf priKeyKeyx;
    err = runtime->WinFile.ReadFileA("testdata/PrivateKey.keyx", &priKeyKeyx);
    if (err != NO_ERROR)
    {
        printf_s("failed to read RSA private key: 0x%X\n", err);
        return false;
    }
    databuf pubKeyKeyx;
    err = runtime->WinCrypto.RSAPubKey(&priKeyKeyx, &pubKeyKeyx);
    if (err != NO_ERROR)
    {
        printf_s("failed to export RSA public key: 0x%X\n", err);
        return false;
    }

    byte cipherData2[] = {
        0xD9, 0xE6, 0xEE, 0xD1, 0x3B, 0xEC, 0x28, 0x1F,
        0x1C, 0x13, 0xCD, 0x7D, 0x3A, 0x15, 0x79, 0x8F,
        0x44, 0xFB, 0xE8, 0x0B, 0x55, 0xAC, 0x20, 0x3E,
        0xB5, 0xA8, 0x7F, 0x68, 0xA8, 0xFD, 0x67, 0x16,
        0xD6, 0x73, 0xC7, 0x23, 0xF5, 0xB4, 0x4D, 0x68,
        0x56, 0xD2, 0x96, 0xCD, 0xA4, 0xEC, 0xC4, 0x5C,
        0x7B, 0xF2, 0x0F, 0xF5, 0x4A, 0x92, 0x3C, 0x50,
        0xFC, 0x5C, 0x81, 0x98, 0x77, 0x7D, 0x32, 0xCE,
        0xFF, 0xE9, 0x90, 0xF3, 0xF6, 0x8C, 0xFE, 0x44,
        0xF5, 0xE5, 0xB0, 0xE6, 0x54, 0x0E, 0xF2, 0xC1,
        0xA3, 0xE7, 0x5F, 0x49, 0xD8, 0xB3, 0x66, 0x05,
        0xCF, 0x6B, 0xD7, 0x5C, 0x51, 0x3F, 0x5F, 0x69,
        0x4D, 0x04, 0x61, 0xDD, 0x64, 0xB9, 0x23, 0x61,
        0x04, 0x6B, 0x86, 0x9F, 0xA7, 0x31, 0xBD, 0x15,
        0x5A, 0xD2, 0xA1, 0xFF, 0x3A, 0x9D, 0xF6, 0x7C,
        0xD8, 0xA0, 0x70, 0x86, 0x49, 0x88, 0xFE, 0xCB,
        0x51, 0x4E, 0x29, 0xF1, 0x8B, 0x36, 0x60, 0x77,
        0xF8, 0xF9, 0x29, 0x7A, 0x2F, 0xEE, 0x0B, 0xE2,
        0x00, 0x35, 0x2F, 0x52, 0x15, 0x3F, 0x60, 0x98,
        0x04, 0x56, 0x94, 0x15, 0x9E, 0xB0, 0xC7, 0x15,
        0x45, 0x46, 0xC0, 0x21, 0xC2, 0xEA, 0x4D, 0x2C,
        0x6B, 0x0E, 0xF4, 0x61, 0x0A, 0x62, 0x3B, 0x8F,
        0x11, 0xDC, 0x0F, 0x46, 0xB0, 0x5E, 0xE9, 0xD5,
        0x91, 0xC4, 0x31, 0xBC, 0x0C, 0xEE, 0xB7, 0xD9,
        0x20, 0x01, 0x1D, 0xB2, 0xCF, 0xDE, 0x46, 0xE0,
        0xEB, 0xBA, 0x14, 0xBB, 0xFB, 0x86, 0x71, 0x5D,
        0x67, 0xBF, 0x89, 0x26, 0x70, 0xE7, 0xF9, 0x48,
        0x1D, 0x4D, 0x4A, 0xE9, 0xA3, 0x2E, 0x07, 0x8F,
        0x14, 0x14, 0x00, 0xC3, 0xB7, 0x0A, 0x42, 0xE7,
        0xB1, 0x79, 0xF8, 0xAA, 0x58, 0x17, 0xA7, 0xED,
        0xDB, 0xF2, 0x61, 0x9F, 0x47, 0x80, 0xEF, 0xDF,
        0x1E, 0x91, 0x85, 0xE8, 0x23, 0x61, 0xBD, 0x17,
    };
    databuf data3 = {
        .buf = cipherData2,
        .len = sizeof(cipherData2),
    };
    databuf plainData2;
    err = runtime->WinCrypto.RSADecrypt(&data3, &priKeyKeyx, &plainData2);
    if (err != NO_ERROR)
    {
        printf_s("failed to decrypt data: 0x%X\n", err);
        return false;
    }
    printHexBytes(&plainData2);
    if (plainData2.len != sizeof(testdata1))
    {
        printf_s("invalid plain data length\n");
        return false;
    }
    byte expected2[] = { 1, 2, 3, 4 };
    if (!mem_equal(expected2, plainData2.buf, sizeof(expected2)))
    {
        printf_s("get incorrect plain data\n");
        return false;
    }
    if (!mem_equal(expected2, testdata1, sizeof(expected2)))
    {
        printf_s("the original data is changed\n");
        return false;
    }

    databuf data4 = {
        .buf = testdata1,
        .len = sizeof(testdata1),
    };
    databuf cipherData3;
    err = runtime->WinCrypto.RSAEncrypt(&data4, &pubKeyKeyx, &cipherData3);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data: 0x%X\n", err);
        return false;
    }
    printHexBytes(&cipherData3);

    runtime->Memory.Free(plainData2.buf);
    runtime->Memory.Free(cipherData3.buf);
    runtime->Memory.Free(pubKeyKeyx.buf);
    runtime->Memory.Free(priKeyKeyx.buf);

    printf_s("test external Golang passed\n");
    return true;
}

static void printHexBytes(databuf* data)
{
    byte* buf = data->buf;
    int counter = 0;
    for (uint i = 0; i < data->len; i++)
    {
        printf_s("%02X ", *buf);

        buf++;
        counter++;
        if (counter >= 16)
        {
            counter = 0;
            printf_s("\n");
        }
    }
    printf_s("\n");
}
