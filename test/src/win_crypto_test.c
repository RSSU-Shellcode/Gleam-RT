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
static bool TestWinCrypto_SHA1();
static bool TestWinCrypto_AESEncrypt();
static bool TestWinCrypto_AESDecrypt();
static bool TestWinCrypto_RSAGenKey();
static bool TestWinCrypto_RSASign();
static bool TestWinCrypto_RSAVerify();
static bool TestWinCrypto_RSAEncrypt();
static bool TestWinCrypto_RSADecrypt();

static void printHexBytes(byte* buf, uint size);

bool TestRuntime_WinCrypto()
{
    test_t tests[] = {
        { TestWinCrypto_RandBuffer },
        { TestWinCrypto_SHA1       },
        { TestWinCrypto_AESEncrypt },
        { TestWinCrypto_AESDecrypt },
        { TestWinCrypto_RSAGenKey  },
        { TestWinCrypto_RSASign    },
        { TestWinCrypto_RSAVerify  },
        { TestWinCrypto_RSAEncrypt },
        { TestWinCrypto_RSADecrypt },
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

    errno err = runtime->WinCrypto.RandBuffer(buf, sizeof(buf));
    if (err != NO_ERROR)
    {
        printf_s("failed to test RandBuffer: 0x%X\n", err);
        return false;
    }

    printHexBytes(buf, sizeof(buf));
    if (buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[15] == 0)
    {
        printf_s("get incorrect random data\n");
        return false;
    }

    printf_s("test RandBuffer passed\n");
    return true;
}

static bool TestWinCrypto_SHA1()
{
    byte buf[] = { 1, 2, 3, 4 };

    byte hash[WC_SHA1_HASH_SIZE];
    errno err = runtime->WinCrypto.SHA1(buf, sizeof(buf), hash);
    if (err != NO_ERROR)
    {
        printf_s("failed to test SHA1: 0x%X\n", err);
        return false;
    }

    printHexBytes(hash, sizeof(hash));
    byte expected[] = {
        0x12, 0xDA, 0xDA, 0x1F, 0xFF, 0x4D, 0x47, 0x87,
        0xAD, 0xE3, 0x33, 0x31, 0x47, 0x20, 0x2C, 0x3B,
        0x44, 0x3E, 0x37, 0x6F,
    };
    if (!mem_equal(expected, hash, WC_SHA1_HASH_SIZE))
    {
        printf_s("get incorrect SHA1 hash\n");
        return false;
    }

    printf_s("test SHA1 passed\n");
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
    byte testkey[] = {
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
    };
    databuf key = {
        .buf = testkey,
        .len = sizeof(testkey),
    };
    databuf out;
    errno err = runtime->WinCrypto.AESEncrypt(&data, &key, &out);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data: 0x%X\n", err);
        return false;
    }

    printHexBytes(out.buf, out.len);
    if (out.len != WC_AES_IV_SIZE + WC_AES_BLOCK_SIZE)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }

    runtime->Memory.Free(out.buf);

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
    byte testkey[] = {
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
    };
    databuf key = {
        .buf = testkey,
        .len = sizeof(testkey),
    };
    databuf cipher;
    errno err = runtime->WinCrypto.AESEncrypt(&data1, &key, &cipher);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data: 0x%X\n", err);
        return false;
    }
    if (cipher.len != WC_AES_IV_SIZE + WC_AES_BLOCK_SIZE)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }
    databuf plain;
    err = runtime->WinCrypto.AESDecrypt(&cipher, &key, &plain);
    if (err != NO_ERROR)
    {
        printf_s("failed to decrypt data: 0x%X\n", err);
        return false;
    }

    printHexBytes(plain.buf, plain.len);
    if (plain.len != sizeof(testdata1))
    {
        printf_s("invalid plain data length\n");
        return false;
    }
    byte expected1[] = { 1, 2, 3, 4 };
    if (!mem_equal(expected1, plain.buf, sizeof(expected1)))
    {
        printf_s("get incorrect plain data\n");
        return false;
    }
    if (!mem_equal(expected1, testdata1, sizeof(expected1)))
    {
        printf_s("original data is changed\n");
        return false;
    }

    runtime->Memory.Free(cipher.buf);
    runtime->Memory.Free(plain.buf);

    byte testdata2[] = { 
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    databuf data2 = {
        .buf = testdata2,
        .len = sizeof(testdata2),
    };
    err = runtime->WinCrypto.AESEncrypt(&data2, &key, &cipher);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data: 0x%X\n", err);
        return false;
    }
    if (cipher.len != WC_AES_IV_SIZE + WC_AES_BLOCK_SIZE * 2)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }
    err = runtime->WinCrypto.AESDecrypt(&cipher, &key, &plain);
    if (err != NO_ERROR)
    {
        printf_s("failed to decrypt data: 0x%X\n", err);
        return false;
    }

    printHexBytes(plain.buf, plain.len);
    if (plain.len != sizeof(testdata2))
    {
        printf_s("invalid plain data length\n");
        return false;
    }
    byte expected2[] = { 
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    if (!mem_equal(expected2, plain.buf, sizeof(expected2)))
    {
        printf_s("get incorrect plain data\n");
        return false;
    }
    if (!mem_equal(expected2, testdata2, sizeof(expected2)))
    {
        printf_s("original data is changed\n");
        return false;
    }

    runtime->Memory.Free(cipher.buf);
    runtime->Memory.Free(plain.buf);

    printf_s("test AESDecrypt passed\n");
    return true;
};

static bool TestWinCrypto_RSAGenKey()
{
    databuf key;
    errno err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_SIGN, 4096, &key);
    if (err != NO_ERROR)
    {
        printf_s("failed to test RSAGenKey: 0x%X\n", err);
        return false;
    }
    printHexBytes(key.buf, key.len);
    if (key.len != 2324)
    {
        printf_s("incorrect output data length: %zu\n", key.len);
        return false;
    }
    byte header1[] = { 
        0x07, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00,
        0x52, 0x53, 0x41, 0x32, 0x00, 0x10, 0x00, 0x00,
    };
    if (!mem_equal(header1, key.buf, sizeof(header1)))
    {
        printf_s("invalid output data\n");
        return false;
    }
    runtime->Memory.Free(key.buf);

    err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_KEYX, 2048, &key);
    if (err != NO_ERROR)
    {
        printf_s("failed to test RSAGenKey: 0x%X\n", err);
        return false;
    }
    printHexBytes(key.buf, key.len);
    if (key.len != 1172)
    {
        printf_s("incorrect output data length: %zu\n", key.len);
        return false;
    }
    byte header2[] = {
        0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00,
        0x52, 0x53, 0x41, 0x32, 0x00, 0x08, 0x00, 0x00,
    };
    if (!mem_equal(header2, key.buf, sizeof(header2)))
    {
        printf_s("invalid output data\n");
        return false;
    }
    runtime->Memory.Free(key.buf);

    printf_s("test RSAGenKey passed\n");
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
        printf_s("failed to RSAGenKey: 0x%X\n", err);
        return false;
    }

    databuf sign;
    err = runtime->WinCrypto.RSASign(&data, &key, &sign);
    if (err != NO_ERROR)
    {
        printf_s("failed to RSASign: 0x%X\n", err);
        return false;
    }

    printHexBytes(sign.buf, sign.len);
    if (sign.len != 256)
    {
        printf_s("invalid signature length\n");
        return false;
    }

    runtime->Memory.Free(key.buf);
    runtime->Memory.Free(sign.buf);

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
        printf_s("failed to RSAGenKey: 0x%X\n", err);
        return false;
    }
    databuf sign;
    err = runtime->WinCrypto.RSASign(&data, &priKey, &sign);
    if (err != NO_ERROR)
    {
        printf_s("failed to RSASign: 0x%X\n", err);
        return false;
    }

    // build public key from private key
    RSAPUBKEYHEADER* pubBuf = (RSAPUBKEYHEADER*)(priKey.buf);
    pubBuf->header.bType = PUBLICKEYBLOB;
    pubBuf->rsaPubKey.magic = MAGIC_RSA1;
    // erase other data about private key
    byte* buf = priKey.buf;
    buf += sizeof(RSAPUBKEYHEADER);
    buf += 2048 / 8; // skip modulus
    uint len = sizeof(RSAPUBKEYHEADER) + 2048 / 8;
    mem_init(buf, priKey.len - len);
    databuf pubKey = {
        .buf = pubBuf,
        .len = len,
    };
    err = runtime->WinCrypto.RSAVerify(&data, &pubKey, &sign);
    if (err != NO_ERROR)
    {
        printf_s("failed to RSAVerify: 0x%X\n", err);
        return false;
    }

    // destroy signature
    *(byte*)(sign.buf) += 1;
    err = runtime->WinCrypto.RSAVerify(&data, &pubKey, &sign);
    if (err == NO_ERROR)
    {
        printf_s("failed to RSAVerify\n");
        return false;
    }

    runtime->Memory.Free(priKey.buf);
    runtime->Memory.Free(sign.buf);

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
    databuf key;
    errno err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_KEYX, 2048, &key);
    if (err != NO_ERROR)
    {
        printf_s("failed to RSAGenKey: 0x%X\n", err);
        return false;
    }
    databuf out;
    err = runtime->WinCrypto.RSAEncrypt(&data, &key, &out);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data: 0x%X\n", err);
        return false;
    }

    printHexBytes(out.buf, out.len);
    if (out.len != 256)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }

    runtime->Memory.Free(key.buf);
    runtime->Memory.Free(out.buf);

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
    databuf key;
    errno err = runtime->WinCrypto.RSAGenKey(WC_RSA_KEY_USAGE_KEYX, 2048, &key);
    if (err != NO_ERROR)
    {
        printf_s("failed to RSAGenKey: 0x%X\n", err);
        return false;
    }
    databuf cipherData;
    err = runtime->WinCrypto.RSAEncrypt(&data, &key, &cipherData);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data: 0x%X\n", err);
        return false;
    }

    databuf plainData;
    err = runtime->WinCrypto.RSADecrypt(&cipherData, &key, &plainData);
    if (err != NO_ERROR)
    {
        printf_s("failed to decrypt data: 0x%X\n", err);
        return false;
    }

    printHexBytes(plainData.buf, plainData.len);
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

    runtime->Memory.Free(key.buf);
    runtime->Memory.Free(cipherData.buf);
    runtime->Memory.Free(plainData.buf);

    printf_s("test RSADecrypt passed\n");
    return true;
}

static void printHexBytes(byte* buf, uint size)
{
    int counter = 0;
    for (uint i = 0; i < size; i++)
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
