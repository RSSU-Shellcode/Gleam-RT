#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "errno.h"
#include "runtime.h"
#include "win_crypto.h"
#include "test.h"

static bool TestWinCrypto_RandBuffer();
static bool TestWinCrypto_GenRSAKey();
static bool TestWinCrypto_SHA1();
static bool TestWinCrypto_AESEncrypt();
static bool TestWinCrypto_AESDecrypt();
static bool TestWinCrypto_RSASign();
static bool TestWinCrypto_RSAVerify();

static void printHexBytes(byte* buf, uint size);

bool TestRuntime_WinCrypto()
{
    test_t tests[] = {
        { TestWinCrypto_RandBuffer },
        { TestWinCrypto_GenRSAKey  },
        { TestWinCrypto_SHA1       },
        { TestWinCrypto_AESEncrypt },
        { TestWinCrypto_AESDecrypt },
        { TestWinCrypto_RSASign    },
        { TestWinCrypto_RSAVerify  },
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

static bool TestWinCrypto_GenRSAKey()
{
    byte* key; uint len;
    errno err = runtime->WinCrypto.GenRSAKey(4096, &key, &len, WC_RSA_KEY_USAGE_SIGN);
    if (err != NO_ERROR)
    {
        printf_s("failed to test GenRSAKey: 0x%X\n", err);
        return false;
    }
    printHexBytes(key, len);
    if (len != 2324)
    {
        printf_s("incorrect output data length: %zu\n", len);
        return false;
    }
    byte header1[] = { 
        0x07, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00,
        0x52, 0x53, 0x41, 0x32, 0x00, 0x10, 0x00, 0x00,
    };
    if (!mem_equal(header1, key, sizeof(header1)))
    {
        printf_s("invalid output data\n");
        return false;
    }
    runtime->Memory.Free(key);

    err = runtime->WinCrypto.GenRSAKey(2048, &key, &len, WC_RSA_KEY_USAGE_KEYX);
    if (err != NO_ERROR)
    {
        printf_s("failed to test GenRSAKey: 0x%X\n", err);
        return false;
    }
    printHexBytes(key, len);
    if (len != 1172)
    {
        printf_s("incorrect output data length: %zu\n", len);
        return false;
    }
    byte header2[] = {
        0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00,
        0x52, 0x53, 0x41, 0x32, 0x00, 0x08, 0x00, 0x00,
    };
    if (!mem_equal(header2, key, sizeof(header2)))
    {
        printf_s("invalid output data\n");
        return false;
    }
    runtime->Memory.Free(key);

    printf_s("test GenRSAKey passed\n");
    return true;
}

static bool TestWinCrypto_SHA1()
{
    byte buf[] = { 1, 2, 3, 4 };

    byte hash[WC_SHA1_SIZE];
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
    if (!mem_equal(expected, hash, WC_SHA1_SIZE))
    {
        printf_s("get incorrect SHA1 hash\n");
        return false;
    }

    printf_s("test SHA1 passed\n");
    return true;
}

static bool TestWinCrypto_AESEncrypt()
{
    byte data[] = { 1, 2, 3, 4 };
    byte key[] = {
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 
    };

    byte* out; uint outLen;
    errno err = runtime->WinCrypto.AESEncrypt(data, sizeof(data), key, &out, &outLen);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data: 0x%X\n", err);
        return false;
    }

    printHexBytes(out, outLen);
    if (outLen != WC_AES_KEY_SIZE)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }

    runtime->Memory.Free(out);

    printf_s("test AESEncrypt passed\n");
    return true;
};

static bool TestWinCrypto_AESDecrypt()
{
    byte data1[] = { 1, 2, 3, 4 };
    byte key[] = {
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 
        0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 
    };

    byte* cipher; uint cipherLen;
    errno err = runtime->WinCrypto.AESEncrypt(data1, sizeof(data1), key, &cipher, &cipherLen);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data: 0x%X\n", err);
        return false;
    }
    if (cipherLen != 32)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }
    byte* plain; uint plainLen;
    err = runtime->WinCrypto.AESDecrypt(cipher, cipherLen, key, &plain, &plainLen);
    if (err != NO_ERROR)
    {
        printf_s("failed to decrypt data: 0x%X\n", err);
        return false;
    }

    printHexBytes(plain, plainLen);
    if (plainLen != 4)
    {
        printf_s("invalid plain data length\n");
        return false;
    }
    byte expected1[] = { 1, 2, 3, 4 };
    if (!mem_equal(expected1, plain, sizeof(expected1)))
    {
        printf_s("get incorrect plain data\n");
        return false;
    }
    if (!mem_equal(expected1, data1, sizeof(expected1)))
    {
        printf_s("original data is changed\n");
        return false;
    }

    runtime->Memory.Free(cipher);
    runtime->Memory.Free(plain);

    byte data2[] = { 
        1, 2, 3, 4, 5, 6, 7, 8, 
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    err = runtime->WinCrypto.AESEncrypt(data2, sizeof(data2), key, &cipher, &cipherLen);
    if (err != NO_ERROR)
    {
        printf_s("failed to encrypt data: 0x%X\n", err);
        return false;
    }
    if (cipherLen != 48)
    {
        printf_s("invalid cipher data length\n");
        return false;
    }
    err = runtime->WinCrypto.AESDecrypt(cipher, cipherLen, key, &plain, &plainLen);
    if (err != NO_ERROR)
    {
        printf_s("failed to decrypt data: 0x%X\n", err);
        return false;
    }

    printHexBytes(plain, plainLen);
    if (plainLen != 16)
    {
        printf_s("invalid plain data length\n");
        return false;
    }
    byte expected2[] = { 
        1, 2, 3, 4, 5, 6, 7, 8, 
        1, 2, 3, 4, 5, 6, 7, 8,
    };
    if (!mem_equal(expected2, plain, sizeof(expected2)))
    {
        printf_s("get incorrect plain data\n");
        return false;
    }
    if (!mem_equal(expected2, data2, sizeof(expected2)))
    {
        printf_s("original data is changed\n");
        return false;
    }

    runtime->Memory.Free(cipher);
    runtime->Memory.Free(plain);

    printf_s("test AESDecrypt passed\n");
    return true;
};

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
    databuf key = {
        .buf = NULL,
        .len = 0,
    };
    errno err = runtime->WinCrypto.GenRSAKey(2048, &key.buf, &key.len, WC_RSA_KEY_USAGE_SIGN);
    if (err != NO_ERROR)
    {
        printf_s("failed to GenRSAKey: 0x%X\n", err);
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

    runtime->Memory.Free(sign.buf);

    printf_s("test RSASign passed\n");
    return true;
}

static bool TestWinCrypto_RSAVerify()
{
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
