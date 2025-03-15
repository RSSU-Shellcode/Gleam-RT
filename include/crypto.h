#ifndef CRYPTO_H
#define CRYPTO_H

#include "c_types.h"

#define CRYPTO_IV_SIZE  16
#define CRYPTO_KEY_SIZE 32

// EncryptBuf is used to encrypt data in buffer with 256 bit key.
void EncryptBuf(void* buf, uint size, byte* key, byte* iv);

// DecryptBuf is used to decrypt data in buffer with 256 bit key.
void DecryptBuf(void* buf, uint size, byte* key, byte* iv);

// XORBuf is used to xor data in buffer with key.
void XORBuf(void* buf, uint bufSize, void* key, uint keySize);

#endif // CRYPTO_H
