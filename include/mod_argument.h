#ifndef MOD_ARGUMENT_H
#define MOD_ARGUMENT_H

#include "c_types.h"
#include "context.h"
#include "errno.h"

// +---------+----------+-----------+----------+-----------+-----------+
// |   key   | num args | args size | checksum | arg1 size | arg1 data |
// +---------+----------+-----------+----------+-----------+-----------+
// | 32 byte |  uint32  |  uint32   |  uint32  |  uint32   |    var    |
// +---------+----------+-----------+----------+-----------+-----------+

#define ARG_CRYPTO_KEY_SIZE (32)
#define ARG_HEADER_SIZE     (32 + 4 + 4 + 4)

#define ARG_OFFSET_CRYPTO_KEY (0)
#define ARG_OFFSET_NUM_ARGS   (32)
#define ARG_OFFSET_ARGS_SIZE  (32 + 4)
#define ARG_OFFSET_CHECKSUM   (32 + 4 + 4)
#define ARG_OFFSET_FIRST_ARG  (32 + 4 + 4 + 4)

typedef bool (*ArgGetValue_t)(uint index, void* value, uint32* size);
typedef bool (*ArgGetPointer_t)(uint index, void** pointer, uint32* size);
typedef bool (*ArgErase_t)(uint index);
typedef void (*ArgEraseAll_t)();

typedef bool  (*ArgLock_t)();
typedef bool  (*ArgUnlock_t)();
typedef errno (*ArgEncrypt_t)();
typedef errno (*ArgDecrypt_t)();
typedef errno (*ArgClean_t)();

typedef struct {
    ArgGetValue_t   GetValue;
    ArgGetPointer_t GetPointer;
    ArgErase_t      Erase;
    ArgEraseAll_t   EraseAll;

    ArgLock_t    Lock;
    ArgUnlock_t  Unlock;
    ArgEncrypt_t Encrypt;
    ArgDecrypt_t Decrypt;
    ArgClean_t   Clean;
} ArgumentStore_M;

ArgumentStore_M* InitArgumentStore(Context* context);

// reserve stub for store arguments
#pragma warning(push)
#pragma warning(disable: 4276)
extern void Argument_Stub();
#pragma warning(pop)

#endif // MOD_ARGUMENT_H
