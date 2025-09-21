#ifndef HASH_API_H
#define HASH_API_H

#include "c_types.h"

// FindAPI will not call GetProcAddress, if this module is
// not loaded, it cannot find the target procedure address.
//
// FindAPI is support forwarded procedure.
// FindAPI is NOT support DLL about API Sets.

typedef void* (*FindAPI_t)(uint module, uint procedure, uint key);
typedef void* (*FindAPI_ML_t)(void* list, uint module, uint procedure, uint key);
typedef void* (*FindAPI_A_t)(byte* module, byte* procedure);
typedef void* (*FindAPI_W_t)(uint16* module, byte* procedure);

// FindAPI is used to find Windows API address by hash and key.
void* FindAPI(uint module, uint procedure, uint key);

// FindAPI_ML is used to find Windows API address by hash and key.
// But it will use the cached InMemoryOrderModuleList.
void* FindAPI_ML(void* list, uint module, uint procedure, uint key);

// FindAPI_A is used to find Windows API address by module name
// and procedure name with ANSI, it is a wrapper about FindAPI.
void* FindAPI_A(byte* module, byte* procedure);

// FindAPI_W is used to find Windows API address by module name
// and procedure name with UTF-16, it is a wrapper about FindAPI.
void* FindAPI_W(uint16* module, byte* procedure);

// CalcModHash_A is used to calculate module ANSI name hash with key.
uint   CalcModHash_A  (byte* module, uint key);
uint32 CalcModHash32_A(byte* module, uint32 key);
uint64 CalcModHash64_A(byte* module, uint64 key);

// CalcModHash_W is used to calculate module UTF-16 name hash with key.
uint   CalcModHash_W  (uint16* module, uint key);
uint32 CalcModHash32_W(uint16* module, uint32 key);
uint64 CalcModHash64_W(uint16* module, uint64 key);

// CalcProcHash is used to calculate procedure name hash with key.
uint   CalcProcHash  (byte* procedure, uint key);
uint32 CalcProcHash32(byte* procedure, uint32 key);
uint64 CalcProcHash64(byte* procedure, uint64 key);

// GetInMemoryOrderModuleList is used to get InMemoryOrderModuleList address.
void* GetInMemoryOrderModuleList();

#endif // HASH_API_H
