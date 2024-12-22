#ifndef SHIELD_H
#define SHIELD_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"

typedef struct {
    uintptr BeginAddress;
    uintptr EndAddress;
    byte    CryptoKey[32];
    HANDLE  hTimer;

    WaitForSingleObject_t WaitForSingleObject;
} Shield_Ctx;

bool DefenseRT(Shield_Ctx* ctx);

#endif // SHIELD_H
