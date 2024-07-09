#include "build.h"
#include "debug.h"

#ifdef IS_RELEASE

bool InitDebugModule()
{
    return true;
}

void dbg_log(char* mod, char* fmt, ...){};

#else

#include <stdio.h>
#include <stdarg.h>
#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"

HANDLE dbg_hMutex;

CreateMutexA_t        dbg_CreateMutexA;
WaitForSingleObject_t dbg_WaitForSingleObject;
ReleaseMutex_t        dbg_ReleaseMutex;

bool InitDebugModule()
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xA2D798D911E87CA2, 0x481735119475138A }, // CreateMutexA
        { 0xC46DDE0F5772E6BA, 0x7C679644A4A302DB }, // ReleaseMutex
        { 0x6AE5CE55F71FE6EE, 0xEBA084F07FBBE115 }, // WaitForSingleObject
    };
#elif _WIN32
    {
        { 0xB1455CC8, 0x33E9036C }, // CreateMutexA
        { 0x242CE451, 0x1C9D2F45 }, // ReleaseMutex
        { 0xD1AF96CF, 0xF3D39D89 }, // WaitForSingleObject
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    dbg_CreateMutexA        = list[0].proc;
    dbg_WaitForSingleObject = list[1].proc;
    dbg_ReleaseMutex        = list[2].proc;

    dbg_hMutex = dbg_CreateMutexA(NULL, false, NULL);


    return true;
}

void dbg_log(char* mod, char* fmt, ...)
{
    dbg_WaitForSingleObject(dbg_hMutex, INFINITE);

    va_list args;
    va_start(args, fmt);

    printf_s("%s ", mod);
    printf_s(fmt, args);

    va_end(args);

    dbg_ReleaseMutex(dbg_hMutex);
}

#endif
