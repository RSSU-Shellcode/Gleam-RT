#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "win_api.h"

DWORD GetModuleFileName(void* list, HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
    uintptr mod = (uintptr)list;
    for (;; mod = *(uintptr*)(mod))
    {
    #ifdef _WIN64
        uintptr modName = *(uintptr*)(mod + 80);
    #elif _WIN32
        uintptr modName = *(uintptr*)(mod + 40);
    #endif
        if (modName == 0x00)
        {
            break;
        }
    #ifdef _WIN64
        uintptr modBase = *(uintptr*)(mod + 32);
    #elif _WIN32
        uintptr modBase = *(uintptr*)(mod + 16);
    #endif
        if (modBase != (uintptr)hModule)
        {
            continue;
        }
    #ifdef _WIN64
        uint16 nameLen = *(uint16*)(mod + 74);
    #elif _WIN32
        uint16 nameLen = *(uint16*)(mod + 38);
    #endif
        if (nameLen > nSize)
        {
            nameLen = (uint16)nSize;
        }
        mem_copy(lpFilename, (LPWSTR)modName, nameLen);
        return nameLen;
    }
    return 0;
}

HMODULE GetModuleHandle(void* list, LPWSTR lpFilename)
{
    uintptr mod = (uintptr)list;
    for (;; mod = *(uintptr*)(mod))
    {
    #ifdef _WIN64
        uintptr modName = *(uintptr*)(mod + 80);
    #elif _WIN32
        uintptr modName = *(uintptr*)(mod + 40);
    #endif
        if (modName == 0x00)
        {
            break;
        }
        if (stricmp_w((LPWSTR)modName, lpFilename) != 0)
        {
            continue;
        }
    #ifdef _WIN64
        uintptr modBase = *(uintptr*)(mod + 32);
    #elif _WIN32
        uintptr modBase = *(uintptr*)(mod + 16);
    #endif
        return (HMODULE)modBase;
    }
    return NULL;
}
