#ifndef WIN_API_H
#define WIN_API_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"

DWORD   GetModuleFileName(void* list, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
HMODULE GetModuleHandle(void* list, LPWSTR lpFilename);

#endif // WIN_API_H
