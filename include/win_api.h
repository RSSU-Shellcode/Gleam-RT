#ifndef WIN_API_H
#define WIN_API_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"

DWORD   GetModuleFileName(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
HMODULE GetModuleHandle(LPWSTR lpFilename);

#endif // WIN_API_H
