#ifndef WIN_TYPES_H
#define WIN_TYPES_H

#include "c_types.h"

typedef uint8  BYTE;
typedef uint16 WORD;
typedef uint32 DWORD;
typedef uint64 QWORD;

typedef int8  CHAR;
typedef int16 SHORT;
typedef int32 LONG;
typedef int64 LONGLONG;

typedef int32 BOOL;
typedef uint  UINT;
typedef uint  SIZE_T;
typedef uint  ULONG_PTR;

typedef void* POINTER;
typedef void* PVOID;
typedef void* HANDLE;

typedef void*   LPVOID;
typedef uint8*  LPSTR;
typedef uint16* LPWSTR;
typedef HANDLE* LPHANDLE;

typedef const void*   LPCVOID;
typedef const uint8*  LPCSTR;
typedef const uint16* LPCWSTR;

#endif // WIN_TYPES_H
