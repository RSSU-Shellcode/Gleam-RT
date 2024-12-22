#ifndef DLL_MSVCRT_H
#define DLL_MSVCRT_H

#include "c_types.h"
#include "win_types.h"

typedef void* (__cdecl *msvcrt_malloc_t)
(
	uint size
);

typedef void* (__cdecl *msvcrt_calloc_t)
(
	uint num, uint size
);

typedef void* (__cdecl *msvcrt_realloc_t)
(
	void* ptr, uint size
);

typedef void (__cdecl *msvcrt_free_t)
(
	void* ptr
);

typedef uint (__cdecl *msvcrt_msize_t)
(
	void* ptr
);

#endif // DLL_MSVCRT_H
