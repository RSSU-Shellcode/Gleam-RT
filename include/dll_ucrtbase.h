#ifndef DLL_UCRTBASE_H
#define DLL_UCRTBASE_H

#include "c_types.h"
#include "win_types.h"

typedef void* (__cdecl *ucrtbase_malloc_t)
(
    uint size
);

typedef void* (__cdecl *ucrtbase_calloc_t)
(
    uint num, uint size
);

typedef void* (__cdecl *ucrtbase_realloc_t)
(
    void* ptr, uint size
);

typedef void (__cdecl *ucrtbase_free_t)
(
    void* ptr
);

typedef uint (__cdecl *ucrtbase_msize_t)
(
    void* ptr
);

#endif // DLL_UCRTBASE_H
