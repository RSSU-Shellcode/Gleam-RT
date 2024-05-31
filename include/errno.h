#ifndef ERRNO_H
#define ERRNO_H

#include "c_types.h"

typedef uint errno;

#define NO_ERROR 0x00000000

#define ERR_LIBRARY_INIT_API   0x00020001
#define ERR_LIBRARY_UPDATE_PTR 0x00020002
#define ERR_LIBRARY_INIT_ENV   0x00020003
#define ERR_LIBRARY_CLEAN_MOD  0x00020004
#define ERR_LIBRARY_FREE_LIST  0x00020005

#define ERR_MEMORY_INIT_API         0x00030001
#define ERR_MEMORY_UPDATE_PTR       0x00030002
#define ERR_MEMORY_INIT_ENV         0x00030003
#define ERR_MEMORY_ENCRYPT_PAGE     0x00030004
#define ERR_MEMORY_DECRYPT_PAGE     0x00030005
#define ERR_MEMORY_CLEAN_PAGE       0x00031006
#define ERR_MEMORY_CLEAN_REGION     0x00031007
#define ERR_MEMORY_FREE_PAGE_LIST   0x00031008
#define ERR_MEMORY_FREE_REGION_LIST 0x00031009

#define ERR_THREAD_INIT_API        0x00040001
#define ERR_THREAD_UPDATE_PTR      0x00040002
#define ERR_THREAD_INIT_ENV        0x00040003
#define ERR_THREAD_GET_CURRENT_TID 0x00040004
#define ERR_THREAD_SUSPEND         0x00041005
#define ERR_THREAD_RESUME          0x00041006
#define ERR_THREAD_TERMINATE       0x00041007
#define ERR_THREAD_CLOSE_HANDLE    0x00041008
#define ERR_THREAD_FREE_LIST       0x00041009

#endif // ERRNO_H
