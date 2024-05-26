#ifndef LIBRARY_H
#define LIBRARY_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"

typedef bool (*LibFreeAll_t)();

typedef struct {
    LoadLibraryA_t   LoadLibraryA;
    LoadLibraryW_t   LoadLibraryW;
    LoadLibraryExA_t LoadLibraryExA;
    LoadLibraryExW_t LoadLibraryExW;

    FreeLibrary_t              FreeLibrary;
    FreeLibraryAndExitThread_t FreeLibraryAndExitThread;

    LibFreeAll_t LibFreeAll;
} LibraryTracker_M;

LibraryTracker_M* InitLibraryTracker(Context* context);

#endif // LIBRARY_H