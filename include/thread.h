#ifndef THREAD_H
#define THREAD_H

#include "c_types.h"

// CamouflageStartAddress is used to camouflage thread
// start address, it will return a random address at the
// text section of current executable image.
void* CamouflageStartAddress(void* list, void* address);

#endif // THREAD_H
