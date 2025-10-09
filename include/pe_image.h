#ifndef PE_IMAGE_H
#define PE_IMAGE_H

#include "c_types.h"

typedef struct {
    // optional header
    uintptr EntryPoint;
    uintptr ImageBase;
    uint32  ImageSize;

    // section information
    uint32 TextVirtualSize;
    uint32 TextVirtualAddress;
    uint32 TextSizeOfRawData;
    uint32 TextPointerToRawData;
} PE_Image;

void ParsePEImage(void* address, PE_Image* image);

#endif // PE_IMAGE_H
