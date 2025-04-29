#include "c_types.h"
#include "lib_memory.h"
#include "random.h"
#include "pe_image.h"
#include "thread.h"

void* CamouflageStartAddress(void* address)
{
#ifdef NOT_CAMOUFLAGE
    return address;
#endif // NOT_CAMOUFLAGE

    // get current process module from PEB
#ifdef _WIN64
    uintptr peb = __readgsqword(96);
    uintptr ldr = *(uintptr*)(peb + 24);
    uintptr mod = *(uintptr*)(ldr + 32);
#elif _WIN32
    uintptr peb = __readfsdword(48);
    uintptr ldr = *(uintptr*)(peb + 12);
    uintptr mod = *(uintptr*)(ldr + 20);
#endif
    // get current process module address
#ifdef _WIN64
    uintptr modAddr = *(uintptr*)(mod + 32);
#elif _WIN32
    uintptr modAddr = *(uintptr*)(mod + 16);
#endif
    // parse module information
    PE_Image image;
    mem_init(&image, sizeof(image));
    ParsePEImage((byte*)modAddr, &image);
    // if failed to get text section address, return raw address
    if (image.TextVirtualAddress == 0)
    {
        return address;
    }
    // select a random start address
    uintptr base  = modAddr + image.TextVirtualAddress;
    uintptr range = image.TextSizeOfRawData;
    uintptr begin = base + RandUintN((uint64)address, range);
    uintptr end   = base + image.TextSizeOfRawData;
    for (uintptr addr = begin; addr < end; addr++)
    {
        byte b = *(byte*)addr; 
        // skip special instructions
        switch (b)
        {
        case 0x00: // NULL
            continue;
        case 0xCC: // int3
            continue;
        case 0xC3: // ret
            continue;
        case 0xC2: // ret n
            continue;
        default:
            break;
        }
        // about push 
        if (b >= 0x50 && b <= 0x57)
        {
            return (void*)addr;
        }
        // about mov
        if (b >= 0x88 && b <= 0x8B)
        {
            return (void*)addr;
        }
        // about mov register
        if (b >= 0xB0 && b <= 0xBF)
        {
            return (void*)addr;
        }
    }
    // if not found, return the random start address
    return (void*)begin;
}
