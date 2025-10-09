#include "c_types.h"
#include "win_types.h"
#include "lib_string.h"
#include "crypto.h"
#include "pe_image.h"

#define DOS_HEADER_SIZE 64

#define NT_HEADER_SIGNATURE_SIZE 4
#define PE_FILE_HEADER_SIZE      20
#define PE_SECTION_HEADER_SIZE   40

void ParsePEImage(void* address, PE_Image* image)
{
    uintptr imageAddr = (uintptr)address;
    uint32  peOffset  = *(uint32*)(imageAddr + DOS_HEADER_SIZE - 4);
    uintptr peHeader  = imageAddr + peOffset + NT_HEADER_SIGNATURE_SIZE;
    // parse file header
    uint16 numSections   = *(uint16*)(peHeader + 2);
    uint16 optHeaderSize = *(uint16*)(peHeader + 16);
    // parse optional header
    uint32  entryPoint = *(uint32*)(peHeader + 36);
#ifdef _WIN64
    uintptr imageBase = *(uintptr*)(peHeader + 44);
#elif _WIN32
    uintptr imageBase = *(uintptr*)(peHeader + 48);
#endif
    uint32 imageSize = *(uint32*)(peHeader + 76);
    // not record the original ".text" bytes
    byte target[] = {
        '.'^0x19, 't'^0xF4, 'e'^0xBF, 'x'^0x8C,
        't'^0x19, 000^0xF4, 000^0xBF, 000^0x8C,
    };
    byte key[] = {0x19, 0xF4, 0xBF, 0x8C};
    XORBuf(target, sizeof(target), key, sizeof(key));
    // parse sections and search .text
    uintptr section = peHeader + PE_FILE_HEADER_SIZE + optHeaderSize;
    for (uint16 i = 0; i < numSections; i++)
    {
        if (strncmp_a((ANSI)section, (ANSI)target, sizeof(target)) != 0)
        {
            section += PE_SECTION_HEADER_SIZE;
            continue;
        }
        section += 8; // skip section name
        image->TextVirtualSize      = *(uint32*)(section + 0);
        image->TextVirtualAddress   = *(uint32*)(section + 4);
        image->TextSizeOfRawData    = *(uint32*)(section + 8);
        image->TextPointerToRawData = *(uint32*)(section + 12);

        panic(PANIC_REACHABLE_TEST);

        break;
    }
    image->EntryPoint = imageAddr + entryPoint;
    image->ImageBase  = imageBase;
    image->ImageSize  = imageSize;
}
