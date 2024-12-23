#include "c_types.h"
#include "win_types.h"
#include "lib_string.h"
#include "crypto.h"
#include "pe_image.h"

void ParsePEImage(void* address, PE_Image* image)
{
    uintptr imageAddr = (uintptr)address;
    uint32  peOffset  = *(uint32*)(imageAddr + 60);
    // parse file header
    uint16 numSections   = *(uint16*)(imageAddr + peOffset + 6);
    uint16 optHeaderSize = *(uint16*)(imageAddr + peOffset + 20);
    // parse optional header
    uint32  entryPoint = *(uint32*)(imageAddr + peOffset + 40);
#ifdef _WIN64
    uintptr imageBase = *(uintptr*)(imageAddr + peOffset + 48);
#elif _WIN32
    uintptr imageBase = *(uintptr*)(imageAddr + peOffset + 52);
#endif
    uint32 imageSize = *(uint32*)(imageAddr + peOffset + 80);
    // not record the original ".text" bytes
    byte target[] = {
        '.'^0x19, 't'^0xF4, 'e'^0xBF, 'x'^0x8C,
        't'^0x19, 000^0xF4, 000^0xBF, 000^0x8C,
    };
    byte key[] = {0x19, 0xF4, 0xBF, 0x8C};
    XORBuf(target, sizeof(target), key, sizeof(key));
    // parse sections and search .text
    uintptr section = imageAddr + PE_FILE_HEADER_SIZE + peOffset + optHeaderSize;
    for (uint16 i = 0; i < numSections; i++)
    {
        if (strncmp_a((ANSI)section, (ANSI)target, sizeof(target)) != 0)
        {
            section += PE_SECTION_HEADER_SIZE;
            continue;
        }
        image->TextVirtualSize      = *(uint32*)(section + 8); 
        image->TextVirtualAddress   = *(uint32*)(section + 12); 
        image->TextSizeOfRawData    = *(uint32*)(section + 16); 
        image->TextPointerToRawData = *(uint32*)(section + 20);
        break;
    }
    image->EntryPoint = imageAddr + entryPoint;
    image->ImageBase  = imageBase;
    image->ImageSize  = imageSize;
}
