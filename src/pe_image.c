#include "c_types.h"
#include "win_types.h"
#include "lib_string.h"
#include "crypto.h"
#include "pe_image.h"

void ParsePEImage(void* address, PE_Image* image)
{
    uintptr imageAddr = (uintptr)address;
    uint32  hdrOffset = *(uint32*)(imageAddr + DOS_HEADER_SIZE - 4);
    // parse PE headers
    Image_NTHeaders*      ntHeaders  = (Image_NTHeaders*)(imageAddr + hdrOffset);
    Image_FileHeader*     fileHeader = &ntHeaders->FileHeader;
    Image_OptionalHeader* optHeader  = &ntHeaders->OptionalHeader;
    // not record the original ".text" bytes
    byte target[] = {
        '.'^0x19, 't'^0xF4, 'e'^0xBF, 'x'^0x8C,
        't'^0x19, 000^0xF4, 000^0xBF, 000^0x8C,
    };
    byte key[] = {0x19, 0xF4, 0xBF, 0x8C};
    XORBuf(target, sizeof(target), key, sizeof(key));
    // get address of first section header
    uintptr fileAddr = imageAddr + hdrOffset + sizeof(ntHeaders->Signature);
    uintptr optAddr  = fileAddr + sizeof(Image_FileHeader);
    uint32  optSize  = fileHeader->SizeOfOptionalHeader;
    Image_SectionHeader* section = (Image_SectionHeader*)(optAddr + optSize);
    // search .text section
    for (uint16 i = 0; i < fileHeader->NumberOfSections; i++)
    {
        if (strncmp_a((ANSI)section, (ANSI)target, sizeof(target)) != 0)
        {
            section++;
            continue;
        }
        image->Text = *section;
        break;
    }
    // store parse result
    image->EntryPoint     = imageAddr + optHeader->AddressOfEntryPoint;
    image->ImageBase      = optHeader->ImageBase;
    image->ImageSize      = optHeader->SizeOfImage;
    image->FileHeader     = *fileHeader;
    image->OptionalHeader = *optHeader;
}
