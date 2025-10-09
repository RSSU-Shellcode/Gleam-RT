#ifndef PE_IMAGE_H
#define PE_IMAGE_H

#include "c_types.h"
#include "win_types.h"

#define DOS_HEADER_SIZE 64

typedef struct {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} Image_FileHeader;

typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} Image_DataDirectory;

typedef struct {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;          
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;      
    DWORD Win32VersionValue;      
    DWORD SizeOfImage;          
    DWORD SizeOfHeaders;
    DWORD CheckSum;             
    WORD  Subsystem;                  
    WORD  DllCharacteristics;
    DWORD SizeOfStackReserve;        
    DWORD SizeOfStackCommit;        
    DWORD SizeOfHeapReserve;         
    DWORD SizeOfHeapCommit;         
    DWORD LoaderFlags;          
    DWORD NumberOfRvaAndSizes;

    Image_DataDirectory DataDirectory[16];
} Image_OptionalHeader32;

typedef struct {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    QWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;      
    DWORD Win32VersionValue;      
    DWORD SizeOfImage;          
    DWORD SizeOfHeaders;
    DWORD CheckSum;              
    WORD  Subsystem;
    WORD  DllCharacteristics;
    QWORD SizeOfStackReserve;
    QWORD SizeOfStackCommit;
    QWORD SizeOfHeapReserve;
    QWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;

    Image_DataDirectory DataDirectory[16];
} Image_OptionalHeader64;

#ifdef _WIN64
    typedef Image_OptionalHeader64 Image_OptionalHeader;
#elif _WIN32
    typedef Image_OptionalHeader32 Image_OptionalHeader;
#endif

typedef struct {
    DWORD                Signature;
    Image_FileHeader     FileHeader;
    Image_OptionalHeader OptionalHeader;
} Image_NTHeaders;

typedef struct {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLineNumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLineNumbers;
    DWORD Characteristics;
} Image_SectionHeader;

typedef struct {
    uintptr EntryPoint;
    uintptr ImageBase;
    uint32  ImageSize;

    Image_FileHeader     FileHeader;
    Image_OptionalHeader OptionalHeader;

    Image_SectionHeader Text;
} PE_Image;

void ParsePEImage(void* address, PE_Image* image);

#endif // PE_IMAGE_H
