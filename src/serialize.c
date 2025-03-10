#include "c_types.h"
#include "lib_memory.h"
#include "serialize.h"

uint32 Serialize(uint32* descriptor, void* data, void* serialized)
{
    byte* buffer  = serialized;
    byte* dataptr = data;
    uint32 length = 0;
    // write magic number
    if (buffer != NULL)
    {
        *(uint32*)buffer = SERIALIZE_HEADER_MAGIC;
        buffer += sizeof(uint32);
    }
    length += sizeof(uint32);
    // calculate the serialized data length and write descriptor
    uint32* desc_p = descriptor;
    for (;;)
    {
        uint32 desc = *desc_p;
        // write descriptor
        if (buffer != NULL)
        {
            *(uint32*)buffer = desc;
            buffer += sizeof(uint32);
        }
        length += sizeof(uint32);
        if (desc == SERIALIZE_ITEM_END)
        {
            break;
        }
        length += desc & SERIALIZE_MASK_LENGTH;
        desc_p++;
    }
    // for only calculate the serialized data length
    if (buffer == NULL)
    {
        return length;
    }
    // write structure field value
    desc_p = descriptor;
    for (;;)
    {
        uint32 desc = *desc_p;
        if (desc == SERIALIZE_ITEM_END)
        {
            break;
        }
        uint32 size = desc & SERIALIZE_MASK_LENGTH;
        switch (desc & SERIALIZE_MASK_FLAG)
        {
        case SERIALIZE_FLAG_VALUE:
            mem_copy(buffer, dataptr, size);
            dataptr += size;
            break;
        case SERIALIZE_FLAG_POINTER:
            uintptr ptr = *(uintptr*)(dataptr);
            mem_copy(buffer, (byte*)(ptr), size);
            dataptr += sizeof(uintptr);
            break;
        }
        buffer += size;
        desc_p++;
    }
    return length;
}

bool Unserialize(void* serialized, void* data)
{
    byte* buffer  = serialized;
    byte* dataptr = data;
    // check is valid serialized data
    if (*(uint32*)buffer != SERIALIZE_HEADER_MAGIC)
    {
        return false;
    }
    buffer += sizeof(uint32);
    // calculate the number of the fields
    uint numFields = 0;
    uint32* desc_p = (uint32*)buffer;
    for (;;)
    {
        uint32 desc = *desc_p;
        if (desc == SERIALIZE_ITEM_END)
        {
            break;
        }
        numFields++;
        desc_p++;
    }
    byte* datasrc = buffer + (numFields + 1) * 4;
    // unserialize data to structure field
    desc_p = (uint32*)buffer;
    for (;;)
    {
        uint32 desc = *desc_p;
        if (desc == SERIALIZE_ITEM_END)
        {
            break;
        }
        uint32 size = desc & SERIALIZE_MASK_LENGTH;
        switch (desc & SERIALIZE_MASK_FLAG)
        {
        case SERIALIZE_FLAG_VALUE:
            mem_copy(dataptr, datasrc, size);
            dataptr += size;
            break;
        case SERIALIZE_FLAG_POINTER:
            uintptr ptr = (uintptr)datasrc;
            if (size == 0)
            {
                ptr = 0; // set NULL pointer
            }
            mem_copy(dataptr, &ptr, sizeof(uintptr));
            dataptr += sizeof(uintptr);
            break;
        }
        datasrc += size;
        desc_p++;
    }
    return true;
}
