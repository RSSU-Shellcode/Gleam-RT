#include "c_types.h"
#include "lib_memory.h"
#include "serialize.h"

uint32 Serialize(uint32* descriptor, void* data, void* serialized)
{
    byte*  buffer  = serialized;
    byte*  dataPtr = data;
    uint32 length  = 0;
    // write magic number
    if (buffer != NULL)
    {
        *(uint32*)buffer = SERIALIZE_HEADER_MAGIC;
        buffer += sizeof(uint32);
    }
    length += sizeof(uint32);
    // calculate the serialized data length and write descriptor
    uint32* descPtr = descriptor;
    for (;;)
    {
        uint32 desc = *descPtr;
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
        descPtr++;
    }
    // for only calculate the serialized data length
    if (buffer == NULL)
    {
        return length;
    }
    // write structure field value
    descPtr = descriptor;
    for (;;)
    {
        uint32 desc = *descPtr;
        if (desc == SERIALIZE_ITEM_END)
        {
            break;
        }
        uint32 size = desc & SERIALIZE_MASK_LENGTH;
        switch (desc & SERIALIZE_MASK_FLAG)
        {
        case SERIALIZE_FLAG_VALUE:
            mem_copy(buffer, dataPtr, size);
            dataPtr += size;
            break;
        case SERIALIZE_FLAG_POINTER:
            uintptr ptr = *(uintptr*)(dataPtr);
            mem_copy(buffer, (byte*)(ptr), size);
            dataPtr += sizeof(uintptr);
            break;
        }
        buffer += size;
        descPtr++;
    }
    return length;
}

BOOL Unserialize(void* serialized, void* data)
{
    byte* buffer  = serialized;
    byte* dataPtr = data;
    // check is valid serialized data
    if (*(uint32*)buffer != SERIALIZE_HEADER_MAGIC)
    {
        return false;
    }
    buffer += sizeof(uint32);
    // calculate the number of the fields
    uint numFields = 0;
    uint32* descPtr = (uint32*)buffer;
    for (;;)
    {
        uint32 desc = *descPtr;
        if (desc == SERIALIZE_ITEM_END)
        {
            break;
        }
        numFields++;
        descPtr++;
    }
    byte* dataSrc = buffer + (numFields + 1) * 4;
    // unserialize data to structure field
    descPtr = (uint32*)buffer;
    for (;;)
    {
        uint32 desc = *descPtr;
        if (desc == SERIALIZE_ITEM_END)
        {
            break;
        }
        uint32 size = desc & SERIALIZE_MASK_LENGTH;
        switch (desc & SERIALIZE_MASK_FLAG)
        {
        case SERIALIZE_FLAG_VALUE:
            mem_copy(dataPtr, dataSrc, size);
            dataPtr += size;
            break;
        case SERIALIZE_FLAG_POINTER:
            uintptr ptr = (uintptr)dataSrc;
            if (size == 0)
            {
                ptr = 0; // set NULL pointer
            }
            mem_copy(dataPtr, &ptr, sizeof(uintptr));
            dataPtr += sizeof(uintptr);
            break;
        }
        dataSrc += size;
        descPtr++;
    }
    return true;
}
