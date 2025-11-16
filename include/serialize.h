#ifndef SERIALIZE_H
#define SERIALIZE_H

#include "c_types.h"

// serialized data structure
// +---------+----------+----------+----------+------------+
// |  magic  |  item 1  |  item 2  | item END |  raw data  |
// +---------+----------+----------+----------+------------+
// |  uint32 |  uint32  |  uint32  |  uint32  |    var     |
// +---------+----------+----------+----------+------------+
//
// item data structure
// 0······· value or pointer
// ·0000000 data length

#define SERIALIZE_HEADER_MAGIC 0xFFFFFFFF
#define SERIALIZE_ITEM_END     0x00000000

#define SERIALIZE_FLAG_VALUE   0x00000000
#define SERIALIZE_FLAG_POINTER 0x80000000

#define SERIALIZE_MASK_FLAG    0x80000000
#define SERIALIZE_MASK_LENGTH  0x7FFFFFFF

// Serialize is used to serialize structure to a buffer.
// If success, return the serialized data length. If failed, return 0.
// If serialized is NULL, it will calculate the serialized data length.
uint32 Serialize(uint32* descriptor, void* data, void* serialized);

// Unserialize is used to unserialize data to a structure.
BOOL Unserialize(void* serialized, void* data);

#endif // SERIALIZE_H
