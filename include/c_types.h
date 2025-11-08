#ifndef C_TYPES_H
#define C_TYPES_H

// disable special warnings for /Wall
#pragma warning(disable: 4057)
#pragma warning(disable: 4152)
#pragma warning(disable: 4255)
#pragma warning(disable: 4459)
#pragma warning(disable: 4710)
#pragma warning(disable: 4711)
#pragma warning(disable: 4820)
#pragma warning(disable: 4826)
#pragma warning(disable: 5045)
#pragma warning(disable: 5250)

// reference basic types from Go
typedef char      int8;
typedef short     int16;
typedef int       int32;
typedef long long int64;

typedef unsigned char      uint8;
typedef unsigned short     uint16;
typedef unsigned int       uint32;
typedef unsigned long long uint64;

#ifdef _WIN64
    typedef int64  integer;
    typedef uint64 uint;
    typedef uint64 uintptr;
#elif _WIN32
    typedef int32  integer;
    typedef uint32 uint;
    typedef uint32 uintptr;
#endif

typedef float  float32;
typedef double float64;

typedef uint8 byte;
typedef int32 rune;

typedef _Bool bool;
typedef int32 BOOL;

typedef struct {
    void* buf;
    uint  len;
} databuf;

#define true  1
#define false 0

#ifndef NULL
#define NULL ((void*)0)
#endif

// copy from <stdint.h>
#define INT8_MIN   (-127i8 - 1)
#define INT16_MIN  (-32767i16 - 1)
#define INT32_MIN  (-2147483647i32 - 1)
#define INT64_MIN  (-9223372036854775807i64 - 1)
#define INT8_MAX   127i8
#define INT16_MAX  32767i16
#define INT32_MAX  2147483647i32
#define INT64_MAX  9223372036854775807i64
#define UINT8_MAX  0xFFui8
#define UINT16_MAX 0xFFFFui16
#define UINT32_MAX 0xFFFFFFFFui32
#define UINT64_MAX 0xFFFFFFFFFFFFFFFFui64

// calculate the array length
#ifndef arrlen
#define arrlen(array) (sizeof(array) / sizeof(array[0]))
#endif

// calculate the structure field offset of the structure
#ifndef offsetof
#define offsetof(struct, field) ((uintptr) & (((struct*)0)->field))
#endif

// reference panic from Go
#define PANIC_UNREACHABLE_CODE 0x00000000
#define PANIC_REACHABLE_TEST   0x00001000

#ifndef panic
#define panic(val) (*(int*)(val) = 0)
#endif

#endif // C_TYPES_H
