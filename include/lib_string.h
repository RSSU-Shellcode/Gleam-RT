#ifndef LIB_STRING_H
#define LIB_STRING_H

#include "c_types.h"

typedef byte*   ANSI;
typedef uint16* UTF16;

// strlen_a is used to calculate ANSI string length.
uint strlen_a(ANSI s);

// strlen_w is used to calculate UTF-16 string length.
uint strlen_w(UTF16 s);

// strcmp_a is used to compare two ANSI strings.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strcmp_a(ANSI a, ANSI b);

// strcmp_w is used to compare two UTF-16 strings.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strcmp_w(UTF16 a, UTF16 b);

// strncmp_a is used to compare two ANSI strings with length.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strncmp_a(ANSI a, ANSI b, int64 n);

// strncmp_w is used to compare two UTF-16 strings with length.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strncmp_w(UTF16 a, UTF16 b, int64 n);

// stricmp_a is used to compare two ANSI strings, it is case-insensitive.
// 
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int stricmp_a(ANSI a, ANSI b);

// stricmp_w is used to compare two UTF-16 strings, it is case-insensitive.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int stricmp_w(UTF16 a, UTF16 b);

// strnicmp_a is used to compare two ANSI strings with length, it is case-insensitive.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strnicmp_a(ANSI a, ANSI b, int64 n);

// strnicmp_w is used to compare two UTF-16 strings with length, it is case-insensitive.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strnicmp_w(UTF16 a, UTF16 b, int64 n);

// strcpy_a is used to copy source ANSI string to destination.
uint strcpy_a(ANSI dst, ANSI src);

// strcpy_w is used to copy source UTF-16 string to destination.
uint strcpy_w(UTF16 dst, UTF16 src);

// strcpy_a is used to copy source ANSI string to destination with length.
uint strncpy_a(ANSI dst, ANSI src, int64 n);

// strcpy_w is used to copy source UTF-16 string to destination with length.
uint strncpy_w(UTF16 dst, UTF16 src, int64 n);

#endif // LIB_STRING_H
