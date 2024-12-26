#ifndef LIB_MEMORY_H
#define LIB_MEMORY_H

#include "c_types.h"

typedef void* (*malloc_t)(uint size);
typedef void* (*calloc_t)(uint num, uint size);
typedef void* (*realloc_t)(void* ptr, uint size);
typedef bool  (*free_t)(void* ptr);
typedef uint  (*msize_t)(void* ptr);
typedef uint  (*mcap_t)(void* ptr);

// mem_copy is used to copy source memory data to the destination.
void mem_copy(void* dst, void* src, uint num);

// mem_move is used to copy source memory data to the destination.
// It can handle overlapping memory regions.
void mem_move(void* dst, void* src, uint num);

// mem_init is used to fill the memory with zero.
void mem_init(void* ptr, uint num);

// mem_set is used to fill the memory with value.
void mem_set(void* ptr, byte val, uint num);

// mem_cmp is used to compare memory data.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int mem_cmp(void* a, void* b, uint num);

// mem_equal is used to compare the memory is equal.
bool mem_equal(void* a, void* b, uint num);

// mem_zero is used to check the memory are all zero.
bool mem_is_zero(void* ptr, uint num);

#endif // LIB_MEMORY_H
