#include "c_types.h"
#include "lib_memory.h"
#include "list_md.h"

#pragma optimize("t", on)

__declspec(noinline)
void List_Init(List* list, List_Ctx* ctx, uint unit)
{
    list->ctx  = *ctx;
    list->Data = NULL;
    list->Len  = 0;
    list->Cap  = 0;
    list->Last = 0;
    list->Unit = unit;
}

__declspec(noinline)
bool List_Set(List* list, uint index, void* data)
{
    if (index + 1 > list->Cap)
    {
        if (!List_Resize(list, index + 1))
        {
            return false;
        }
    }
    uintptr addr = (uintptr)(list->Data) + index * list->Unit;
    mem_copy((void*)addr, data, list->Unit);
    return true;
}

__declspec(noinline)
void* List_Get(List* list, uint index)
{
    if (index + 1 > list->Cap)
    {
        return NULL;
    }
    uintptr addr = (uintptr)(list->Data);
    return (void*)(addr + index * list->Unit);
}

__declspec(noinline)
bool List_Insert(List* list, void* data)
{
    bool resized = false;
    if (list->Len >= list->Cap)
    {
        bool success;
        if (list->Cap == 0)
        {
            success = List_Resize(list, 16);
        } else {
            if (list->Cap < 1024)
            {
                success = List_Resize(list, list->Cap * 2);
            } else {
                success = List_Resize(list, list->Cap * 5 / 4);
            }
        }
        if (!success)
        {
            return false;
        }
        resized = true;
    }
    // set the begin position
    uint i = 0;
    if (resized)
    {
        i = list->Len;
    }
    // search empty for insert item
    for (; i < list->Cap; i++)
    {
        byte* addr  = ((byte*)(list->Data) + i * list->Unit);
        bool  empty = true;
        for (uint j = 0; j < list->Unit; j++)
        {
            if (*(addr + j) == 0)
            {
                continue;
            }
            empty = false;
            break;
        }
        if (!empty)
        {
            continue;
        }
        if (i > list->Last)
        {
            list->Last = i;
        }
        mem_copy(addr, data, list->Unit);
        list->Len++;
        return true;
    }
    panic(PANIC_UNREACHABLE_CODE);
    return false;
}

__declspec(noinline)
bool List_Delete(List* list, uint index)
{
    if (index + 1 > list->Cap)
    {
        return false;
    }
    byte* addr = (byte*)(list->Data) + index * list->Unit;
    mem_init(addr, list->Unit);
    list->Len--;
    return true;
}

__declspec(noinline)
bool List_Find(List* list, void* data, uint equal, uint* idx)
{
    uint equLen = equal;
    if (equLen == 0)
    {
        equLen = list->Unit;
    }
    uint index = 0;
    bool found = false;
    for (uint num = 0; num < list->Len; index++)
    {
        void* item = List_Get(list, index);
        if (mem_is_zero(item, equLen))
        {
            continue;
        }
        if (!mem_equal(item, data, equLen))
        {
            num++;
            continue;
        }
        found = true;
        break;
    }
    if (!found)
    {
        return false;
    }
    byte* addr = (byte*)(list->Data) + (index*list->Unit);
    mem_copy(data, addr, list->Unit);
    if (idx != NULL)
    {
        *idx = index;
    }
    return true;
}

__declspec(noinline)
bool List_Resize(List* list, uint cap)
{
    uint  size = cap * list->Unit;
    void* data;
    if (list->Data != NULL)
    {
        uint oldSize = List_Size(list);
        data = list->ctx.realloc(list->Data, size);
        void* addr = (void*)((uintptr)data + oldSize);
        uint  num  = size - oldSize;
        mem_init(addr, num);
    } else {
        data = list->ctx.malloc(size);
        mem_init(data, size);
    }
    if (data == NULL)
    {
        return false;
    }
    list->Data = data;
    list->Cap  = cap;
    if (list->Len >= cap)
    {
        list->Len = cap;
    }
    if (list->Last >= cap && cap > 0)
    {
        list->Last = cap - 1;
    }
    return true;
}

uint List_Size(List* list)
{
    return list->Cap * list->Unit;
}

__declspec(noinline)
bool List_Free(List* list)
{
    if (list->Data == NULL || list->ctx.free == NULL)
    {
        return true;
    }
    return list->ctx.free(list->Data);
}

#pragma optimize("t", off)
