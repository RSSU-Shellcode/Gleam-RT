#include <stdio.h>
#include "c_types.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

static bool TestStorage_SetValue();
static bool TestStorage_GetValue();
static bool TestStorage_GetPointer();
static bool TestStorage_Delete();
static bool TestStorage_DeleteAll();

bool TestRuntime_Storage()
{
    test_t tests[] = {
        { TestStorage_SetValue   },
        { TestStorage_GetValue   },
        { TestStorage_GetPointer },
        { TestStorage_Delete     },
        { TestStorage_DeleteAll  },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        printf_s("--------------------------------\n");
        if (!tests[i]())
        {
            return false;
        }
        printf_s("--------------------------------\n\n");
    }
    return true;
}

static bool TestStorage_SetValue()
{
    printf_s("set value with id 0\n");
    int  id  = 0;
    uint val = 1234;
    if (!runtime->Storage.SetValue(id, &val, sizeof(val)))
    {
        printf_s("failed to set value with id 0: 0x%X\n", GetLastErrno());
        return false;
    }

    printf_s("set value with the same id\n");
    id  = 0;
    val = 5678;
    if (!runtime->Storage.SetValue(id, &val, sizeof(val)))
    {
        printf_s("failed to set value with id 0: 0x%X\n", GetLastErrno());
        return false;
    }

    printf_s("set value with the different id\n");
    id  = 16;
    val = 1234;
    if (!runtime->Storage.SetValue(id, &val, sizeof(val)))
    {
        printf_s("failed to set value with id 16: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}

static bool TestStorage_GetValue()
{
    printf_s("get value and receive size\n");
    int id = 0;
    uint val;
    uint size;
    if (!runtime->Storage.GetValue(id, &val, &size))
    {
        printf_s("failed to get value with id 0: 0x%X\n", GetLastErrno());
        return false;
    }
    if (val != 5678)
    {
        printf_s("get incorrect value with id 0\n");
        return false;
    }
    if (size != sizeof(val))
    {
        printf_s("get value with incorrect size\n");
        return false;
    }

    printf_s("get value but not receive size\n");
    id   = 16;
    val  = 0;
    size = 0;
    if (!runtime->Storage.GetValue(id, &val, NULL))
    {
        printf_s("failed to get value with id 0: 0x%X\n", GetLastErrno());
        return false;
    }
    if (val != 1234)
    {
        printf_s("get incorrect value with id 16\n");
        return false;
    }
    if (size != 0)
    {
        printf_s("get value with incorrect size\n");
        return false;
    }
    return true;
}

static bool TestStorage_GetPointer()
{
    printf_s("get pointer and receive size\n");
    int id = 0;
    uint* val = NULL;
    uint  size;
    if (!runtime->Storage.GetPointer(id, &val, &size))
    {
        printf_s("failed to get pointer with id 0: 0x%X\n", GetLastErrno());
        return false;
    }
    if (*val != 5678)
    {
        printf_s("get incorrect value with id 0\n");
        return false;
    }
    if (size != sizeof(*val))
    {
        printf_s("get pointer with incorrect size\n");
        return false;
    }

    printf_s("get pointer but not receive size\n");
    id   = 16;
    val  = NULL;
    size = 0;
    if (!runtime->Storage.GetPointer(id, &val, NULL))
    {
        printf_s("failed to get pointer with id 0: 0x%X\n", GetLastErrno());
        return false;
    }
    if (*val != 1234)
    {
        printf_s("get incorrect value with id 16\n");
        return false;
    }
    if (size != 0)
    {
        printf_s("get pointer with incorrect size\n");
        return false;
    }
    return true;
}

static bool TestStorage_Delete()
{
    printf_s("delete value with id 0\n");
    int id = 0;
    if (!runtime->Storage.Delete(id))
    {
        printf_s("delete value with incorrect id: 0x%X\n", GetLastErrno());
        return false;
    }

    printf_s("delete value with id 16\n");
    id = 16;
    if (!runtime->Storage.Delete(id))
    {
        printf_s("delete value with incorrect id: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}

static bool TestStorage_DeleteAll()
{
    int  id  = 2;
    uint val = 1234;
    if (!runtime->Storage.SetValue(id, &val, sizeof(val)))
    {
        printf_s("failed to set value with id 2: 0x%X\n", GetLastErrno());
        return false;
    }
    id  = 2;
    val = 5678;
    if (!runtime->Storage.SetValue(id, &val, sizeof(val)))
    {
        printf_s("failed to set value with id 2: 0x%X\n", GetLastErrno());
        return false;
    }

    id  = 4;
    val = 1235;
    if (!runtime->Storage.SetValue(id, &val, sizeof(val)))
    {
        printf_s("failed to set value with id 16: 0x%X\n", GetLastErrno());
        return false;
    }

    printf_s("delete all value\n");
    if (!runtime->Storage.DeleteAll())
    {
        printf_s("failed to delete all values: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}
