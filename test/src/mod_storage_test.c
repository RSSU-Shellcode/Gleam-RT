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
    int  id  = 0;
    uint val = 1234;
    if (!runtime->Storage.SetValue(id, &val, sizeof(val)))
    {
        printf_s("failed to set value with id 0\n");
        return false;
    }

    printf_s("set value with the same id\n");
    id  = 0;
    val = 5678;
    if (!runtime->Storage.SetValue(id, &val, sizeof(val)))
    {
        printf_s("failed to set value with id 0\n");
        return false;
    }
    return true;
}

static bool TestStorage_GetValue()
{
    return true;
}

static bool TestStorage_GetPointer()
{
    return true;
}

static bool TestStorage_Delete()
{
    return true;
}

static bool TestStorage_DeleteAll()
{
    return true;
}
