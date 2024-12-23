#include <stdio.h>
#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_winhttp.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "errno.h"
#include "win_http.h"
#include "runtime.h"
#include "test.h"

static bool TestWinHTTP_Get();
static bool TestWinHTTP_Post();
static bool TestWinHTTP_Free();

bool TestRuntime_WinHTTP()
{
    test_t tests[] = 
    {
        { TestWinHTTP_Get  },
        { TestWinHTTP_Post },
        { TestWinHTTP_Free },
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

static bool TestWinHTTP_Get()
{
    UTF16 URL = L"http://127.0.0.1:8001/hello.txt";
    HTTP_Resp resp;

    errno err = runtime->WinHTTP.Get(URL, NULL, &resp);
    if (err != NO_ERROR)
    {
        printf_s("failed to get: 0x%X\n", err);
        return false;
    }

    if (resp.Body.Size != 5)
    {
        printf_s("invalid response body size: %zu\n", resp.Body.Size);
        return false;
    }
    if (strncmp_a(resp.Body.Buf, "hello", 5) != 0)
    {
        printf_s("invalid response body\n");
        return false;
    }
    printf_s("response size: %zu\n", resp.Body.Size);
    printf_s("response body: %s\n", (byte*)resp.Body.Buf);

    runtime->Memory.Free(resp.Body.Buf);

    printf_s("test Get passed\n");
    return true;
}

static bool TestWinHTTP_Post()
{
    UTF16 URL  = L"http://127.0.0.1:8001/hello.txt";
    ANSI  data = "test body data";
    HTTP_Body body = {
        .Buf  = data,
        .Size = strlen_a(data),
    };
    HTTP_Resp resp;

    errno err = runtime->WinHTTP.Post(URL, &body, NULL, &resp);
    if (err != NO_ERROR)
    {
        printf_s("failed to post: 0x%X\n", err);
        return false;
    }

    if (resp.Body.Size != 5)
    {
        printf_s("invalid response body size: %zu\n", resp.Body.Size);
        return false;
    }
    if (strncmp_a(resp.Body.Buf, "hello", 5) != 0)
    {
        printf_s("invalid response body\n");
        return false;
    }
    printf_s("response size: %zu\n", resp.Body.Size);
    printf_s("response body: %s\n", (byte*)resp.Body.Buf);

    runtime->Memory.Free(resp.Body.Buf);

    printf_s("test Post passed\n");
    return true;
}

static bool TestWinHTTP_Free()
{
    errno err = runtime->WinHTTP.Free();
    if (err != NO_ERROR)
    {
        printf_s("failed to free: 0x%X\n", err);
        return false;
    }

    printf_s("test Free passed\n");
    return true;
}
