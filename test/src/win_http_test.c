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
static bool TestWinHTTP_Do();
static bool TestWinHTTP_Free();

bool TestRuntime_WinHTTP()
{
    test_t tests[] = 
    {
        { TestWinHTTP_Get  },
        { TestWinHTTP_Post },
        { TestWinHTTP_Do   },
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
    HTTP_Request req;
    runtime->WinHTTP.Init(&req);
    req.URL = L"http://127.0.0.1:8001/hello.txt";

    HTTP_Response resp;
    errno err = runtime->WinHTTP.Get(&req, &resp);
    if (err != NO_ERROR)
    {
        printf_s("failed to get: 0x%X\n", err);
        return false;
    }

    if (resp.StatusCode != 200)
    {
        printf_s("invalid status code: %d\n", resp.StatusCode);
        return false;
    }
    printf_s("Headers:\n%ls", resp.Headers);

    if (resp.Body.len != 5)
    {
        printf_s("invalid response body size: %zu\n", resp.Body.len);
        return false;
    }
    if (strncmp_a(resp.Body.buf, "hello", 5) != 0)
    {
        printf_s("invalid response body\n");
        return false;
    }
    printf_s("response body: %s\n", (byte*)(resp.Body.buf));
    printf_s("response size: %zu\n", resp.Body.len);

    runtime->Memory.Free(resp.Headers);
    runtime->Memory.Free(resp.Body.buf);

    printf_s("test Get passed\n");
    return true;
}

static bool TestWinHTTP_Post()
{
    ANSI data = "test body data";
    databuf body = {
        .buf = data,
        .len = strlen_a(data),
    };

    HTTP_Request req;
    runtime->WinHTTP.Init(&req);
    req.URL  = L"http://127.0.0.1:8001/hello.txt";
    req.Body = &body;

    HTTP_Response resp;
    errno err = runtime->WinHTTP.Post(&req, &resp);
    if (err != NO_ERROR)
    {
        printf_s("failed to post: 0x%X\n", err);
        return false;
    }

    if (resp.StatusCode != 200)
    {
        printf_s("invalid status code: %d\n", resp.StatusCode);
        return false;
    }
    printf_s("Headers:\n%ls", resp.Headers);

    if (resp.Body.len != 5)
    {
        printf_s("invalid response body size: %zu\n", resp.Body.len);
        return false;
    }
    if (strncmp_a(resp.Body.buf, "hello", 5) != 0)
    {
        printf_s("invalid response body\n");
        return false;
    }
    printf_s("response body: %s\n", (byte*)(resp.Body.buf));
    printf_s("response size: %zu\n", resp.Body.len);

    runtime->Memory.Free(resp.Headers);
    runtime->Memory.Free(resp.Body.buf);

    printf_s("test Post passed\n");
    return true;
}

static bool TestWinHTTP_Do()
{
    // set headers
    // set user-agent
    // set proxy url
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
