#include "c_types.h"
#include "lib_memory.h"
#include "lib_match.h"

integer burteForce(byte* s, integer ns, byte* sep, integer nsep);

#pragma optimize("t", on)

integer MatchByte(byte* s, integer ns, byte b)
{
    for (integer i = 0; i < ns; i++)
    {
        if (s[i] == b)
        {
            return i;
        }
    }
    return -1;
}

__declspec(noinline)
integer MatchBytes(byte* s, integer ns, byte* sep, integer nsep)
{
    if (nsep == 0)
    {
        return 0;
    }
    if (nsep == 1)
    {
        return MatchByte(s, ns, *sep);
    }
    if (nsep == ns)
    {
        if (mem_equal(s, sep, ns))
        {
            return 0;
        }
        return -1;
    }
    if (nsep > ns)
    {
        return -1;
    }
    // use brute force if data is too small
    if (ns <= 64)
    {
        return burteForce(s, ns, sep, nsep);
    }
    byte b0 = sep[0];
    byte b1 = sep[1];
    integer i = 0;
    integer t = ns - nsep + 1;
    while (i < t)
    {
        // search the first same byte
        if (s[i] != b0)
        {
            integer o = MatchByte(s+(i+1), t-(i+1), b0);
            if (o < 0)
            {
                return -1;
            }
            i += o + 1;
        }
        // compare the second byte
        if (s[i + 1] != b1)
        {
            i++;
            continue;
        }
        // compare the total data
        if (mem_equal(s+(i+2), sep+2, nsep-2))
        {
            return i;
        }
        i++;
    }
    return -1;
}

integer burteForce(byte* s, integer ns, byte* sep, integer nsep)
{
    for (integer i = 0; i < (ns - nsep + 1); i++)
    {
        if (mem_equal(s+i, sep, nsep))
        {
            return i;
        }
    }
    return -1;
}

#pragma optimize("t", off)
