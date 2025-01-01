#include "c_types.h"
#include "lib_memory.h"
#include "compress.h"

#define MIN_MATCH_LENGTH 3
#define MAX_MATCH_LENGTH 18

#define DEFAULT_WINDOW_SIZE 512
#define MAXIMUM_WINDOW_SIZE 4096

integer find(byte* s, uint ns, byte* sep, uint nsep);

uint Compress(void* dst, void* src, uint len, uint win)
{
    if (win > MAXIMUM_WINDOW_SIZE)
    {
        return (uint)(-1);
    }
    if (win == 0)
    {
        win = DEFAULT_WINDOW_SIZE;
    }
    byte* output = (byte*)dst;
    byte* input  = (byte*)src;

    integer dataLen = (integer)len;
    integer winSize = (integer)win;

    byte* window = (byte*)src;
    uint  winLen = 0;

    // initialize flag block;
    output[0] = 0;
    byte flag = 0;
    integer flagPtr = 0;
    integer flagCtr = 0;

    integer srcPtr = 0;
    integer dstPtr = 1;
    while (srcPtr < dataLen)
    {
        integer rem = dataLen - srcPtr;
        // search the same data in current window
        integer offset = 0;
        integer length = 0;
        for (integer l = MIN_MATCH_LENGTH; l <= MAX_MATCH_LENGTH; l++)
        {
			if (rem < l)
            {
                break;
			}
            integer idx = find(window, winLen, input + srcPtr, l);
			if (idx == -1)
            {
                break;
			}
            offset = winLen - idx - 1;
			length = l;
		}
        // set compress flag and write data
		if (length != 0)
        {
            flag |= 1;
			// 12 bit = offset, 4 bit = length
			// offset max is 4095, max length value is [0-15] + 3
            uint16 mark = (uint16)((offset << 4) + (length - MIN_MATCH_LENGTH));
            // encode mark to buffer
            output[dstPtr+0] = (byte)(mark >> 8);
            output[dstPtr+1] = (byte)(mark >> 0);
            dstPtr+=2;
		} else {
            output[dstPtr] = input[srcPtr];
			dstPtr++;
		}
        // update flag block
		if (flagCtr == 7) 
        {
            output[flagPtr] = flag;
			// update pointer
            flagPtr = dstPtr;
            dstPtr++;
			// reset status
            flag = 0;
            flagCtr = 0;
		} else {
            flag <<= 1;
            flagCtr++;
		}
		// update source pointer
		if (length != 0) 
        {
            srcPtr += length;
		} else {
            srcPtr++;
		}
		// update window
        integer start = srcPtr - winSize;
		if (start < 0)
        {
            start = 0;
		} 
        window = input + start;
        winLen = srcPtr - start;
    }
	// process the final flag block
	if (flagCtr != 0) 
    {
        flag <<= (byte)(7 - flagCtr);
        output[flagPtr] = flag;
	}
    return dstPtr;
}

uint Decompress(void* dst, void* src, uint len)
{
    return 0;
}

integer find(byte* s, uint ns, byte* sep, uint nsep)
{
    for (integer i = 0; i < (integer)ns - (integer)nsep +1 ; i++)
    {
        if (mem_equal(s, sep, nsep))
        {
            return i;
        }
        s++;
    }
    return -1;
}
