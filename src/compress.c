#include "c_types.h"
#include "lib_memory.h"
#include "lib_match.h"
#include "compress.h"

#define MIN_MATCH_LENGTH 3
#define MAX_MATCH_LENGTH 18

#define DEFAULT_WINDOW_SIZE 512
#define MAXIMUM_WINDOW_SIZE 4096

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
            integer idx = MatchBytes(window, winLen, input + srcPtr, l);
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
            output[dstPtr+0] = (byte)(mark >> 0);
            output[dstPtr+1] = (byte)(mark >> 8);
            dstPtr += 2;
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
    } else {
        dstPtr--; // rollback pointer
    }
    return dstPtr;
}

uint Decompress(void* dst, void* src, uint len)
{
    byte* output = (byte*)dst;
    byte* input  = (byte*)src;
    integer dataLen = (integer)len;

    bool flag[8];
    mem_init(flag, sizeof(flag));
    integer flagIdx = 8;

    integer dstPtr = 0;
    integer srcPtr = 0;
    while (srcPtr < dataLen)
    {
        // check need read flag block
        if (flagIdx == 8) 
        {
            byte b = input[srcPtr];
            flag[0] = (b & (1 << 7)) != 0;
            flag[1] = (b & (1 << 6)) != 0;
            flag[2] = (b & (1 << 5)) != 0;
            flag[3] = (b & (1 << 4)) != 0;
            flag[4] = (b & (1 << 3)) != 0;
            flag[5] = (b & (1 << 2)) != 0;
            flag[6] = (b & (1 << 1)) != 0;
            flag[7] = (b & (1 << 0)) != 0;
            srcPtr++;
            flagIdx = 0;
        }
        if (flag[flagIdx])
        {
            uint16 mark = *(uint16*)(input+srcPtr);
            integer offset = (integer)((mark >> 4) + 1);
            integer length = (integer)((mark & 0xF) + MIN_MATCH_LENGTH);
            integer start = dstPtr - offset;
            mem_copy(output + dstPtr, output + start, length);
            srcPtr += 2;
            dstPtr += length;
        } else {
            output[dstPtr] = input[srcPtr];
            srcPtr++;
            dstPtr++;
        }
        // update flag index
        flagIdx++;
    }
    return dstPtr;
}
