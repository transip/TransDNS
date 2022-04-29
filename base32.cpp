/**
 * Base32 conversion routines
 */

#include "base32.h"
#include <memory.h>
#include <stdio.h>
#include <string.h>

int base32_encode(unsigned char const* src, int srclength, char* target, int targsize)
{
    static char b32[] = "0123456789abcdefghijklmnopqrstuv";
    char buf[9];
    int len = 0;

    while (srclength > 0) {
        int t;
        memset(buf, '\0', sizeof buf);

        /* xxxxx000 00000000 00000000 00000000 00000000 */
        buf[0] = b32[src[0] >> 3];

        /* 00000xxx xx000000 00000000 00000000 00000000 */
        t = (src[0] & 7) << 2;
        if (srclength > 1)
            t += src[1] >> 6;
        buf[1] = b32[t];
        if (srclength == 1)
            break;

        /* 00000000 00xxxxx0 00000000 00000000 00000000 */
        buf[2] = b32[(src[1] >> 1) & 0x1f];

        /* 00000000 0000000x xxxx0000 00000000 00000000 */
        t = (src[1] & 1) << 4;
        if (srclength > 2)
            t += src[2] >> 4;
        buf[3] = b32[t];
        if (srclength == 2)
            break;

        /* 00000000 00000000 0000xxxx x0000000 00000000 */
        t = (src[2] & 0xf) << 1;
        if (srclength > 3)
            t += src[3] >> 7;
        buf[4] = b32[t];
        if (srclength == 3)
            break;

        /* 00000000 00000000 00000000 0xxxxx00 00000000 */
        buf[5] = b32[(src[3] >> 2) & 0x1f];

        /* 00000000 00000000 00000000 000000xx xxx00000 */
        t = (src[3] & 3) << 3;
        if (srclength > 4)
            t += src[4] >> 5;
        buf[6] = b32[t];
        if (srclength == 4)
            break;

        /* 00000000 00000000 00000000 00000000 000xxxxx */
        buf[7] = b32[src[4] & 0x1f];

        if (targsize < 8)
            return -1;

        src += 5;
        srclength -= 5;
        memcpy(target, buf, 8);

        target += 8;
        targsize -= 8;
        len += 8;
    }
    if (srclength) {
        if (targsize < strlen(buf) + 1)
            return -1;
        strncpy(target, buf, targsize);
        target[strlen(buf)] = '\0';
        len += strlen(buf);
    } else if (targsize < 1)
        return -1;
    else
        *target = '\0';
    return len;
}

int base32_decode(const char* str, unsigned char* output, int output_len)
{
    char c;
    int bits_read = 0;

    memset(output, 0, output_len);
    while ((c = *str++)) {
        // 5 bits input map onto 8 bits output
        if (bits_read + 5 >= output_len * 8)
            return 0;

        unsigned char value;

        if (c >= '0' && c <= '9')
            value = c - '0' + 0;
        else if (c >= 'A' && c <= 'V')
            value = c - 'A' + 10;
        else if (c >= 'a' && c <= 'v')
            value = c - 'a' + 10;
        else
            return 0;

        int bits = 7 - bits_read % 8;
        int byte = bits_read / 8;

        if (bits >= 4) {
            output[byte] |= value << (bits - 4);
        } else {
            output[byte] |= value >> (4 - bits);
            output[byte + 1] |= value << (bits + 4);
        }

        bits_read += 5;
    }

    return (bits_read + 7) / 8; // round up
}
