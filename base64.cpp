/**
 * Base64 code
 */

#include "base64.h"
#include <stdlib.h>
#include <string.h>

int base64_decode_basic(const char* in, int len, char* out, int outlen);
int base64_decode_fast(const char* in, int len, char* out, int outlen);
void base64_setup_large_lookup_table();

int base64_decode(const char* in, int len, char* out, int outlen)
{
    return base64_decode_basic(in, len, out, outlen);
}

typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned char uint8;

static uint16* large_lookup_table = NULL;

#define base64_fast_decode_part(src, b1, b2, b3) \
    uint16 s1 = large_lookup_table[src[0]];      \
    uint16 s2 = large_lookup_table[src[1]];      \
                                                 \
    uint32 n32;                                  \
    n32 = s1;                                    \
    n32 <<= 10;                                  \
    n32 |= s2 >> 2;                              \
                                                 \
    b3 = n32 & 0x00FF;                           \
    n32 >>= 8;                                   \
    b2 = n32 & 0x00FF;                           \
    n32 >>= 8;                                   \
    b1 = n32 & 0x00FF;                           \
                                                 \
    src += 2;

// XXX this version doesn't work correctly with embedded spaces, yet: cannot be used
int base64_decode_fast(const char* in, int len, char* out, int outlen)
{
    if (NULL == large_lookup_table)
        base64_setup_large_lookup_table();

    if (outlen < ((len / 4) - 1) * 3)
        return 0;

    int loop_max = (len / 4) - 1;
    uint16* src = (uint16*)in;
    for (int i = 0; i < loop_max; ++i) {
        uint8 b1, b2, b3;
        base64_fast_decode_part(src, b1, b2, b3);

        out[0] = b1;
        out[1] = b2;
        out[2] = b3;

        src += 2;
        out += 3;
    }

    int len_out = ((len / 4) - 1) * 3;

    uint8 b1, b2, b3;
    base64_fast_decode_part(src, b1, b2, b3);

    if (len_out >= outlen)
        return 0;

    *out++ = b1;
    len_out++;
    if (b2 != 99) {
        if (len_out >= outlen)
            return 0;
        *out++ = b2;
        len_out++;
    }

    if (b3 != 99) {
        if (len_out >= outlen)
            return 0;

        *out++ = b3;
        len_out++;
    }

    return len_out;
}

static uint8 lookup_digits[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //gap: ctrl chars
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //gap: ctrl chars
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //gap: spc,!"#$%'()*
    62, // +
    0, 0, 0, // gap ,-.
    63, // /
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // 0-9
    0, 0, 0, // gap: :;<
    99, //  = (end padding)
    0, 0, 0, // gap: >?@
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, // A-Z
    0, 0, 0, 0, 0, 0, // gap: [\]^_`
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, // a-z
    0, 0, 0, 0, // gap: {|}~ (and the rest...)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void base64_setup_large_lookup_table()
{
    int len = 256 * 256;
    if (NULL == large_lookup_table)
        large_lookup_table = (uint16*)malloc(len * sizeof(uint16));

    uint16* p = large_lookup_table;
    for (int i = 0; i < 256; ++i) {
        for (int x = 0; x < 256; ++x) {
            uint16 w;
            w = lookup_digits[x] << 8;
            w |= lookup_digits[i] << 2; // pre-shifted
            *p++ = w;
        }
    }
}

static const unsigned char map[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255,
    255, 254, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6,
    7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
    37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255
};

int base64_decode_basic(const char* in, int len,
    char* out, int outlen)
{
    unsigned long t, x, y, z;
    unsigned char c;
    int g;

    g = 3;
    for (x = y = z = t = 0; x < len; x++) {
        c = map[in[x] & 0xFF];
        if (c == 255)
            continue;
        if (c == 254) {
            c = 0;
            g--;
        }
        t = (t << 6) | c;
        if (++y == 4) {
            if (z + g > outlen) {
                return 0;
            }
            out[z++] = (unsigned char)((t >> 16) & 255);
            if (g > 1)
                out[z++] = (unsigned char)((t >> 8) & 255);
            if (g > 2)
                out[z++] = (unsigned char)(t & 255);
            y = t = 0;
        }
    }

    if (y != 0) {
        return 0;
    }

    return z;
}
