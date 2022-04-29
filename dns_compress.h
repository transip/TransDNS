#ifndef __DNS_COMPRESS_C
#define __DNS_COMPRESS_C

#include "dns.h"
#include <memory.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

//#define DEBUG

#ifdef DEBUG
#define RIP(msg)          \
    do {                  \
        printf(msg "\n"); \
        exit(0);          \
    } while (0)
#define DBG_MSG(msg, ...) printf(msg "\n", __VA_ARGS__);
#else
#define RIP(msg)
#define DBG_MSG(msg, ...)
#endif

typedef char byte;
typedef unsigned short uint16;
typedef char* zstring;
#define offset_buffer(buffer, offset, type) (*(type*)((byte*)(buffer) + (offset)))
#define COUNTOF(x) (sizeof(x) / sizeof((x)[0]))

#define DNS_MAX_NAME_PART 63
#define COMPRESS_DICT_LEN 8096
#define DNS_ENCODE_COMPRESSED_PTR(offset) (1 << 15 | 1 << 14 | ((unsigned short)offset))

#define DNS_COMPRESS_FAILURE_INVALID_NAME_LENGTH -2

typedef struct
{
    zstring name; // a known dns name
    size_t len; // the length of the dns name
    size_t offset; // the offset in the work buffer of the dns name
} dictionary_entry;

/**
 * @param byte* the data of the package to compress
 * @param size_t len in the length of the package data
 * @param byte* out a buffer that will receive the compressed package,
 *                  must be at least len_in bytes long
 * @param size_t* len_out a pointer to a variable that will receive the  real 
 *                          size of the compressed buffer
 * @return int 0 on success, any other value on failure
 */
int compress_package(byte* in, size_t len_in, byte* out, size_t* len_out);

#endif //__DNS_COMPRESS_C
