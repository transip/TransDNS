/**
 *
 *
 */

#ifndef _MISC_H
#define _MISC_H

#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// this table maps each ascii char to a lowercase version of it
// and is binary safe.
const unsigned char LOWERCASE[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
    110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
    91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
    106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
    118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
    130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141,
    142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153,
    154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166,
    167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192,
    193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205,
    206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218,
    219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231,
    232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
    245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

inline char* skip_whitespace(char* ptr)
{
    while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n')
        ptr++;

    return ptr;
}

inline char* skip_nonwhitespace(char* ptr)
{
    while (*ptr != '\0' && *ptr != ' ' && *ptr != '\t' && *ptr != '\n')
        ptr++;

    return ptr;
}

char* read_string_nowhitespace(char* ptr, char* buf, int buf_len);

inline bool is_hex_digit(char c);
inline int hexchar_to_value(char c);
inline int hex_to_byte(char major, char minor);
int read_hex_encoded_nowhitespace(char*& ptr, char* buf, int buf_len);
int read_hex_encoded(char*& ptr, char* buf, int buf_len);

unsigned long custom_timegm(const struct tm* tm);
unsigned long expiration_time_from_string(char* ptr, char** next_ptr);

// socket helpers
const char* address_from_sockaddr_storage(const struct sockaddr_storage* saddr, char* buf, size_t len);

#endif //_MISC_H
