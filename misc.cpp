/**
 * Dumping ground for miscellaneous functions that
 * don't depend on anything other.
 */

#include "misc.h"
#include <time.h>

// custom timegm function that has way better performance,
// converts a tm struct to a unix epoch timestamp (utc)
unsigned long custom_timegm(const struct tm* tm)
{
    const int num_days_offset_for_month[] = {
        0,
        31,
        31 + 28,
        31 + 28 + 31,
        31 + 28 + 31 + 30,
        31 + 28 + 31 + 30 + 31,
        31 + 28 + 31 + 30 + 31 + 30,
        31 + 28 + 31 + 30 + 31 + 30 + 31,
        31 + 28 + 31 + 30 + 31 + 30 + 31 + 31,
        31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30,
        31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31,
        31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30
    };

    long years, days, leaps, hours, year_for_leap;
    int i, is_before_possible_leapday;

    years = tm->tm_year - 70; // tm_year starts at 1900

    is_before_possible_leapday = tm->tm_mon < 1 || (tm->tm_mon == 1 && tm->tm_mday <= 29);
    year_for_leap = is_before_possible_leapday ? years - 1 : years; // if we are before a possible leap day in the current year,
    // don't take this years leapday into account, since it won't
    // affect days before 29 feb.

    leaps = (year_for_leap + 2) / 4;
    i = (year_for_leap + 70 - 100) / 100;
    leaps -= ((i / 4) * 3 + i % 4);

    days = num_days_offset_for_month[tm->tm_mon];

    days += tm->tm_mday - 1; // days of month passed
    days = days + (years * 365) + leaps;

    hours = tm->tm_hour;
    return (days * 86400) + (hours * 3600) + (tm->tm_min * 60) + tm->tm_sec;
}

char* read_string_nowhitespace(char* ptr, char* buf, int buf_len)
{
    int len;
    char* next_ptr;

    ptr = skip_whitespace(ptr);
    next_ptr = skip_nonwhitespace(ptr);

    len = next_ptr - ptr;
    if (len > 0) {
        if (len > buf_len - 1)
            len = buf_len - 1;

        memmove(buf, ptr, len);
        buf[len] = '\0';
    } else if (buf_len > 0)
        buf[0] = '\0';

    return next_ptr;
}

inline bool is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

inline int hexchar_to_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else
        return -1;
}

inline int hex_to_byte(char major, char minor)
{
    return hexchar_to_value(major) * 16 + hexchar_to_value(minor);
}

int read_hex_encoded_nowhitespace(char*& ptr, char* buf, int buf_len)
{
    int len = 0;
    char major, minor;

    ptr = skip_whitespace(ptr);
    if (*ptr == '-') {
        len = 0;
        ptr++;
    } else {
        while (1) {
            major = LOWERCASE[(unsigned char)*ptr];
            minor = LOWERCASE[(unsigned char)(*(ptr + 1))];
            if (!is_hex_digit(major) || !is_hex_digit(minor))
                break;

            if (len >= buf_len)
                break;

            buf[len] = hex_to_byte(major, minor);
            ++len;
            ptr += 2;
            ptr = skip_whitespace(ptr);
        }

        ptr = skip_nonwhitespace(ptr);
    }

    return len;
}

int read_hex_encoded(char*& ptr, char* buf, int buf_len)
{
    int len = 0;
    char major, minor;

    ptr = skip_whitespace(ptr);
    if (*ptr == '-') {
        len = 0;
        ptr++;
    } else {
        while (1) {
            major = LOWERCASE[(unsigned char)*ptr];
            minor = LOWERCASE[(unsigned char)(*(ptr + 1))];
            if (!is_hex_digit(major) || !is_hex_digit(minor))
                break;

            if (len >= buf_len)
                break;

            buf[len] = hex_to_byte(major, minor);
            ++len;
            ptr += 2;
        }

        ptr = skip_nonwhitespace(ptr);
    }

    return len;
}

unsigned long expiration_time_from_string(char* ptr, char** next_ptr)
{
    unsigned long result = 0;

    ptr = skip_whitespace(ptr);
    *next_ptr = skip_nonwhitespace(ptr);

    //according to RFC it's either the format below, or it's a counter
    if (*next_ptr - ptr == 14) {
        // YYYYMMDDHHmmSS notation
        char Y[5], M[3], D[3], H[3], m[3], S[3];
        struct tm tm;

        memcpy(Y, ptr + 0, 4);
        Y[4] = '\0';
        memcpy(M, ptr + 4, 2);
        M[2] = '\0';
        memcpy(D, ptr + 6, 2);
        D[2] = '\0';
        memcpy(H, ptr + 8, 2);
        H[2] = '\0';
        memcpy(m, ptr + 10, 2);
        m[2] = '\0';
        memcpy(S, ptr + 12, 2);
        S[2] = '\0';

        tm.tm_year = atoi(Y) - 1900;
        tm.tm_mon = atoi(M) - 1;
        tm.tm_mday = atoi(D);
        tm.tm_hour = atoi(H);
        tm.tm_min = atoi(m);
        tm.tm_sec = atoi(S);

        result = custom_timegm(&tm);
    } else {
        result = strtol(ptr, next_ptr, 10);
    }

    return result;
}

const char* address_from_sockaddr_storage(const struct sockaddr_storage* saddr, char* buf, size_t len)
{
    if (saddr->ss_family == AF_INET6) {
        struct sockaddr_in6* sock_in = (sockaddr_in6*)saddr;
        inet_ntop(AF_INET6, (void*)&sock_in->sin6_addr, buf, len);
    } else {
        struct sockaddr_in* sock_in = (sockaddr_in*)saddr;
        inet_ntop(AF_INET, (void*)&sock_in->sin_addr, buf, len);
    }

    return buf;
}
