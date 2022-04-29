/**
 * Utility functions for DNS
 */

#include "dns_util.h"
#include <algorithm>
#include <memory.h>

/**
 * Counts the number of labels in a Dns name.
 *
 * @param char* name the dns name to count the label from
 * @return int the number of labels in the dns name.
 * @note that the root name (".") does not have any labels
 */
int dns_util::count_name_labels(const char* name)
{
    int num_labels = 0;
    while (*name != 0) {
        name += ((unsigned char)*name) + 1;
        num_labels++;
    }

    return num_labels;
}

/**
 * Compares the text of the 2 dns labels without taking the case into account.
 * The length of both texts must be the same.
 *
 * Use this function instead of strcmpi because there is a difference between canonical ordering
 * and our string is not NULL terminated.
 * 
 * @param const char* a the first label text to compare
 * @param const char* b the second label text to compare
 * @param int len the length of both labels
 * @return <0 if a<b, 0 if a==b, >0 if a>b
 */
int dns_util::cmp_label_text(const char* a, const char* b, int len)
{
    for (int i = 0; i < len; ++i) {
        unsigned char c_a = LOWERCASE[(unsigned char)*a];
        unsigned char c_b = LOWERCASE[(unsigned char)*b];
        if (c_a < c_b)
            return -1;
        if (c_a > c_b)
            return 1;

        a++;
        b++;
    }

    return 0;
}

/**
 * Compares 2 dns labels, the labels must start with the
 * length byte
 *
 * @param char* a the first label to compare
 * @param char* b the second label to compare
 * @return <0 if a<b, 0 if a==b, >0 if a>b
 */
inline int dns_util::cmp_label(const char* a, const char* b)
{
    if (((unsigned char)*a) < ((unsigned char)*b))
        return -1;
    else if (((unsigned char)*a) > ((unsigned char)*b))
        return 1;
    else
        //XYZ       return cmp_label_text(a+1, b+1, std::min(*a, *b));
        return cmp_label_text(a + 1, b + 1, (unsigned char)*a); //*a == *b
}

/**
 * Compares 2 dns labels canonically, the labels must start with the
 * length byte
 *
 * @param char* a the first label to compare
 * @param char* b the second label to compare
 * @return <0 if a<b, 0 if a==b, >0 if a>b
 */
inline int dns_util::cmp_label_canonical(const char* a, const char* b)
{
    int res = cmp_label_text(a + 1, b + 1, std::min(*a, *b));
    if (res != 0)
        return res; // xyz != abc
    if (((unsigned char)*a) < ((unsigned char)*b))
        return -1; // xxx < xxxA
    if (((unsigned char)*a) > ((unsigned char)*b))
        return 1; // xxxA > xxx
    return 0;
}

/**
 * Skips a Dns name to the requested label, offsetted to the left
 *
 * @param char* name the dns name to get the offset in the label to
 * @param int offset_left the label from the left to get back
 * @return char* the dns name offsetted to the requested label
 */
inline const char* dns_util::skip_to_label(const char* name, int offset_left)
{
    while (*name != 0 && --offset_left > 0)
        name += ((unsigned char)*name) + 1;

    return name;
}

/**
 * Compares two labels in a dns name, offsetted from the right
 *
 * @param char* a the first dns name to compare the label from
 * @param int num_label_a the number of labels in dns name a
 * @param char* b the second dns name to compare a label from
 * @param int num_labels_b  the number of labels in dns name b
 * @param int right_offset the label to compare, offsetted from the right
 * @return <0 if label(a)<label(b), 0 if the label in label(a)==label(b), >0 if the label in a>label(b)
 */
int dns_util::cmp_label_in_name_from_right(const char* a, int num_labels_a,
    const char* b, int num_labels_b, int right_offset)
{
    a = skip_to_label(a, num_labels_a - right_offset);
    b = skip_to_label(b, num_labels_b - right_offset);

    return cmp_label_canonical(a, b);
}

/**
 * Compares two dns names canonically
 *
 * @param string char* a the first name to compare
 * @param string char* b the second name to compare
 * @return -1 if a < b, 0 if a == b, 1 if a > b
 */
int dns_util::cmp_names_canonical(const char* a, const char* b)
{
    int num_labels_a = count_name_labels(a);
    int num_labels_b = count_name_labels(b);
    int num_min_labels = std::min(num_labels_a, num_labels_b);

    for (int i = 0; i < num_min_labels; ++i) {
        int res = cmp_label_in_name_from_right(a, num_labels_a, b, num_labels_b, i);
        if (res != 0)
            return res;
    }

    return num_labels_a < num_labels_b ? -1 : num_labels_b < num_labels_a ? 1 : 0;
}

bool dns_util::matches_label_or_wildcard(const char* a, const char* b)
{
    //*a == *b = optimalisation, it saves us a function call in a lot of cases.
    return (*a == 1 && *(a + 1) == '*') || (*a == *b && cmp_label(a, b) == 0);
}

bool dns_util::matches_name(const char* a, const char* b)
{
    //(*a == *b) = optimalisation, it saves us a function call in a lot of cases.
    while (*a != 0 && *b != 0 && (*a == *b) && cmp_label(a, b) == 0) {
        a += *a + 1;
        b += *b + 1;
    }

    return *a == 0 && *b == 0;
}

bool dns_util::matches_name_or_wildcard(const char* a, const char* b)
{
    while (*a != 0 && *b != 0 && matches_label_or_wildcard(a, b)) {
        a += *a + 1;
        b += *b + 1;
    }

    return *a == 0 && *b == 0;
}

#ifdef _AVE_DEBUG_DNS_UTIL
#include <stdio.h>
int main()
{
    char* a = "\1*\4test\7example\3com\0";
    char* b = "\1y\3tes\7example\3com\0";

    int res = dns_util::cmp_names_canonical(a, b);
    printf("%u\n", res);
}
#endif //_AVE_DEBUG_DNS_UTIL
