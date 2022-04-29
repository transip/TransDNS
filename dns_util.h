/**
 * Utility functions for DNS
 */

#include "dns.h"

class dns_util {
public:
    static int cmp_label_in_name_from_right(const char* a, int num_labels_a, const char* b, int num_labels_b, int right_offset);
    static inline const char* skip_to_label(const char* name, int offset_left);

    /**
     * Counts the number of labels in a Dns name.
     *
     * @param char* name the dns name to count the label from
     * @return int the number of labels in the dns name.
     * @note that the root name (".") does not have any labels
     */
    static int count_name_labels(const char* name);

    /**
     * Compares 2 dns labels, the labels must start with the
     * length byte
     *
     * @param char* a the first label to compare
     * @param char* b the second label to compare
     * @return <0 if a<b, 0 if a==b, >0 if a>b
     */
    static inline int cmp_label(const char* a, const char* b);

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
    static int cmp_label_text(const char* a, const char* b, int len);

    /**
     * Compares 2 dns labels canonically, the labels must start with the
     * length byte
     *
     * @param char* a the first label to compare
     * @param char* b the second label to compare
     * @return <0 if a<b, 0 if a==b, >0 if a>b
     */
    static inline int cmp_label_canonical(const char* a, const char* b);

    /**
     * Compares two dns names canonically
     *
     * @param string char* a the first name to compare
     * @param string char* b the second name to compare
     * @return -1 if a < b, 0 if a == b, 1 if a > b
     */
    static int cmp_names_canonical(const char* a, const char* b);

    static bool matches_name(const char* a, const char* b);
    static bool matches_label_or_wildcard(const char* a, const char* b);
    static bool matches_name_or_wildcard(const char* a, const char* b);
};
