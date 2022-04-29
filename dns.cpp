#include "dns.h"
#include "base32.h"
#include "base64.h"
#include "dns_util.h"
#include <algorithm>
#include <arpa/inet.h>
#include <functional>
#include <netinet/in.h>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

using namespace std;

struct dns_name_mapping {
    const char* name;
    int type;
};

static dns_name_mapping dns_name_mapping_table[] = {
    { "A", DNS_TYPE_A },
    { "NS", DNS_TYPE_NS },
    { "MD", DNS_TYPE_MD },
    { "MF", DNS_TYPE_MF },
    { "CNAME", DNS_TYPE_CNAME },
    { "SOA", DNS_TYPE_SOA },
    { "MB", DNS_TYPE_MB },
    { "MG", DNS_TYPE_MG },
    { "MR", DNS_TYPE_MR },
    { "NULL", DNS_TYPE_NULL },
    { "WKS", DNS_TYPE_WKS },
    { "PTR", DNS_TYPE_PTR },
    { "HINFO", DNS_TYPE_HINFO },
    { "MINFO", DNS_TYPE_MINFO },
    { "MX", DNS_TYPE_MX },
    { "TXT", DNS_TYPE_TXT },
    { "RP", DNS_TYPE_RP },
    { "SIG", DNS_TYPE_SIG },
    { "KEY", DNS_TYPE_KEY },
    { "AAAA", DNS_TYPE_AAAA },
    { "LOCL", DNS_TYPE_LOC },
    { "SRV", DNS_TYPE_SRV },
    { "NAPTR", DNS_TYPE_NAPTR },
    { "CERT", DNS_TYPE_CERT },
    { "A6", DNS_TYPE_A6 },
    { "DNAME", DNS_TYPE_DNAME },
    { "OPT", DNS_TYPE_OPT },
    { "DS", DNS_TYPE_DS },
    { "SSHFP", DNS_TYPE_SSHFP },
    { "IPSECKEY", DNS_TYPE_IPSECKEY },
    { "RRSIG", DNS_TYPE_RRSIG },
    { "NSEC", DNS_TYPE_NSEC },
    { "DNSKEY", DNS_TYPE_DNSKEY },
    { "DHCID", DNS_TYPE_DHCID },
    { "NSEC3", DNS_TYPE_NSEC3 },
    { "NSEC3PARAM", DNS_TYPE_NSEC3PARAM },
    { "TLSA", DNS_TYPE_TLSA },
    { "HIP", DNS_TYPE_HIP },
    { "SPF", DNS_TYPE_SPF },
    { "AXFR", DNS_TYPE_AXFR },
    { "ANY", DNS_TYPE_ANY },
    { "CAA", DNS_TYPE_CAA },
    { NULL, 0 }
};

int dns_uint16_encode(const uint16 n, char* buf)
{
    buf[0] = n >> 8;
    buf[1] = n & 0xFF;

    return 2;
}

int dns_uint8_encode(const uint8 n, char* buf)
{
    buf[0] = n;

    return 1;
}

void dns_uint16_decode(const char* buf, uint16* n)
{
    *n = (buf[0] << 8) + (unsigned char)buf[1];
}

void dns_uint32_decode(const char* buf, uint32* n)
{
    *n = ntohl(*(uint32*)buf);
}

int dns_uint32_encode(const uint32 n, char* buf)
{
    buf[0] = ((uint16)(n >> 16)) >> 8;
    buf[1] = ((uint16)(n >> 16)) & 0xFF;
    buf[2] = ((uint16)n) >> 8;
    buf[3] = ((uint16)n) & 0xFF;

    return 4;
}

int dns_header_decode(const char* buf, struct dns_header* h)
{
    dns_uint16_decode(buf + 0, &h->id);
    dns_uint16_decode(buf + 2, &h->flags);
    dns_uint16_decode(buf + 4, &h->qdcount);
    dns_uint16_decode(buf + 6, &h->ancount);
    dns_uint16_decode(buf + 8, &h->nscount);
    dns_uint16_decode(buf + 10, &h->arcount);

    return DNS_HEADER_LENGTH;
};

int dns_header_encode(const struct dns_header& h, char* buf)
{
    dns_uint16_encode(h.id, buf + 0);
    dns_uint16_encode(h.flags, buf + 2);
    dns_uint16_encode(h.qdcount, buf + 4);
    dns_uint16_encode(h.ancount, buf + 6);
    dns_uint16_encode(h.nscount, buf + 8);
    dns_uint16_encode(h.arcount, buf + 10);

    return DNS_HEADER_LENGTH;
}

int dns_type_name_to_int(const char* type)
{
    int i;

    if (LOWERCASE[(unsigned char)type[0]] == 't' && LOWERCASE[(unsigned char)type[1]] == 'y' && LOWERCASE[(unsigned char)type[2]] == 'p' && LOWERCASE[(unsigned char)type[3]] == 'e') {
        return atoi(type + 4);
    }

    //XXX: if performance speedup is needed, we can build a array/hashmap
    for (i = 0; i < sizeof(dns_name_mapping_table) / sizeof(dns_name_mapping_table[0]); ++i) {
        if (dns_name_mapping_table[i].name != NULL && strcasecmp(dns_name_mapping_table[i].name, type) == 0) {
            return dns_name_mapping_table[i].type;
        }
    }

    return 0;
}

const char* dns_type_to_name(int type)
{
    //XXX: if performance speedup is needed, we can build a array/hashmap
    for (int i = 0; i < sizeof(dns_name_mapping_table) / sizeof(dns_name_mapping_table[0]); ++i) {
        if (dns_name_mapping_table[i].type == type) {
            return dns_name_mapping_table[i].name;
        }
    }

    return "unknown type";
}

void dns_header_print(const struct dns_header& h)
{
    printf("id: %hu\tflags: %hu\tqd: %hu\tan: %hu\tns: %hu\tar: %hu\n", h.id, h.flags, h.qdcount, h.ancount, h.nscount, h.arcount);
}

int dns_question_decode(const char* buf, const int len, struct dns_question* q)
{
    int i, j;

    for (i = 0, j = -1; i < (len - 5) && i < DNS_MAX_DOMAIN_LENGTH - 1 && buf[i] != 0; i++) {
        if (i == j + 1) { //Do consistency checking for flaky garbage packets (dns part lengths may never be longer than 63 bytes).
            if (buf[i] < 0 || buf[i] > 63)
                break;
            j += buf[i] + 1;
        }

        q->name[i] = buf[i];
    }

    if (buf[i] != 0) {
        // Garbage packet
        return 0;
    }

    q->name[i] = 0;
    q->len = i + 1;

    dns_uint16_decode(buf + i + 1, &q->qtype);
    dns_uint16_decode(buf + i + 3, &q->qclass);

    return i + 5;
}

int dns_question_encode(const struct dns_question& q, char* buf)
{
    memmove(buf, q.name, q.len);

    dns_uint16_encode(q.qtype, buf + q.len);
    dns_uint16_encode(q.qclass, buf + q.len + 2);

    return q.len + 4;
}

int dns_domain_length(const char* from, int len)
{
    int i;
    for (i = 0; i < DNS_MAX_DOMAIN_LENGTH && from[i] != 0 && i < len; ++i) {
        i += (unsigned char)from[i];
    }

    if (i >= len) {
        return 0;
    }

    return i + 1;
}

int dns_domain_decode(const char* from, char* to)
{
    int i, len;

    for (i = 0; i < DNS_MAX_DOMAIN_LENGTH && from[i] != 0; ++i) {
        len = (unsigned char)from[i];
        for (++i; len > 0 && i < DNS_MAX_DOMAIN_LENGTH; --len) {
            to[i - 1] = from[i];
            ++i;
        }
        --i;
        to[i] = '.';
    }
    if (i > 1)
        to[i - 1] = 0;
    else
        to[0] = 0;

    return i + 1;
}

void dns_question_print(const struct dns_question& q)
{
    char buf[DNS_MAX_DOMAIN_LENGTH + 1];

    dns_domain_decode(q.name, buf);
    printf("T:%hu (%s) C:%hu S:%s\n", q.qtype, dns_type_to_name(q.qtype), q.qclass, buf);
}

int dns_resource_encode(const struct dns_resource& r, const struct dns_question& q, char* buf, int buf_len)
{
    uint16 i;

    // q.len + 2 bytes type + 2 bytes class + 4 bytes ttl + 2 bytes rdlength + rdlength
    if (q.len + 2 + 2 + 4 + 2 + r.rdlength > buf_len) {
        return -1;
    }

    memmove(buf, q.name, q.len);
    i = q.len;

    dns_uint16_encode(r.rtype, buf + i);
    //dns_uint16_encode( r.rclass, buf+i+2 ); XXX hack: always use same class as question!
    dns_uint16_encode(q.qclass, buf + i + 2);
    dns_uint32_encode(r.ttl, buf + i + 4);
    dns_uint16_encode(r.rdlength, buf + i + 8);

    i += 10;
    memmove(buf + i, r.rdata, r.rdlength);

    return i + r.rdlength;
}

int dns_resource_fixed_encode(const struct dns_resource_fixed& r, const struct dns_question& q, char* buf, int buf_len)
{
    uint16 i;

    // q.len + 2 bytes type + 2 bytes class + 4 bytes ttl + 2 bytes rdlength + rdlength
    if (q.len + 2 + 2 + 4 + 2 + r.rdlength > buf_len) {
        return -1;
    }

    memmove(buf, q.name, q.len);
    i = q.len;

    dns_uint16_encode(r.rtype, buf + i);
    dns_uint16_encode(r.rclass, buf + i + 2);
    dns_uint32_encode(r.ttl, buf + i + 4);
    dns_uint16_encode(r.rdlength, buf + i + 8);

    i += 10;
    memmove(buf + i, r.rdata, r.rdlength);

    return i + r.rdlength;
}

void dns_resource_print(const struct dns_resource& r, const struct dns_question& q)
{
    char buf[DNS_MAX_DOMAIN_LENGTH + 1];

    memmove(buf, q.name, q.len);
    printf("T:%d T:%d C:%d L:%d\n%s\n%s\n", r.rtype, r.ttl, r.rclass, r.rdlength, buf, r.rdata + 2);
}

bool dns_resource_named::operator<(const dns_resource_named& that) const
{
    return dns_util::cmp_names_canonical(this->name, that.name) < 0;
}

void dns_resource::assign_from(const dns_resource& r)
{
    this->rdata = r.rdata;
    this->rtype = r.rtype;
    this->rclass = r.rclass;
    this->ttl = r.ttl;
    this->rdlength = r.rdlength;
    this->id = r.id;
}

/*const bool dns_question::operator< (const dns_question &q) const {
    register int    i;

    if( qtype!=q.qtype )
        return (qtype<q.qtype);
    //removed class; we assume to be only in IN class.

    for( i=0;name[i] && i<len;++i )
        if( name[i] != q.name[i] )
             return (name[i]<q.name[i]);

    return (name[i]<q.name[i]);
}*/

const bool dns_question::operator==(const dns_question& q) const
{
    int i;

    if (qtype != q.qtype)
        return false;
    if (len != q.len)
        return false;
    //removed class; we assume to be only in IN class.

    for (i = 0; name[i] && i < len; ++i)
        if (LOWERCASE[(unsigned char)name[i]] != LOWERCASE[(unsigned char)q.name[i]])
            return false;

    return (q.name[i] == name[i]);
}

const bool dns_domain::operator==(const dns_domain& d) const
{
    int i;

    if (len != d.len) {
        return false;
    }

    for (i = 0; name[i] && i < len; ++i) {
        if (LOWERCASE[(unsigned char)name[i]] != LOWERCASE[(unsigned char)d.name[i]]) {
            return false;
        }
    }

    return (d.name[i] == name[i]);
}

int dns_domain_encode(const char* from, char* to)
{
    int len = strlen(from);
    bool prev_is_escape = false;
    int to_index = 0;
    int last_seperator_index = 0;
    int illegal = 0;
    int i;

    char read_buffer[DNS_MAX_DOMAIN_LENGTH + 1];
    len = len < DNS_MAX_DOMAIN_LENGTH ? len : DNS_MAX_DOMAIN_LENGTH;
    memmove(read_buffer, from, len);
    read_buffer[len] = '\0';

    // we encode a domain name from readable form into wire format here,
    // so we need to take escape-chars into account.

    // The backslash (\) is used as an escape character, which
    // signals that the next character should be taken literally, instead
    // of being interpreted. E.g. \a => a, \. => . (instead of seperator).

    // The code builds the wire format by making a dummy seperator with length 0,
    // then reads characters from the input until we hit a next seperator.
    // When the next seperator is found or we are at the end, the previous seperator
    // is updated from length 0 to the length of what we have written to the wire format
    // so far. The last_seperator_index variable is used to track the position of the
    // previous seperator.

    last_seperator_index = to_index;
    to[to_index++] = '\0';

    for (i = 0; i < len; ++i) {
        char c = read_buffer[i];

        if (prev_is_escape) {
            to[to_index++] = c;
            prev_is_escape = false;
        } else {
            if (c == '\\') {
                prev_is_escape = true;
            } else {
                prev_is_escape = false;
                if (c == '.') {
                    to[last_seperator_index] = to_index - last_seperator_index - 1;

                    last_seperator_index = to_index;
                    to[to_index++] = '\0';
                } else {
                    illegal += IS_ILLEGAL[(unsigned char)c];
                    to[to_index++] = c;
                }
            }
        }
    }

    to[last_seperator_index] = to_index - last_seperator_index - 1;

    if (illegal != 0) {
        syslog(LOG_ERR, "%s contains %d illegal characters", from, illegal);
        to[0] = '\0';
        return 1; // if we have an illegal label, just return the root zone, so we
        // won't have corrupt packages (andreasv - 20100602)
    }

    // Catch root zone case where we might accidentaly give back the wrong length
    if (to[0] == '\0') {
        return 1;
    }

    return to_index;
}

int dns_ip_encode(const char* from, char* to)
{
    int a, b, c, d;

    sscanf(from, "%d.%d.%d.%d", &a, &b, &c, &d);

    to[0] = a;
    to[1] = b;
    to[2] = c;
    to[3] = d;

    return 4;
}

int dns_ip6_encode(const char* from, char* to)
{
    inet_pton(AF_INET6, from, to);

    return 16;
}

void dns_ip_decode(const char* from, char* to)
{
    sprintf(to, "%d.%d.%d.%d", from[0], from[1], from[2], from[3]);
}

int dns_txt_encode(const char* from, char* to)
{
    // textual records are split in segments of
    // max. 256 bytes, where the first byte is the length of the data that follows.
    //
    // E.g. for a string of 440 characters we get:
    // [255, 255chars], [255, 255chars], [40, 40chars]
    //
    // Since the output buffer = the input buffer,
    // we'll need to memmove the segments in reverse,
    // otherwise character data will be overwritten
    // which we still need to read

    uint16 inputLength = MIN((uint16)strlen(from), (uint16)(DNS_MAX_RDATA_LENGTH - 5)); // we can hold 1024 bytes max, with 5 segment seperators = 1019 bytes data total
    uint16 lastSegmentLength = inputLength % 255;
    uint16 numSegments = inputLength / 255;

    // fix: guard against empty txt records
    if (inputLength == 0) {
        return 0;
    }

    if (lastSegmentLength == 0) {
        lastSegmentLength = 255;
    } else {
        numSegments += 1;
    }

    int i;
    for (i = numSegments - 1; i >= 0; --i) {
        uint16 len = (i == numSegments - 1) ? lastSegmentLength : 255;
        uint16 readOffset = 255 * i;
        uint16 writeOffset = 256 * i + 1;

        memmove(to + writeOffset, from + readOffset, len);
        to[writeOffset - 1] = (char)len;
    }

    // output length = all segments of length 255 and their length byte, and the last
    //                 segment and its length byte

    int len = (numSegments - 1) * 256 + 1 + lastSegmentLength;
    len = MIN(len, (uint16)DNS_MAX_RDATA_LENGTH);
    return len;
}

int dns_mx_recode(const char* from, char* to)
{
    int pref;
    char buf[DNS_MAX_DOMAIN_LENGTH + 1];

    sscanf(from, "%d %s", &pref, buf);
    dns_uint16_encode(pref, to);

    return dns_domain_encode(buf, to + 2) + 2;
}

int dns_soa_encode(const uint32 ttl, const char* from, char* to)
{
    int len, serial, refresh, retry, expire, minimum_ttl = 0;
    char master[DNS_MAX_DOMAIN_LENGTH + 1], hostmaster[DNS_MAX_DOMAIN_LENGTH + 1];

    sscanf(from, "%s %s %u %u %u %u %u", master, hostmaster, &serial, &refresh, &retry, &expire, &minimum_ttl);
    //20080428: was (changed because serial, retry, etc. were 0): sscanf( from, "%s %s %lu %lu %lu %lu", master, hostmaster, &serial, &refresh, &retry, &expire );

    if (minimum_ttl == 0)
        minimum_ttl = ttl;

    len = dns_domain_encode(master, to);
    len += dns_domain_encode(hostmaster, to + len);
    len += dns_uint32_encode(serial, to + len); //serial
    len += dns_uint32_encode(refresh, to + len); //refresh
    len += dns_uint32_encode(retry, to + len); //retry
    len += dns_uint32_encode(expire, to + len); //expire
    len += dns_uint32_encode(minimum_ttl, to + len); //minimum ttl

    return len;
}

/**
 * (dbosschieter - 20170422)
 * CAA <flags> <tag> <value>
 *
 * Where:
 *
 * Flags:  Is an unsigned integer between 0 and 255.
 *
 * Tag:  Is a non-zero sequence of US-ASCII letters and numbers in lower
 *    case.
 *
 * Value:  Is the <character-string> encoding of the value field as
 *    specified in [RFC1035], Section 5.1.
 */
int dns_caa_encode(const char* from, char* to)
{
    uint8 flags, tag_length;
    int len;
    size_t value_length, max_value_length;
    char tag[DNS_MAX_TYPE_LENGTH + 1];
    char* ptr = (char*)from;

    flags = (uint8)strtol(ptr, &ptr, 10);
    ptr = skip_whitespace(ptr); // skip space
    ptr = read_string_nowhitespace(ptr, tag, sizeof(tag) / sizeof(tag[0]));
    tag_length = strlen(tag);

    len = dns_uint8_encode(flags, to);
    len += dns_uint8_encode(tag_length, to + len);

    // get tag part
    memmove(to + len, tag, tag_length);
    len += tag_length;

    // set the max value length
    max_value_length = DNS_MAX_RDATA_LENGTH - tag_length - 2;

    // get value part
    ptr = skip_whitespace(ptr);
    value_length = strlen(ptr);
    if (value_length > max_value_length) {
        value_length = max_value_length;
    }
    memmove(to + len, ptr, value_length);
    len += value_length;

    return len;
}

int dns_srv_encode(const char* from, char* to)
{
    int prio, weight, port, len;
    char buf[DNS_MAX_DOMAIN_LENGTH + 1];

    sscanf(from, "%d %d %d %s", &prio, &weight, &port, buf);
    len = 0;

    len += dns_uint16_encode(prio, to + len);
    len += dns_uint16_encode(weight, to + len);
    len += dns_uint16_encode(port, to + len);
    len += dns_domain_encode(buf, to + len);

    return len;
}

int dns_dnskey_encode(const char* from, char* to)
{
    int len, decoded_key_len;
    int flags;
    uint8 protocol, algorithm;
    char decoded_key[DNS_MAX_BASE64_DATA];
    char* ptr = (char*)from;

    flags = strtol(ptr, &ptr, 10);
    protocol = (uint8)strtol(ptr, &ptr, 10);
    algorithm = (uint8)strtol(ptr, &ptr, 10);

    ptr = skip_whitespace(ptr);
    decoded_key_len = base64_decode(ptr, strlen(ptr), decoded_key, sizeof(decoded_key));

    len = 0;
    len += dns_uint16_encode(flags, to + len);
    memmove(to + len++, &protocol, 1);
    memmove(to + len++, &algorithm, 1);

    memmove(to + len, decoded_key, decoded_key_len);
    len += decoded_key_len;

    //printf("decoded dnskey\n");

    return len;
}

int dns_ds_encode(const char* from, char* to)
{
    int len, decoded_digest_len;
    uint16 keytag;
    uint8 algorithm, digest_type;
    char decoded_digest[DNS_MAX_BASE64_DATA];
    char* ptr = (char*)from;

    keytag = strtol(ptr, &ptr, 10);
    algorithm = (uint8)strtol(ptr, &ptr, 10);
    digest_type = (uint8)strtol(ptr, &ptr, 10);

    ptr = skip_whitespace(ptr);
    decoded_digest_len = read_hex_encoded_nowhitespace(ptr, decoded_digest, sizeof(decoded_digest));

    len = 0;
    len += dns_uint16_encode(keytag, to + len);
    memmove(to + len++, &algorithm, 1);
    memmove(to + len++, &digest_type, 1);

    memmove(to + len, decoded_digest, decoded_digest_len);
    len += decoded_digest_len;

    return len;
}

int dns_rrsig_encode(const char* from, char* to)
{
    int len, signature_len;
    int algorithm, labels, orig_ttl;
    int key_tag;
    uint32 expiration, inception;
    char type[DNS_MAX_TYPE_LENGTH + 1];
    char signer_name[DNS_MAX_DOMAIN_LENGTH + 1];
    char decoded_signature[DNS_MAX_BASE64_DATA];
    char* signature;
    char* ptr;
    char* next_ptr;

    ptr = (char*)from;
    next_ptr = NULL;

    ptr = read_string_nowhitespace(ptr, type, sizeof(type) / sizeof(type[0]));
    algorithm = strtol(ptr, &ptr, 10);
    labels = strtol(ptr, &ptr, 10);
    orig_ttl = strtol(ptr, &ptr, 10);
    expiration = expiration_time_from_string(ptr, &ptr);
    inception = expiration_time_from_string(ptr, &ptr);
    key_tag = strtol(ptr, &ptr, 10);
    ptr = read_string_nowhitespace(ptr, signer_name, sizeof(signer_name) / sizeof(signer_name[0]));
    ptr = skip_whitespace(ptr);
    signature = ptr;

    signature_len = base64_decode(signature, strlen(signature), decoded_signature, sizeof(decoded_signature));

    len = 0;
    len += dns_uint16_encode(dns_type_name_to_int(type), to + len);
    memmove(to + len++, &algorithm, 1);
    memmove(to + len++, &labels, 1);
    len += dns_uint32_encode(orig_ttl, to + len);
    len += dns_uint32_encode(expiration, to + len);
    len += dns_uint32_encode(inception, to + len);
    len += dns_uint16_encode(key_tag, to + len);
    len += dns_domain_encode(signer_name, to + len);

    memmove(to + len, decoded_signature, signature_len);
    len += signature_len;

    return len;
}

int read_type_bitmap(char*& ptr, unsigned char* bitmap)
{
    char type[DNS_MAX_TYPE_LENGTH + 1];
    int type_id;
    int bitmap_len = 0;

    memset(bitmap, 0, DNS_MAX_BITMAP_LENGTH); // max 32 octets, 1 block id, 1 block len
    while (*ptr) {
        ptr = skip_whitespace(ptr);
        ptr = read_string_nowhitespace(ptr, type, sizeof(type) / sizeof(type[0]));
        if (type[0] != '\0') {
            type_id = dns_type_name_to_int(type);
            if (type_id == 0) {
                continue;
            }
            unsigned char window = (unsigned char)((type_id & 0xFF00) >> 8);
            unsigned char* window_start = bitmap + window * DNS_MAX_BITMAP_WINDOW_LENGTH;
            window_start[0] = window;
            unsigned char window_pos = (unsigned char)(type_id & 0xFF);
            window_start[1] = std::max(window_start[1], (unsigned char)((window_pos / 8) + 1));
            window_start[2 + (window_pos / 8)] |= 1 << (7 - (window_pos % 8));
        }
    }

    // Compact it
    for (int i = 0; i < DNS_MAX_BITMAP_WINDOW_COUNT; i++) {
        if (i != 0 && bitmap[(i * DNS_MAX_BITMAP_WINDOW_LENGTH) + 1] > 0) {
            memmove(bitmap + bitmap_len, bitmap + (i * DNS_MAX_BITMAP_WINDOW_LENGTH), bitmap[(i * DNS_MAX_BITMAP_WINDOW_LENGTH) + 1] + 2);
        }
        if (bitmap[(i * DNS_MAX_BITMAP_WINDOW_LENGTH) + 1] > 0) {
            bitmap_len += bitmap[(i * DNS_MAX_BITMAP_WINDOW_LENGTH) + 1] + 2;
        }
    }

    return bitmap_len;
}

int dns_nsec3param_encode(const char* from, char* to)
{
    int len = 0;
    char* ptr = (char*)from;

    char salt[DNS_MAX_SALT_LENGTH + 1];

    uint8 algorithm = strtol(ptr, &ptr, 10);
    uint8 flags = strtol(ptr, &ptr, 10);
    uint16 iterations = strtol(ptr, &ptr, 10);
    uint16 salt_len;
    salt_len = read_hex_encoded(ptr, salt, sizeof(salt) / sizeof(salt[0]));

    len += dns_uint8_encode(algorithm, to + len);
    len += dns_uint8_encode(flags, to + len);
    len += dns_uint16_encode(iterations, to + len);
    len += dns_uint8_encode(salt_len, to + len);

    memmove(to + len, salt, salt_len);
    len += salt_len;

    return len;
}

int dns_nsec3_encode(const char* from, char* to)
{
    int len = 0, bitmap_len;
    char* ptr = (char*)from;
    unsigned char bitmap[DNS_MAX_BITMAP_LENGTH];
    char salt[DNS_MAX_SALT_LENGTH + 1],
        hash[DNS_MAX_HASH_LENGTH + 1];

    uint8 algorithm = strtol(ptr, &ptr, 10);
    uint8 flags = strtol(ptr, &ptr, 10);
    uint16 iterations = strtol(ptr, &ptr, 10);
    uint16 salt_len = 0;
    uint16 hash_len = 0;

    salt_len = read_hex_encoded(ptr, salt, sizeof(salt) / sizeof(salt[0]));
    ptr = skip_whitespace(ptr);
    ptr = read_string_nowhitespace(ptr, hash, sizeof(hash) / sizeof(hash[0]));
    hash_len = strlen(hash);
    bitmap_len = read_type_bitmap(ptr, bitmap);

    len += dns_uint8_encode(algorithm, to + len);
    len += dns_uint8_encode(flags, to + len);
    len += dns_uint16_encode(iterations, to + len);
    len += dns_uint8_encode(salt_len, to + len);

    memmove(to + len, salt, salt_len);
    len += salt_len;

    hash_len = (hash_len * 5) / 8 + 1; // 1 for safety
    hash_len = base32_decode(hash, (unsigned char*)(to + len + 1), hash_len);
    len += dns_uint8_encode(hash_len, to + len);
    len += hash_len;

    if (bitmap_len > 0) {
        memmove(to + len, bitmap, bitmap_len);
        len += bitmap_len;
    }

    return len;
}

int dns_nsec_encode(const char* from, char* to)
{
    int len = 0;
    char* ptr = (char*)from;
    char domain[DNS_MAX_DOMAIN_LENGTH + 1];
    unsigned char bitmap[DNS_MAX_BITMAP_LENGTH];
    int bitmap_len;

    ptr = read_string_nowhitespace(ptr, domain, sizeof(domain) / sizeof(domain[0]));
    bitmap_len = read_type_bitmap(ptr, bitmap);

    len += dns_domain_encode(domain, to + len);

    if (bitmap_len > 0) {
        memmove(to + len, bitmap, bitmap_len);
        len += bitmap_len;
    }

    return len;
}

int dns_sshfp_encode(const char* from, char* to)
{
    int len = 0;
    uint16 fingerprint_length = 0;
    char* ptr = (char*)from;
    char fingerprint[DNS_MAX_RDATA_LENGTH + 1];

    uint8 algorithm = strtol(ptr, &ptr, 10);
    uint8 fp_type = strtol(ptr, &ptr, 10);
    fingerprint_length = read_hex_encoded_nowhitespace(ptr, fingerprint, sizeof(fingerprint) / sizeof(fingerprint[0]));

    len += dns_uint8_encode(algorithm, to + len);
    len += dns_uint8_encode(fp_type, to + len);

    memmove(to + len, fingerprint, fingerprint_length);
    len += fingerprint_length;

    return len;
}

int dns_tlsa_encode(const char* from, char* to)
{
    int len = 0;
    uint16 cert_data_length = 0;
    char* ptr = (char*)from;
    char cert_data[DNS_MAX_RDATA_LENGTH + 1];

    uint8 usage = strtol(ptr, &ptr, 10);
    uint8 selector = strtol(ptr, &ptr, 10);
    uint8 match_type = strtol(ptr, &ptr, 10);
    cert_data_length = read_hex_encoded_nowhitespace(ptr, cert_data, sizeof(cert_data) / sizeof(cert_data[0]));

    len += dns_uint8_encode(usage, to + len);
    len += dns_uint8_encode(selector, to + len);
    len += dns_uint8_encode(match_type, to + len);

    memmove(to + len, cert_data, cert_data_length);
    len += cert_data_length;

    return len;
}

bool is_axfr_request(const char* pkt_in, const int len)
{
    int pkt_in_len;
    struct dns_question q;
    struct dns_header h;
    bool result;
    char name[DNS_MAX_RDATA_LENGTH + 1];
    q.name = name;

    pkt_in_len = dns_header_decode(pkt_in, &h);
    result = false;
    if (h.qdcount == 1) {
        dns_question_decode(pkt_in + pkt_in_len, len, &q);
        if (q.qtype == DNS_TYPE_AXFR)
            result = true;
    }

    return result;
}

bool is_notify_request(const char* pkt_in, const int len)
{
    struct dns_header h;

    dns_header_decode(pkt_in, &h);
    return DNS_HEADER_OPCODE_GET(h.flags) == DNS_OPCODE_NOTIFY;
}

bool is_request_type_supported(uint16 qtype)
{
    switch (qtype) {
#ifdef DEBUG_DNSSEC
    /*
        * This is only for debugging purposes, these records should
        * not actually be queriable since they are only used for
        * dnssec validation.
        */
    case DNS_TYPE_NSEC:
    case DNS_TYPE_NSEC3:
#endif
    case DNS_TYPE_A:
    case DNS_TYPE_MX:
    case DNS_TYPE_TXT:
    case DNS_TYPE_SPF:
    case DNS_TYPE_AAAA:
    case DNS_TYPE_SRV:
    case DNS_TYPE_DS:
    case DNS_TYPE_RRSIG:
    case DNS_TYPE_NSEC3PARAM:
    case DNS_TYPE_SSHFP:
    case DNS_TYPE_TLSA:
    case DNS_TYPE_DNSKEY:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
    case DNS_TYPE_SOA:
    case DNS_TYPE_NS:
    case DNS_TYPE_ANY:
        return true;
    default:
        return false;
    }
}

int dns_wildcard_encode(dns_domain* domain)
{
    unsigned char labelLength = 0;

    if (domain->len > 2) {
        if (domain->name[1] == '*') {
            domain->len -= 2;
            memmove(domain->name, domain->name + 2, domain->len);
        }

        labelLength = domain->name[0] + 1;
        if (domain->name[0] == 0 || labelLength - 2 >= domain->len || domain->len - labelLength + 2 > DNS_MAX_DOMAIN_LENGTH)
            return -1;

        domain->name[0] = 1;
        domain->name[1] = '*';
        domain->len -= labelLength - 2;
        memmove(domain->name + 2, domain->name + labelLength, domain->len);

        return domain->len;
    }

    return -1;
}
