#ifndef DNS_H
#define DNS_H

#include "misc.h"

#define DNS_TYPE_A 1 // supported
#define DNS_TYPE_NS 2 // supported
#define DNS_TYPE_MD 3 // obsolete
#define DNS_TYPE_MF 4 // obsolete
#define DNS_TYPE_CNAME 5 // supported
#define DNS_TYPE_SOA 6 // supported
#define DNS_TYPE_MB 7 // EXPERIMENTAL (obsolete)
#define DNS_TYPE_MG 8 // EXPERIMENTAL (obsolete)
#define DNS_TYPE_MR 9 // EXPERIMENTAL (obsolete)
#define DNS_TYPE_NULL 10 // EXPERIMENTAL (obsolete)
#define DNS_TYPE_WKS 11 // well known service point description
#define DNS_TYPE_PTR 12 // supported
#define DNS_TYPE_HINFO 13 // host information
#define DNS_TYPE_MINFO 14 // mailbox or mail list information
#define DNS_TYPE_MX 15 // supported
#define DNS_TYPE_TXT 16 // supported
#define DNS_TYPE_RP 17 // Responsible Person
#define DNS_TYPE_AFSDB 18 // for AFS Data Base location
#define DNS_TYPE_X25 19 // for X.25 PSDN address
#define DNS_TYPE_ISDN 20 // for ISDN address
#define DNS_TYPE_RT 21 // for Route Through
#define DNS_TYPE_NSAP 22 // for NSAP address, NSAP style A record
#define DNS_TYPE_NSAP_PTR 23 // for domain name pointer, NSAP style
#define DNS_TYPE_SIG 24 // for security signature
#define DNS_TYPE_KEY 25 // for security key
#define DNS_TYPE_PX 26 // X.400 mail mapping information
#define DNS_TYPE_GPOS 27 // Geographical Position
#define DNS_TYPE_AAAA 28 // supported
#define DNS_TYPE_LOC 29
#define DNS_TYPE_NXT 30 // Next Domain - OBSOLETE
#define DNS_TYPE_EID 31 // Endpoint Identifier
#define DNS_TYPE_NIMLOC 32 // Nimrod Locator
#define DNS_TYPE_SRV 33 // supported
#define DNS_TYPE_ATMA 34 // ATM Address
#define DNS_TYPE_NAPTR 35 // WANT TO SUPPORT
#define DNS_TYPE_KX 36 // Key Exchanger
#define DNS_TYPE_CERT 37
#define DNS_TYPE_A6 38 // deprecated
#define DNS_TYPE_DNAME 39
#define DNS_TYPE_SINK 40 // SINK
#define DNS_TYPE_OPT 41 // pseudo edns (supported)
#define DNS_TYPE_APL 42 // APL
#define DNS_TYPE_DS 43 // NOT YET SUPPORTED
#define DNS_TYPE_SSHFP 44 // supported
#define DNS_TYPE_IPSECKEY 45
#define DNS_TYPE_RRSIG 46 // dnssec (supported)
#define DNS_TYPE_NSEC 47 // dnssec (supported)
#define DNS_TYPE_DNSKEY 48 // dnssec (supported)
#define DNS_TYPE_DHCID 49
#define DNS_TYPE_NSEC3 50 // dnssec (supported)
#define DNS_TYPE_NSEC3PARAM 51 // dnssec (supported)
#define DNS_TYPE_TLSA 52 // supported
#define DNS_TYPE_HIP 55
#define DNS_TYPE_NINFO 56 // NINFO
#define DNS_TYPE_RKEY 57 // RKEY
#define DNS_TYPE_TALINK 58 // Trust Anchor Link
#define DNS_TYPE_SPF 99 // supported
#define DNS_TYPE_AXFR 252 // pseudo type, supported
#define DNS_TYPE_ANY 255 // supported
#define DNS_TYPE_CAA 257 // supported

#define DNS_CLASS_RESERVED 0
#define DNS_CLASS_IN 1
#define DNS_CLASS_CH 3
#define DNS_CLASS_HS 4
#define DNS_CLASS_NONE 254
#define DNS_CLASS_ANY 255

#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2
/*  (3 is reserved) */
#define DNS_OPCODE_NOTIFY 4
#define DNS_OPCODE_UPDATE 5

#define DNS_RCODE_BADVERS 16
#define DNS_RCODE_REFUSED 5
#define DNS_RCODE_NOTIMPLEMENTED 4
#define DNS_RCODE_NAMEERROR 3
#define DNS_RCODE_SERVERFAILURE 2

#define NSEC3_HASH_ALGO_SHA1 1

#define DNS_HEADER_LENGTH 12 //bytes
#define DNS_MAX_LABEL_LENGTH 63 // bytes, a label can be max 63 bytes long
#define DNS_MAX_DOMAIN_LENGTH 256 //bytes, used in conjunction with the mysql server! - this limit is imposed by RF 1034 (limit is 255 + 1 for including the final dot)
#define DNS_MAX_RDATA_LENGTH 1024 //bytes, used in conjunction with the mysql server!   - this is an arbitrairy limit
#define DNS_MAX_TYPE_LENGTH 20 // bytes, used for decoding rrsig records
#define DNS_MAX_BITMAP_WINDOW_LENGTH 34 // 32 octets, 1 octet window id, 1 octet window length
#define DNS_MAX_BITMAP_WINDOW_COUNT 256
#define DNS_MAX_BITMAP_LENGTH (DNS_MAX_BITMAP_WINDOW_COUNT * DNS_MAX_BITMAP_WINDOW_LENGTH)
#define DNS_MAX_BASE64_DATA 2048 // bytes, maximum length of base64 encoded values (used with dnskey and rrsig RRs)
#define MAX_RRSIG_RECORDS 1024 // number of rrsig records we can add to one section
#define DNS_MAX_SALT_LENGTH 255 // bytes
#define DNS_MAX_HASH_LENGTH 255 // bytes
#define DNS_MAX_NEEDED_NSEC3_RECORDS 3 // items
#define DNS_MAX_NEEDED_NSEC_RECORDS 2 // items
#define DNS_MAX_UDP_PACKET 512 //bytes
#define DNS_MAX_AXFR_PACKET 16383 //bytes
#define DNS_MAX_BACKLOG 1024 //connections
#define DNS_MAX_TCP_WAIT 60 //in seconds
#define DNS_MAX_ITERATE 10 //maximum number of iterations for cname's
#define DNS_MAX_CAATAG_LENGTH 15; // (rfc6844) The tag length MUST be at least 1 and SHOULD be no more than 15

#define DNS_HEADER_QR_GET(a) (((uint16)(a)&0x8000) >> 15)
#define DNS_HEADER_OPCODE_GET(a) (((uint16)(a)&0x7800) >> 11)
#define DNS_HEADER_AA_GET(a) (((uint16)(a)&0x400) >> 10)
#define DNS_HEADER_TC_GET(a) (((uint16)(a)&0x200) >> 9)
#define DNS_HEADER_RD_GET(a) (((uint16)(a)&0x100) >> 8)
#define DNS_HEADER_RA_GET(a) (((uint16)(a)&0x80) >> 7)
#define DNS_HEADER_RCODE_GET(a) (((uint16)(a)&0xF))

#define DNS_EXT_HEADER_DO_GET(a) (((uint16)(a)&0x8000) >> 15)

#define DNS_HEADER_QR_SET(a, b) (((a) & ~0x8000) | ((uint16)(b) << 15))
#define DNS_HEADER_OPCODE_SET(a, b) (((a) & ~0x7800) | ((uint16)(b) << 14))
#define DNS_HEADER_AA_SET(a, b) (((a) & ~0x400) | ((uint16)(b) << 10))
#define DNS_HEADER_AA_UNSET(a, b) (((a) & ~0x400) & (~((uint16)(b) << 10)))
#define DNS_HEADER_TC_SET(a, b) (((a) & ~0x200) | ((uint16)(b) << 9))
#define DNS_HEADER_RD_SET(a, b) (((a) & ~0x100) | ((uint16)(b) << 8))
#define DNS_HEADER_RA_SET(a, b) (((a) & ~0x100) | ((uint16)(b) << 7))
#define DNS_HEADER_RA_UNSET(a, b) (((a) & ~0x100) & (~((uint16)(b) << 7)))
#define DNS_HEADER_RESERVED_UNSET(a, b) (((a) & ~0x100) & (~((uint16)(b) << 6)))
#define DNS_HEADER_AD_SET(a, b) (((a) & ~0x100) | ((uint16)(b) << 5))
#define DNS_HEADER_AD_UNSET(a, b) (((a) & ~0x100) & (~((uint16)(b) << 5)))

#define DNS_HEADER_RCODE_SET(a, b) (((a) & ~0x100) | ((uint16)(b)))
#define DNS_HEADER_RCODE_UNSET(a, b) (((a) & ~0x100) & (~((uint16)(b))))

#define DNS_EXT_HEADER_DO_SET(a, b) (((a) & ~0x8000) | ((uint16)(b) << 15))

#define DNS_EXT_HEADER_VALID_MASK 0x8000

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

struct dns_header {
    uint16 id;
    uint16 flags;
    uint16 qdcount,
        ancount,
        nscount,
        arcount;
};

struct dns_question {
    char* name;
    uint16 qtype, qclass;
    unsigned char len;

    //const bool operator<( const dns_question &q ) const;
    const bool operator==(const dns_question& q) const;
};

struct dns_resource {
    char* rdata;
    uint16 rtype, rclass;
    uint32 ttl;
    uint16 rdlength;
    unsigned int id;

    void assign_from(const dns_resource& r);
};

struct dns_resource_named : dns_resource {
    char* name;
    int name_len;

    bool operator<(const dns_resource_named& that) const;
};

struct dns_resource_fixed {
    char rdata[DNS_MAX_RDATA_LENGTH + 1];
    uint16 rtype, rclass;
    uint32 ttl;
    uint16 rdlength;
    unsigned int id;
};

struct dns_domain {
    char* name;
    unsigned char len;

    const bool operator==(const dns_domain& s) const;
};

// this table tells which bytes
// are legal in dns name labels
const unsigned char IS_ILLEGAL[] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

int dns_uint16_encode(const uint16, char*);
int dns_uint32_encode(const uint32, char*);
void dns_uint16_decode(const char*, uint16*);
void dns_uint32_decode(const char*, uint32*);
int dns_nsec3_encode(const char* from, char* to);
int dns_nsec3param_encode(const char* from, char* to);

int dns_resource_encode(const struct dns_resource&, const struct dns_question&, char*, int);
int dns_resource_fixed_encode(const struct dns_resource_fixed&, const struct dns_question&, char*, int);
void dns_question_print(const struct dns_question&);
int dns_domain_decode(const char*, char*);
int dns_domain_length(const char*, int len);
int dns_question_encode(const struct dns_question&, char*);
int dns_question_decode(const char*, const int, struct dns_question*);
int dns_header_encode(const struct dns_header&, char*);
int dns_header_decode(const char*, struct dns_header*);
void dns_header_print(const struct dns_header& h);
void dns_resource_print(const struct dns_resource& r, const struct dns_question&);
int dns_domain_encode(const char*, char*);
int dns_ip_encode(const char*, char*);
int dns_ip6_encode(const char*, char*);
int dns_txt_encode(const char* from, char* to);
void dns_ip_decode(const char*, char*);
int dns_mx_recode(const char*, char*);
int dns_soa_encode(const uint32 ttl, const char* from, char* to);
int dns_srv_encode(const char* from, char* to);
int dns_dnskey_encode(const char* from, char* to);
int dns_ds_encode(const char* from, char* to);
int dns_rrsig_encode(const char* from, char* to);
int dns_nsec_encode(const char* from, char* to);
int dns_sshfp_encode(const char* from, char* to);
int dns_tlsa_encode(const char* from, char* to);
int dns_caa_encode(const char* from, char* to);
bool is_axfr_request(const char*, const int);
bool is_notify_request(const char*, const int);
bool is_request_type_supported(uint16 type);
int dns_wildcard_encode(dns_domain*);
#endif
