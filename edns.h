/**
 * Extended DNS Support for TransDNS.
 *
 * See also: RFC2671
 */

#ifndef _EDNS_H
#define _EDNS_H

#define EDNS_VERSION 0

#include "dns.h"

struct edns_options {
    int has_edns : 16;

    uint16 udp_payload_size;
    uint16 extended_flags;
    unsigned char extended_rcode;
    unsigned char version;
    const char* options;
};

int edns_handle_packet(const char* pkt_in, const int len, struct edns_options* opts);
int edns_answer_packet(char* pkt_out, int buf_len, struct dns_header* hdr_out, struct edns_options* opts);

#endif //_EDNS_H
