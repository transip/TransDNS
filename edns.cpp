/**
 * Module that supports basic Extended DNS.
 *
 * See also: RFC2761
 */

#include "edns.h"
#include "dns.h"
#include "dns_data.h"
#include "settings.h"
#include <algorithm> // for std::min()

int edns_answer_packet(char* pkt_out, int buf_len, struct dns_header* hdr_out, struct edns_options* opts)
{
    uint32 flags;
    int pkt_out_len = 0;

    if (opts->has_edns) {
        if (opts->version != EDNS_VERSION) {
            // XXX validate
        }
        // 1 byte empty qname, 2 bytes type, 2 bytes payload_size, 4 bytes flags, 2 bytes rdlength always 0
        if (buf_len < 1 + 2 + 2 + 4 + 2) {
            return -1;
        }

        hdr_out->arcount++;

        // empty root name
        *pkt_out = '\0';
        pkt_out_len++;

        flags = opts->extended_flags & DNS_EXT_HEADER_VALID_MASK;
        flags |= ((uint32)opts->extended_rcode) << 24;
        flags |= ((uint32)EDNS_VERSION) << 16;

        pkt_out_len += dns_uint16_encode(DNS_TYPE_OPT, pkt_out + pkt_out_len);
        pkt_out_len += dns_uint16_encode(opts->udp_payload_size, pkt_out + pkt_out_len);
        pkt_out_len += dns_uint32_encode(flags, pkt_out + pkt_out_len);
        pkt_out_len += dns_uint16_encode(0, pkt_out + pkt_out_len); // no data, yet
        //XYZ: removed empty lines
    }

    return pkt_out_len;
}

int edns_handle_packet(const char* pkt_in, const int len, struct edns_options* opts)
{
    struct dns_header h;
    struct dns_question q;
    uint16 rdata_len;
    uint16 rtype;
    uint32 flags;
    uint16 udp_payload_size = 0;
    int i, reslen;
    int pkt_in_len = 0;
    char dummy_name[DNS_MAX_DOMAIN_LENGTH + 1];
    q.name = dummy_name;

    if (0 == opts) {
        return 0;
    }

    opts->has_edns = 0;
    opts->extended_rcode = 0;
    opts->extended_flags = 0;
    opts->version = 0;

    // At least 5 bytes needed for a question (one for '.' and 2 each for class and type)
    if (len < pkt_in_len + DNS_HEADER_LENGTH + 5) {
        return -1;
    }

    pkt_in_len = dns_header_decode(pkt_in, &h);

    if (h.qdcount != 1) {
        // Invalid packet or definately no opt record
        return -1;
    }

    for (i = 0; i < h.qdcount; ++i) {
        reslen = dns_question_decode(pkt_in + pkt_in_len, len - pkt_in_len, &q);
        if (reslen <= 0) {
            // Invalid question found, bailing
            return -1;
        }
        pkt_in_len += reslen;
    }

    if (len < pkt_in_len)
        return -1; // invalid packet

    // skip sections we are not interested in
    for (i = 0; i < h.ancount + h.nscount; ++i) {
        reslen = dns_domain_length(pkt_in + pkt_in_len, len - pkt_in_len);
        if (reslen <= 0) {
            return -1;
        }
        pkt_in_len += reslen;
        pkt_in_len += 2 + 2 + 4; // type, class, ttl
        if (len < pkt_in_len + 2) {
            // +2 for the rdatalen
            return -1; // invalid packet
        }
        dns_uint16_decode(pkt_in + pkt_in_len, &rdata_len);
        pkt_in_len += 2; // rdata len
        pkt_in_len += rdata_len;
        if (len < pkt_in_len) {
            return -1; // invalid packet
        }
    }

    // finally, we've hit the ar sections
    for (i = 0; i < h.arcount; ++i) {
        reslen = dns_domain_length(pkt_in + pkt_in_len, len - pkt_in_len);
        if (reslen <= 0) {
            return -1;
        }
        pkt_in_len += reslen;

        if (len < (pkt_in_len + 2 + 2 + 4 + 2)) {
            return -1;
        }

        dns_uint16_decode(pkt_in + pkt_in_len, &rtype);
        pkt_in_len += 2;
        if (rtype == DNS_TYPE_OPT) {
            dns_uint16_decode(pkt_in + pkt_in_len, &udp_payload_size);
            pkt_in_len += 2;

            dns_uint32_decode(pkt_in + pkt_in_len, &flags);
            pkt_in_len += 4;

            dns_uint16_decode(pkt_in + pkt_in_len, &rdata_len);
            pkt_in_len += 2;

            opts->options = pkt_in + pkt_in_len;
            opts->extended_rcode = (flags & 0xFF000000) >> 24;
            opts->extended_flags = (flags & 0x0000FFFF);
            opts->version = (flags & 0x00FF0000) >> 16;
            opts->has_edns = 1;

            if (pkt_in_len + rdata_len > len) {
                return -1;
            }

            break;
        } else {
            pkt_in_len += 2 + 4; // class, ttl
            dns_uint16_decode(pkt_in + pkt_in_len, &rdata_len);
            pkt_in_len += 2; // rdata len
            pkt_in_len += rdata_len;
            if (pkt_in_len > len) {
                return -1;
            }
        }
    }

    if (udp_payload_size != 0) {
        //XYZ changed int -> uint16
        opts->udp_payload_size = std::min((uint16)udp_payload_size, (uint16)MAX_PACKET_SIZE);
        opts->udp_payload_size = std::min((uint16)opts->udp_payload_size, (uint16)max_udp_payload_size);
    }

    return opts->has_edns;
}
