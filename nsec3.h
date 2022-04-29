/**
 * Support for the nsec3 lookup
 *
 * See also: RFC 5155
 */

#ifndef _NSEC3_H
#define _NSEC3_H

#include "dns_data.h"

#define SHA_BASE32_DIGEST_LENGTH 32

int dnssec_add_nsec3s(request_context_t* context, char* pkt_out, int buf_len, struct dns_header* h, int* found_nsec3_when_needed, int* is_empty_non_terminal_nsec3);

#endif //_NSEC3_h
