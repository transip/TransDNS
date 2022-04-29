/**
 * This module provides AXFR support for TransDNS
 */

#ifndef _AXFR_H
#define _AXFR_H

#include "dns_data.h"

void dns_axfr_read_acl();

int dns_axfr_answer(request_context_t* context, const char* pkt_in, const int pkt_in_len, struct sockaddr_storage* saddr, const int socket);

#endif //_AXFR_H
