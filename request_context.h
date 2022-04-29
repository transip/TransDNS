/**
 * This module defines a data structure for contextual information 
 * for a request.
 */

#ifndef _REQUEST_CONTEXT_H
#define _REQUEST_CONTEXT_H

#include "dns.h"
#include "dns_data.h"
#include "response_info.h"

enum REQUEST_TYPE {
    REQUEST_TYPE_UDP,
    REQUEST_TYPE_TCP
};

class hash_cache;

struct request_context_t {
    // request info
    REQUEST_TYPE request_type;

    // socket related info for this request
    struct sockaddr_storage* sockaddr;
    char source_addr[INET6_ADDRSTRLEN + 1];

    // data used to handle this request
    dns_data_t* dns_data;
    dns_domain_rrs_t* dnssec_nsec_data;

    // request in buffer (bytes we got from the client)
    char* buf;
    int query_len;

    // DNS header
    dns_header request_header;
    dns_header response_header;

    // DNSSEC
    bool dnssec_do;
    hash_cache* dnssec_hash_cache;

    response_info_t response_info_chain[DNS_MAX_ITERATE];
    int number_of_response_infos;

    unsigned int thread_id;

    // METHODS
    char* get_source_address();
    response_info_t* get_current_response_info();
    response_info_t* start_response_info();
    void debug_print();

protected:
    void _new_response_info();
};

#endif //_REQUEST_CONTEXT_H
