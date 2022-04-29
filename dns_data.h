#ifndef DNS_DATA_H
#define DNS_DATA_H

#include "dns.h"
#include <netinet/in.h>

#include <algorithm>
#include <functional>
#include <map>
#include <unordered_map>
#include <vector>

#define MAX_PACKET_SIZE 65507
#define MAX_UDP_RECV_SIZE 2048
#define UDP_RECV_QUEUE 500

struct dns_tcp_handle {
    struct sockaddr_storage saddr;
    int s;
};

typedef std::vector<dns_resource> dns_resource_v;

struct dns_resource_type {
    uint16 rtype;
    dns_resource_v records;
};

typedef std::vector<dns_resource_type> dns_resource_type_v;

struct dns_label {
    int childs;
    int zone_id;
    dns_resource_type_v recordtypes;
};

namespace std {
template <>
struct hash<dns_question> {
    size_t operator()(const dns_question& q) const
    {
        std::size_t hash = 5381;
        int i;

        for (i = 0; q.name[i] != 0 && i < q.len; ++i)
            hash = ((hash << 5) + hash) + LOWERCASE[(unsigned char)q.name[i]];

        return ((hash << 5) + hash) + q.qtype;
    }
};
}

namespace std {
template <>
struct hash<dns_domain> {
    size_t operator()(const dns_domain& d) const
    {
        std::size_t hash = 5381;
        int i;
        for (i = 0; d.name[i] != 0 && i < d.len; ++i) {
            hash = ((hash << 5) + hash) + LOWERCASE[(unsigned char)d.name[i]];
        }

        return hash;
    }
};
}

struct request_context_t;

typedef std::vector<dns_resource_named> dns_resource_named_v;

typedef std::unordered_map<dns_domain, dns_label> dns_data_t;
typedef std::unordered_map<dns_domain, dns_label>::iterator dns_data_iter_t;

typedef std::unordered_map<dns_domain, dns_resource_named_v> dns_domain_rrs_t;
typedef std::unordered_map<dns_domain, dns_resource_named_v>::iterator dns_domain_rrs_iter_t;

int dns_data_answer(request_context_t* context);

dns_label* dns_data_get_label(request_context_t*, dns_domain*, int);
struct dns_resource_type* dns_data_get_record_type_data(dns_label*, uint16);
int dns_data_answer_cname(request_context_t*, dns_label*, dns_question*, char*, int, struct dns_header*, bool, int);
int dns_data_answer_single_record(request_context_t*, dns_label*, dns_question&, char*, int, struct dns_header*, int);
int dns_data_answer(request_context_t*);
int dns_axfr_answer(request_context_t*, const char*, const int, const struct dns_tcp_handle);
int dns_data_answer_add_rrsigs(dns_label*, char*, int, dns_question&, uint16*, uint32 = 0);

bool dns_data_soa_exists(dns_label* label);

#endif
