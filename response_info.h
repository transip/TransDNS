/**
 * This module defines a data structure for information for a response.
 */

#ifndef _RESPONSE_INFO_H
#define _RESPONSE_INFO_H

#include "dns.h"
#include "dns_data.h"

enum MATCH_TYPE {
    MATCH_TYPE_UNKNOWN_QUERY, // we don't know the query type, so we cannot answer it
    MATCH_TYPE_DIRECT_HIT, // the question could directly be answered
    MATCH_TYPE_WILDCARD_HIT, // the question was satisfied with a wildcard
    MATCH_TYPE_DELEGATION, // we are not authoritive for this question
    MATCH_TYPE_NO_CNAME_BUT_A_RECORD, // weird case (?)
    MATCH_TYPE_CNAME_REDIRECTION, // we got a CNAME for the query when another record was requested
    MATCH_TYPE_NONE // no records are matching
};

struct response_info_t {
    dns_question q;
    char qname[DNS_MAX_DOMAIN_LENGTH];

    bool is_unknown_zone;
    bool is_name_error;
    bool is_no_data;

    bool is_wildcard_hit;
    char wildcard_name[DNS_MAX_DOMAIN_LENGTH];
    int wildcard_name_len;

    bool is_cname_redirection;
    int zone_id;
    bool is_direct_hit;
    bool is_unknown_query_type;

    bool is_delegation;
    bool is_secure_delegation;

    char delegation_name[DNS_MAX_DOMAIN_LENGTH];
    int delegation_name_len;

    // DNSSEC NSEC3
    dns_resource* nsec3_params;

    void assign_question(const dns_question& other_q);
    void assign_wildcard_name(const dns_domain& wildcard_q);
    void assign_delegation_name(const dns_question& delegation_q);
    void debug_print();
};

#endif //_RESPONSE_INFO_H
