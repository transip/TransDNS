/**
 * This module provides response info functions
 */

#include "response_info.h"
#include "misc.h"
#include <stdio.h>

void response_info_t::assign_question(const dns_question& other_q)
{
    q = other_q;
    q.name = qname;
    memcpy(q.name, other_q.name, q.len);
}

void response_info_t::assign_wildcard_name(const dns_domain& wildcardName)
{
    memcpy(wildcard_name, wildcardName.name, wildcardName.len);
    wildcard_name_len = wildcardName.len;
}

void response_info_t::assign_delegation_name(const dns_question& delegation_q)
{
    memcpy(delegation_name, delegation_q.name, delegation_q.len);
    delegation_name_len = delegation_q.len;
}

void response_info_t::debug_print()
{
    dns_question_print(q);
    printf("  flags: ");
    if (is_unknown_zone)
        printf("is_unknown_zone ");
    if (is_name_error)
        printf("is_name_error ");
    if (is_no_data)
        printf("is_no_data ");
    if (is_cname_redirection)
        printf("is_cname_redirection ");
    if (is_direct_hit)
        printf("is_direct_hit ");
    if (is_wildcard_hit)
        printf("is_wildcard_hit ");
    if (is_unknown_query_type)
        printf("is_unknown_query_type ");
    if (is_delegation)
        printf("is_delegation ");
    if (is_secure_delegation)
        printf("is_secure_delegation ");
    if (delegation_name_len > 0) {
        char buf[DNS_MAX_DOMAIN_LENGTH];
        dns_domain_decode(delegation_name, buf);
        printf("\ndelegation: %s", buf);
    }

    printf("\n:");

    if (wildcard_name[0] > 0) {
        char buf[DNS_MAX_DOMAIN_LENGTH];
        dns_domain_decode(wildcard_name, buf);
        printf("  wildcard: %s\n", buf);
    }
}
