/**
 * Support for the nsec3 lookup
 *
 * See also: RFC 5155
 */

#include "nsec3.h"
#include "base32.h"
#include "dns_util.h"
#include "hash_cache.h"
#include "misc.h"
#include "request_context.h"
#include <cassert>
#include <stdio.h>

// #define NSEC3_DEBUG

extern int dnssec_nsec3_bind9_wildcard_compatibility; // from settings

typedef char nsec3_hash_t[DNS_MAX_DOMAIN_LENGTH + 1]; // a fqdn, nsec3 hash name

// ensure we do not add the same nsec3 record (~= hash) twice, since our RRSIG would no longer match
// in that case.
// For this, we keep a list of known nsec3_hashes we've added and return 1 when we've added a
// fqdn hash we haven't seen yet and return 0 if we already added it. The caller should
// not add the nsec3 rr to the output of the package when this method returns 0.
int nsec3_add_already_known_hash(nsec3_hash_t* already_added_nsec3_hashes, int response_info_count, char* hash, int len)
{
    nsec3_hash_t hash_to_compare = { 0 };
    memcpy(hash_to_compare, hash, len);

    for (int i = 0; i < DNS_MAX_NEEDED_NSEC3_RECORDS * response_info_count; ++i) {
        char* known_hash = already_added_nsec3_hashes[i];
        if (known_hash[0] == '\0') {
            memmove(known_hash, hash_to_compare, DNS_MAX_DOMAIN_LENGTH + 1);
            return 1;
        }
        // we do use cmp_label_text here on a FQDN, but we can safely also ignore the length bytes of a FQDN as text.
        else if (dns_util::cmp_label_text(known_hash, hash_to_compare, DNS_MAX_DOMAIN_LENGTH) == 0) {
            return 0;
        }
    }

    return 0;
}

// Calculates the hash for a given name and salt, iterations.
// Returns the length of the hash. The hash is stored in the [out] output buffer.
int nsec3_calc_hash(request_context_t* context, const char* name, int name_len, const char* salt, int salt_len, uint16 iterations, char* output, int output_len)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    int hash_len = iterated_cached_hash(context->dnssec_hash_cache, (unsigned char*)hash, (unsigned char*)salt, salt_len, (unsigned char*)name, name_len, iterations);

    return base32_encode((unsigned char*)hash, hash_len, output, output_len);
}

// Hashes a given name with the given NSEC3 parameters.
// Returns the length of the hash. The hash is stored in the [out] output buffer.
int nsec3_hash_name(request_context_t* context, const char* name, int name_len, dns_resource* params, char* output, int output_len)
{
    uint16 iterations;
    uint8 salt_len = *(params->rdata + 4);
    const char* salt = params->rdata + 5;
    dns_uint16_decode(params->rdata + 2, &iterations);

    char lowercased_name[DNS_MAX_DOMAIN_LENGTH];
    if (name_len >= sizeof(lowercased_name) / sizeof(lowercased_name[0]))
        return 0; // SERVFAIL via meta data in future releases

    for (int i = 0; i < name_len; ++i) {
        lowercased_name[i] = LOWERCASE[(unsigned char)name[i]];
    }

    return nsec3_calc_hash(context, lowercased_name, name_len, salt, salt_len, iterations, output, output_len);
}

// Find the NSEC3PARAM dns_resource for a zone for a given response_info. When there is no NSEC3PARAM
// (either a zone without DNSSEC or an zone with a missing NSEC3PARAM), NULL will be returned.
//
// Also returns the zone apex in the [out]apex and [out]apex_len arguments.
dns_resource* nsec3_find_params(request_context_t* context, response_info_t* response_info, char** apex, int* apex_len)
{
    dns_question q1 = response_info->q; // by value, since we modify q1

    dns_data_iter_t iter, iter_end;

    q1.qtype = DNS_TYPE_NSEC3PARAM;
    dns_domain domain;
    domain.name = q1.name;
    domain.len = q1.len;
    dns_resource_type* resourceType = dns_data_get_record_type_data(dns_data_get_label(context, &domain, 0), DNS_TYPE_NSEC3PARAM);

    while (domain.len > 0 && *domain.name && resourceType == NULL) {
        domain.len -= (*domain.name + 1);
        domain.name += *domain.name + 1;
        resourceType = dns_data_get_record_type_data(dns_data_get_label(context, &domain, 0), DNS_TYPE_NSEC3PARAM);
    }

    if (resourceType != NULL) {
        dns_resource_v& v = resourceType->records;
        int size = v.size();
        for (int i = 0; i < size; ++i) {
            dns_resource& rr = v[i];
            if (NSEC3_HASH_ALGO_SHA1 == *rr.rdata) {
                *apex = domain.name;
                *apex_len = domain.len;
                return &rr;
            }
        }
    }

    return NULL;
}

// Gets the dns_resource that matches the given algorithm for a given dns_resource_ve vector.
dns_resource* nsec3_get_rr(dns_resource_v& v, uint8 algo = NSEC3_HASH_ALGO_SHA1)
{
    int size = v.size();
    for (int i = 0; i < size; ++i) {
        dns_resource& nsec3 = v[i];
        if (*nsec3.rdata == algo)
            return &nsec3;
    }

    return NULL;
}

int nsec3_find_and_pack_direct_match(request_context_t* context, dns_data_t* dns_data, const char* name, int name_len,
    dns_resource* params, const char* apex, int apex_len, struct dns_header* h, char* pkt_out, int buf_len,
    int* found_nsec3_when_needed, nsec3_hash_t* already_added_hashes)
{
    int len = 0, res;

    char question_hash[DNS_MAX_HASH_LENGTH + 1];
    char question_hash_fqdn[DNS_MAX_DOMAIN_LENGTH + 1] = { 0 };

    int question_hash_len = nsec3_hash_name(context, name, name_len, params, question_hash, sizeof(question_hash));

    question_hash_fqdn[0] = question_hash_len;
    memcpy(question_hash_fqdn + 1, question_hash, question_hash_len);
    memcpy(question_hash_fqdn + 1 + question_hash_len, apex, apex_len);

    dns_question q1 = { question_hash_fqdn, DNS_TYPE_NSEC3, DNS_CLASS_IN, (unsigned char)(1 + question_hash_len + apex_len) };
    dns_domain domain;
    domain.name = q1.name;
    domain.len = q1.len;

    dns_label* label = dns_data_get_label(context, &domain, 0);
    dns_resource_type* resourceType = dns_data_get_record_type_data(label, DNS_TYPE_NSEC3);

    // no direct match
    dns_resource* nsec3 = NULL;
    if (resourceType != NULL)
        nsec3 = nsec3_get_rr(resourceType->records);

    if (nsec3 != NULL) {
        *found_nsec3_when_needed = 1;
        if (nsec3_add_already_known_hash(already_added_hashes, context->number_of_response_infos, question_hash_fqdn, DNS_MAX_DOMAIN_LENGTH + 1)) {
            res = dns_resource_encode(*nsec3, q1, pkt_out + len, buf_len);
            if (res < 0) {
                return -1;
            }
            len += res;
            buf_len -= res;
            h->nscount++;

            if (len > 0) {
                res = dns_data_answer_add_rrsigs(label, pkt_out + len, buf_len, q1, &h->nscount);
                if (res < 0) {
                    return -1;
                }
                len += res;
                buf_len -= res;
            }
        }
    } else {
        *found_nsec3_when_needed = 0;
    }

    return len;
}

// Finds the next closer for a wildcard hit:
//      question:       a.z.w.example.com
//      wildcard hit:   *.w.example.com
//      ancestor:       w.example.com
//      next closer:    z.w.example.com
//
// The next closer is the first name that's longer than the ancestor of the wildcard.
//
// returns true when the response_info is a wildcard hit and we found a next closer
//
bool nsec3_find_wildcard_next_closer(response_info_t* response_info, char** next_closer, int* next_closer_len)
{
    assert(response_info != NULL);
    assert(next_closer != NULL);
    assert(next_closer_len != NULL);

    dns_question* q = &response_info->q;

    // ensure that we can find a next closer
    if (!response_info->is_wildcard_hit || response_info->wildcard_name_len < 2 || (response_info->wildcard_name[0] != 2 && response_info->wildcard_name[1] != '*') || q->len < response_info->wildcard_name_len) {
        return false;
    }

    *next_closer = q->name;
    *next_closer_len = q->len;

    int wildcard_ancestor_len = response_info->wildcard_name_len - 2; // -2 for *.
    while (*next_closer_len - (**next_closer + 1) > wildcard_ancestor_len) {
        *next_closer_len -= (**next_closer + 1);
        *next_closer += (**next_closer + 1);
    }

#ifdef NSEC3_DEBUG
    char buf[DNS_MAX_DOMAIN_LENGTH];
    dns_domain_decode(*next_closer, buf);
    printf("next closer: %s\n", buf);
#endif

    return true;
}

// Finds and adds the NSEC3 record that covers the given
// name. Returns the length of the data to the packet added.
//
// Beware: A length of 0 does not mean that this case did not apply,
//         but could also mean that the NSEC3 record was already
//         present in packet. Use found_nsec3_when_needed
//          to determine if the NSEC3 record was found.
int nsec3_find_and_add_covering_rr(request_context_t* context,
    dns_resource_named_v* nsecs3,
    char* name,
    int name_len,
    dns_resource* params,
    dns_header* h,
    char* pkt_out,
    int buf_len,
    int* found_nsec3_when_needed,
    nsec3_hash_t* already_added_hashes)
{
    int len = 0, res;

    // first, create the hash of the name we want to cover
    char hash[DNS_MAX_HASH_LENGTH + 2];
    int hash_len = nsec3_hash_name(context, name, name_len, params, hash + 1, sizeof(hash));
    hash[0] = hash_len;

    // Next, search the list of NSEC3 records for our zone in order and
    // find the record where the hash of <hash>.zonename is larger
    // than the hash of the name we want to cover.
    int size = nsecs3->size();
    int prev = -1;
    for (int i = 0; i < size; ++i) {
        dns_resource_named& rr = (*nsecs3)[i];
        if (rr.rtype == DNS_TYPE_NSEC3 && *rr.rdata == NSEC3_HASH_ALGO_SHA1) {
            // we use cmp_label_text here on a FQDN, because we can safely compare the length bytes
            // of the FQDNs
            if (dns_util::cmp_label_text(rr.name, hash, SHA_BASE32_DIGEST_LENGTH) > 0) {
                break;
            }

            prev = i;
        }
    }

    if (prev == -1) {
        // the first sorted hash > the wanted hash, so our last item covers it:
        // search backwards to find the last item that is of NSEC3 type and the correct algorithm
        for (int i = size - 1; i >= 0; --i) {
            dns_resource_named& rr = (*nsecs3)[i];
            if (rr.rtype == DNS_TYPE_NSEC3 && *rr.rdata == NSEC3_HASH_ALGO_SHA1) {
                prev = i;
                break;
            }
        }
    }

    // if we found a covering NSEC3 record, add it to the packet when it's not already there
    if (prev != -1) {
        *found_nsec3_when_needed = 1;

        dns_resource_named& rr = (*nsecs3)[prev];
        if (nsec3_add_already_known_hash(already_added_hashes, context->number_of_response_infos, rr.name, rr.name_len)) {
            dns_question q1 = { rr.name, rr.rtype, rr.rclass, (unsigned char)rr.name_len };
            res = dns_resource_encode(rr, q1, pkt_out + len, buf_len);
            if (res < 0) {
                return -1;
            }
            len += res;
            buf_len -= res;
            h->nscount++;

            if (len > 0) {
                dns_domain domain;
                domain.name = rr.name;
                domain.len = rr.name_len;
                dns_label* label = dns_data_get_label(context, &domain, 0);
                res = dns_data_answer_add_rrsigs(label, pkt_out + len, buf_len, q1, &h->nscount);
                if (res < 0) {
                    return -1;
                }
                len += res;
                buf_len -= res;
            }
        }
    }

    return len;
}

int nsec3_name_error(request_context_t* context, response_info_t* response_info, char* pkt_out, int buf_len, struct dns_header* h,
    int* found_nsec3_when_needed, dns_resource* params, char* apex, int apex_len, nsec3_hash_t* already_added_hashes)
{
    int len = 0, res;

    dns_data_t* dns_data = context->dns_data;
    dns_domain_rrs_t* nsec_data = context->dnssec_nsec_data;
    dns_question q = response_info->q;

    char domain[DNS_MAX_DOMAIN_LENGTH + 1];
    int domain_len = dns_domain_decode(apex, domain);

    dns_domain d = { domain, (unsigned char)(domain_len - 2) };
    dns_domain_rrs_iter_t iter = nsec_data->find(d);
    if (iter == nsec_data->end())
        return 0;

    // find closest encloser and keep track of the next encloser
    bool found_closest_encloser = false;

    char* closest_encloser = q.name;
    int closest_encloser_len = q.len;

    char* next_closer = q.name;
    int next_closer_len = q.len;

    while (closest_encloser_len > 0 && *closest_encloser && !found_closest_encloser) {
        closest_encloser_len -= (*closest_encloser + 1);
        closest_encloser += *closest_encloser + 1;

        dns_domain domainObj;
        domainObj.name = closest_encloser;
        domainObj.len = closest_encloser_len;
        if (dns_data_get_label(context, &domainObj, 0) != NULL) {
            found_closest_encloser = true;
        } else {
            next_closer_len -= (*next_closer + 1);
            next_closer += (*next_closer + 1);
        }
    }

    if (found_closest_encloser) {
        // nsec3 that matches the closest encloser
        res = nsec3_find_and_pack_direct_match(context, dns_data, closest_encloser, closest_encloser_len, params,
            apex, apex_len, h, pkt_out + len, buf_len,
            found_nsec3_when_needed, already_added_hashes);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;

        if (!*found_nsec3_when_needed) {
            h->nscount -= 0;
            return 0;
        }

        // nsec3 that covers the next closer
        res = nsec3_find_and_add_covering_rr(context, &iter->second, next_closer, next_closer_len, params,
            h, pkt_out + len, buf_len,
            found_nsec3_when_needed, already_added_hashes);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;

        if (!*found_nsec3_when_needed) {
            h->nscount -= 1;
            return 0;
        }

        char wildcard[DNS_MAX_DOMAIN_LENGTH + 1] = "\1*";
        memcpy(wildcard + 2, closest_encloser, closest_encloser_len);
        int wildcard_len = closest_encloser_len + 2;

        // nsec3 that matches the wildcard rr at the closest encloser
        res = nsec3_find_and_add_covering_rr(context, &iter->second, wildcard, wildcard_len, params,
            h, pkt_out + len, buf_len,
            found_nsec3_when_needed, already_added_hashes);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;

        if (!*found_nsec3_when_needed) {
            h->nscount -= 2;
            return 0;
        }
    }

    return len;
}

int nsec3_wildcard_hit(request_context_t* context, response_info_t* response_info, char* pkt_out, int buf_len, struct dns_header* h,
    int* found_nsec3_when_needed, dns_resource* params, char* apex, int apex_len, nsec3_hash_t* already_added_hashes)
{
    int len = 0, res;

    dns_data_t* dns_data = context->dns_data;
    dns_domain_rrs_t* nsec_data = context->dnssec_nsec_data;

    // find next closer name:
    //  0. (e.g. qname = a.z.w.example.)
    //  1. find the wildcard name that matches (*.w.example)
    //  2. take the ancestor of the wildcard (w.example)
    //  3. take the next closer name (z.w.example)
    //  4. prove that it doesn't exist by providing an nsec
    //      that covers the hash of the next closer name
    //      .e.g. nsec.owner_name < hash(z.w.example) < nsec.next_owner_name

    char* next_closer;
    int next_closer_len;
    bool wildcard_found = nsec3_find_wildcard_next_closer(response_info, &next_closer, &next_closer_len);
    if (wildcard_found) {
        char domain[DNS_MAX_DOMAIN_LENGTH + 1];
        int domain_len = dns_domain_decode(apex, domain);

        dns_domain d = { domain, (unsigned char)(domain_len - 2) };
        dns_domain_rrs_iter_t iter = nsec_data->find(d);
        if (iter != nsec_data->end()) {
            res = nsec3_find_and_add_covering_rr(context, &iter->second, next_closer,
                next_closer_len, params, h, pkt_out + len, buf_len,
                found_nsec3_when_needed, already_added_hashes);

            if (res < 0) {
                return -1;
            }
            len += res;
            buf_len -= res;
        }
    }

    // bug for bug compatible with bind9 if enabled
    // bind9 returns the closest provable encloser on a direct wildcard hit.
    // This isn't strictly necessary at all, because the existance of the closest encloser
    // is proven by the presence of the expanded wildcard in the answer section.
    if (dnssec_nsec3_bind9_wildcard_compatibility) {
#ifdef NSEC3_DEBUG
        printf("NSEC3: wildcard hit, adding extra NSEC3 for bind compatiblity\n");
#endif //NSEC3_DEBUG

        // nsec3 that matches the closest encloser
        char* closest_encloser = next_closer + *next_closer + 1;
        int closest_encloser_len = next_closer_len - (*next_closer + 1);

        // nsec3 that matches the closest encloser
        res = nsec3_find_and_pack_direct_match(context, dns_data, closest_encloser, closest_encloser_len, params,
            apex, apex_len, h, pkt_out + len, buf_len,
            found_nsec3_when_needed, already_added_hashes);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
    }

    return len;
}

int nsec3_check_wildcard_nodata_hit(request_context_t* context, response_info_t* response_info, char* pkt_out, int buf_len, struct dns_header* h,
    int* found_nsec3_when_needed, dns_resource* params, char* apex, int apex_len, nsec3_hash_t* already_added_hashes)
{
    int len = 0, res;

    dns_data_t* dns_data = context->dns_data;
    dns_domain_rrs_t* nsec_data = context->dnssec_nsec_data;

    // 2) check for a wildcard hit
    char* next_closer;
    int next_closer_len;
    bool wildcard_found = nsec3_find_wildcard_next_closer(response_info, &next_closer, &next_closer_len);
    if (wildcard_found) {
        char domain[DNS_MAX_DOMAIN_LENGTH + 1];
        int domain_len = dns_domain_decode(apex, domain);

        dns_domain d = { domain, (unsigned char)(domain_len - 2) };
        dns_domain_rrs_iter_t iter = nsec_data->find(d);
        if (iter == nsec_data->end())
            return 0;

        // nsec3 that matches the closest encloser
        char* closest_encloser = next_closer + *next_closer + 1;
        int closest_encloser_len = next_closer_len - (*next_closer + 1);

        // nsec3 that matches the closest encloser
        res = nsec3_find_and_pack_direct_match(context, dns_data, closest_encloser, closest_encloser_len, params,
            apex, apex_len, h, pkt_out + len, buf_len,
            found_nsec3_when_needed, already_added_hashes);
        if (res < 0) {
            return 1;
        }
        len += res;
        buf_len -= res;
        if (!*found_nsec3_when_needed) {
            h->nscount -= 0;
            return 0;
        }

        // nsec3 that covers the next closer
        res = nsec3_find_and_add_covering_rr(context, &iter->second, next_closer, next_closer_len, params,
            h, pkt_out + len, buf_len,
            found_nsec3_when_needed, already_added_hashes);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
        if (!*found_nsec3_when_needed) {
            h->nscount -= 1;
            return 0;
        }

        char wildcard[DNS_MAX_DOMAIN_LENGTH + 1] = "\1*";
        memcpy(wildcard + 2, closest_encloser, closest_encloser_len);
        int wildcard_len = closest_encloser_len + 2;

        // nsec3 that matches the wildcard rr at the closest encloser
        res = nsec3_find_and_pack_direct_match(context, dns_data, wildcard, wildcard_len, params,
            apex, apex_len, h, pkt_out + len, buf_len,
            found_nsec3_when_needed, already_added_hashes);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
        if (!*found_nsec3_when_needed) {
            h->nscount -= 2;
            return 0;
        }
    }

    return len;
}

int nsec3_name_error_or_no_data(request_context_t* context, response_info_t* response_info, char* pkt_out, int buf_len, struct dns_header* h,
    int* found_nsec3_when_needed, dns_resource* params, char* apex, int apex_len, nsec3_hash_t* already_added_hashes, int* is_empty_non_terminal_nsec3)
{
    // name error or no data, 3 possibilities:
    //  1) empty non-terminal hit -> search for a hit on hash name
    //  2) wildcard hit without data -> search for a matching wildcard (must be after 1,
    //      consider existing rr a.y.w.example and *.w.example -> the wildcard would
    //      hit before the empty non terminal y.w.example otherwise)
    //  3) name does not exist

    int len = 0;

    dns_data_t* dns_data = context->dns_data;
    dns_question q = response_info->q;

    // 1) empty non-terminal
    int did_find_direct_match_nsec3 = 0;
    int added_len = nsec3_find_and_pack_direct_match(context, dns_data, q.name, q.len, params,
        apex, apex_len, h, pkt_out + len, buf_len,
        &did_find_direct_match_nsec3, already_added_hashes);
    if (added_len < 0) {
        return -1;
    }
    if (did_find_direct_match_nsec3) {
        if (found_nsec3_when_needed != NULL)
            *found_nsec3_when_needed = 1;

#ifdef NSEC3_DEBUG
        printf("NSEC3: empty non-terminal: no data\n");
#endif //NSEC3_DEBUG
        len += added_len;
        buf_len -= added_len;

        // matching empty non-terminal
        // RFC5155, 7.2.3. No Data Responses, QTYPE is not DS
        // RFC5155, 7.2.4. No Data Responses, QTYPE is DS   -> this is okay, this NSEC3 proves the non-existance of the DS record
        if (is_empty_non_terminal_nsec3 != NULL)
            *is_empty_non_terminal_nsec3 = 1;
    } else {
        // XXX: RFC5155, 7.2.4. No Data Responses, QTYPE is DS ????

        //  2) wildcard hit without data
        // RFC5155, 7.2.3. No Data Responses, QTYPE is not DS
        int did_matched_wildcard_nodata_nsec3 = 0;

        int added_len = nsec3_check_wildcard_nodata_hit(context, response_info, pkt_out + len, buf_len, h, &did_matched_wildcard_nodata_nsec3, params, apex, apex_len, already_added_hashes);
        if (added_len < 0) {
            return -1;
        }
        if (did_matched_wildcard_nodata_nsec3) {
            if (found_nsec3_when_needed != NULL)
                *found_nsec3_when_needed = 1;

#ifdef NSEC3_DEBUG
            printf("NSEC3: wildcard hit: no data\n");
#endif //NSEC3_DEBUG
            len = added_len;
        } else {
#ifdef NSEC3_DEBUG
            printf("NSEC3: name error\n");
#endif //NSEC3_DEBUG
            //  3) name does not exist (NAMEERROR)
            // RFC5155, 7.2.2. Name Error Responses
            len = nsec3_name_error(context, response_info, pkt_out + len, buf_len, h, found_nsec3_when_needed, params, apex, apex_len, already_added_hashes);
        }
    }

    return len;
}

int dnssec_add_nsec3s_for_response_info(request_context_t* context, response_info_t* response_info, char* pkt_out, int buf_len, struct dns_header* h,
    int* found_nsec3_when_needed, int* is_empty_non_terminal_nsec3, nsec3_hash_t* already_added_hashes)
{
    int len = 0;
    dns_data_t* dns_data = context->dns_data;

    char* apex = 0;
    int apex_len = 0;
    dns_resource* params = nsec3_find_params(context, response_info, &apex, &apex_len);
    if (NULL == params) {
#ifdef NSEC3_DEBUG
        printf("NSEC3: no NSEC3PARAMS found\n");
#endif
        return 0;
    }

    if (is_empty_non_terminal_nsec3 != NULL) {
        *is_empty_non_terminal_nsec3 = 0;
    }

    // HANDLING

    if (response_info->is_delegation) {
        // RFC5155, 7.2.7. Referrals to Unsigned Subzones

        if (!response_info->is_secure_delegation) {
#ifdef NSEC3_DEBUG
            printf("NSEC3: insecure delegation: needs nsec3 for the direct hit\n");
#endif //NSEC3_DEBUG
            // if this is a query for NS records on an insecure subzone delegation,
            // we should return the matching NSEC3 per RFC5155 (7.2.7) to prove there
            // are no DS records (the NSEC3 proves this with its types field) under
            // this label.

            len = nsec3_find_and_pack_direct_match(context, dns_data, response_info->delegation_name, response_info->delegation_name_len, params, apex, apex_len, h, pkt_out + len, buf_len, found_nsec3_when_needed, already_added_hashes);
        } else {
#ifdef NSEC3_DEBUG
            printf("NSEC3: secure delegation: DS records present with RRSIGS\n");
#endif //NSEC3_DEBUG
            // thisis a secure subzone delegation, since there are DS records. We do not need to return
            // any NSEC3s, since the existance of the DS records will prove the secure-ness of the delegation.
            // the NS-response should include these DS records, which will be signed, making it possible
            // to validate our response.
            if (found_nsec3_when_needed != NULL)
                *found_nsec3_when_needed = true;
        }
    } else if (response_info->is_name_error || response_info->is_no_data) {
#ifdef NSEC3_DEBUG
        printf("NSEC3: name error OR no data\n");
#endif //NSEC3_DEBUG
        // RFC5155, 7.2.2. Name Error Responses or 7.2.3. No Data Responses, QTYPE is not DS or 7.2.4. No Data Responses, QTYPE is DS
        *found_nsec3_when_needed = 0;
        len = nsec3_name_error_or_no_data(context, response_info, pkt_out + len, buf_len, h, found_nsec3_when_needed, params, apex, apex_len, already_added_hashes, is_empty_non_terminal_nsec3);

    } else if (response_info->is_wildcard_hit) {
#ifdef NSEC3_DEBUG
        printf("NSEC3: wildcard hit\n");
#endif //NSEC3_DEBUG
        // RFC5155, 7.2.6. Wildcard Answer Responses
        len = nsec3_wildcard_hit(context, response_info, pkt_out + len, buf_len, h, found_nsec3_when_needed, params, apex, apex_len, already_added_hashes);
    } else {
        *found_nsec3_when_needed = true;
#ifdef NSEC3_DEBUG
        printf("NSEC3: direct hit, RRSIGS present or not signed\n");
#endif //NSEC3_DEBUG
    }

    return len;
}

int dnssec_add_nsec3s(request_context_t* context, char* pkt_out, int buf_len, struct dns_header* h, int* found_nsec3_when_needed, int* is_empty_non_terminal_nsec3)
{
    int len = 0, res;
    nsec3_hash_t* already_added_hashes = (nsec3_hash_t*)malloc(sizeof(nsec3_hash_t) * DNS_MAX_NEEDED_NSEC3_RECORDS * (context->number_of_response_infos)); // already known hashes
    for (int i = 0; i < DNS_MAX_NEEDED_NSEC3_RECORDS * (context->number_of_response_infos); i++) {
        already_added_hashes[i][0] = '\0';
    }

    if (context->number_of_response_infos > 1) {
        is_empty_non_terminal_nsec3 = NULL; // there's no point in checking for non empty terminals when we are following a CNAME chain
    }

#ifdef NSEC3_DEBUG
    printf("NSEC3: looking for NSEC3 records (num chains:  %d)\n", context->number_of_response_infos);
#endif //NSEC3_DEBUG

    // loop over each response info, so we do an NSEC3 lookup for each part of a CNAME chain also
    // we say we found all nsec3 records when needed, when each part of the chain has its nsec3 records found.
    int added_all_nsec3s = 1;
    for (int i = 0; i < context->number_of_response_infos; ++i) {
        response_info_t* response_info = &context->response_info_chain[i];

#ifdef NSEC3_DEBUG
        printf("%d from %d:\n", i + 1, context->number_of_response_infos);
        response_info->debug_print();
#endif //NSEC3_DEBUG

        int added_nsec3s = 0;
        res = dnssec_add_nsec3s_for_response_info(context, response_info, pkt_out + len, buf_len, h, &added_nsec3s, is_empty_non_terminal_nsec3, already_added_hashes);
        if (res < 0) {
            free(already_added_hashes);
            return -1;
        }
        len += res;
        buf_len -= res;
        added_all_nsec3s &= added_nsec3s;

#ifdef NSEC3_DEBUG
        printf("==================\n\n");
#endif //NSEC3_DEBUG
    }

    if (found_nsec3_when_needed != NULL) {
        *found_nsec3_when_needed = added_all_nsec3s;
    }

    free(already_added_hashes);

    return len;
}
