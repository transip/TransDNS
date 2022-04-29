#include "dns_data.h"
#include "dns.h"
#include "dns_compress.h"
#include "dns_util.h"
#include "edns.h"
#include "nsec3.h"
#include "request_context.h"
#include "settings.h"
#include <arpa/inet.h>
#include <cassert>
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <syslog.h>

using namespace std;

static dns_resource_v empty_v; // empty vector, used by reference when needed, so we don't do an unnessary memory allocation
typedef char nsec_name_t[DNS_MAX_DOMAIN_LENGTH + 1]; // a fqdn, nsec label name

dns_label* dns_data_get_label(request_context_t* context, dns_domain* domain, int wildcard_level = 0)
{
    dns_data_iter_t iter;
    dns_data_t* dns_data = context->dns_data;
    int i;

    if (wildcard_level > 0) {
        for (i = 0; i < wildcard_level; ++i) {
            if (dns_wildcard_encode(domain) <= 0)
                return NULL;
        }
    }

    iter = dns_data->find(*domain);
    if (iter != dns_data->end())
        return &iter->second;

    return NULL;
}

struct dns_resource_type* dns_data_get_record_type_data(dns_label* label, uint16 type)
{
    dns_resource_type_v* rrTypesVector;
    struct dns_resource_type* recordType;

    if (label == NULL)
        return NULL;

    rrTypesVector = &label->recordtypes;

    int size = rrTypesVector->size();

    for (; size > 0; --size) {
        recordType = &(*rrTypesVector)[size - 1];
        if (recordType->rtype == type) {
            // Yay FOUND!
            return recordType;
        }
    }
    return NULL;
}

bool dns_data_label_has_only_nsec3s(dns_label* label)
{
    dns_resource_type_v* rrTypesVector;
    struct dns_resource_type* recordType;

    if (label == NULL)
        return true;

    rrTypesVector = &label->recordtypes;

    if (rrTypesVector->empty()) {
        // This is an Empty Non Terminal so we need to treat it like a normal label not an NSEC3 label
        return false;
    }

    int size = rrTypesVector->size();

    for (; size > 0; --size) {
        recordType = &(*rrTypesVector)[size - 1];
        if (recordType->rtype != DNS_TYPE_NSEC3 && recordType->rtype != DNS_TYPE_RRSIG) {
            // Yay FOUND!
            return false;
        }
    }
    return true;
}

int dns_data_answer_add_rrsigs(dns_label* label, char* pkt_out, int buf_len, dns_question& q, uint16* countHeaderField, uint32 overrideTtl)
{
    int len = 0, size, res;
    dns_question q1;
    dns_resource_type* rrsigType = dns_data_get_record_type_data(label, DNS_TYPE_RRSIG);

    if (rrsigType != NULL) {
        dns_resource_v* rrsigRecords = &rrsigType->records;
        q1 = q;
        q1.qtype = DNS_TYPE_RRSIG;
        for (size = rrsigRecords->size(); size > 0; size--) {
            dns_resource* rrsigRecord = &(*rrsigRecords)[size - 1];
            uint16 rrsigType;
            dns_uint16_decode(rrsigRecord->rdata, &rrsigType);
            if (rrsigType == q.qtype) {
                if (overrideTtl > 0) {
                    dns_resource record;
                    record.id = rrsigRecord->id;
                    record.rclass = rrsigRecord->rclass;
                    record.rdata = rrsigRecord->rdata;
                    record.rtype = rrsigRecord->rtype;
                    record.rdlength = rrsigRecord->rdlength;
                    record.ttl = overrideTtl;
                    res = dns_resource_encode(record, q1, pkt_out + len, buf_len);
                    if (res < 0) {
                        return -1;
                    }
                    len += res;
                    buf_len -= res;
                } else {
                    res = dns_resource_encode(*rrsigRecord, q1, pkt_out + len, buf_len);
                    if (res < 0) {
                        return -1;
                    }
                    len += res;
                    buf_len -= res;
                }
                ++(*countHeaderField);
            }
        }
    }
    return len;
}

int dns_data_answer_common(request_context_t* context, dns_label* label, dns_question& q, char* pkt_out, int buf_len, struct dns_header* h, int wildcard_level = 0)
{
    int size, len, res;
    dns_resource* r;
    dns_resource_v *recordVector = NULL, v_temp;
    dns_resource_type* typeData = NULL;

    if (label == NULL)
        return 0;

    len = 0;

    typeData = dns_data_get_record_type_data(label, q.qtype);

    if (typeData == NULL)
        return 0;

    recordVector = &typeData->records;

    if (recordVector == NULL)
        return 0;

    size = recordVector->size();

    if (size != 0) {
        if (size > 1) {
            v_temp = *recordVector;
            random_shuffle(v_temp.begin(), v_temp.end());
            recordVector = &v_temp;
        }
        for (; size > 0; --size) {
            r = &(*recordVector)[size - 1];
            ++h->ancount;
            res = dns_resource_encode(*r, q, pkt_out + len, buf_len);
            if (res < 0) {
                return -1;
            }
            len += res;
            buf_len -= res;
        }
    }

    if (len > 0 && context->dnssec_do) {
        res = dns_data_answer_add_rrsigs(label, pkt_out + len, buf_len, q, &h->ancount);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
    }

    return len;
}

int dns_data_answer_single_record(request_context_t* context, dns_label* label, dns_question& q, char* pkt_out, int buf_len, struct dns_header* h, int wildcard_level = 0)
{
    int size, len, res;
    dns_resource* r;
    dns_resource_v* recordVector = NULL;
    dns_resource_type* typeData = NULL;

    if (label == NULL)
        return 0;

    len = 0;

    typeData = dns_data_get_record_type_data(label, q.qtype);

    if (typeData == NULL)
        return 0;

    recordVector = &typeData->records;

    if (recordVector == NULL)
        return 0;

    size = recordVector->size();

    if (size != 0) {
        r = &(*recordVector)[0];
        ++h->ancount;
        res = dns_resource_encode(*r, q, pkt_out + len, buf_len);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
    }

    if (len > 0 && context->dnssec_do) {
        res = dns_data_answer_add_rrsigs(label, pkt_out + len, buf_len, q, &h->ancount);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
    }

    return len;
}

//dont forget the trailing '.'!
int dns_data_answer_ns(request_context_t* context, dns_label* label, dns_question& q, char* pkt_out, int buf_len, struct dns_header* h, int wildcard_level = 0)
{
    int original_ancount = h->ancount;
    int len = 0, res;
    res = dns_data_answer_common(context, label, q, pkt_out, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;

    // DNSSEC: return DS records for secure delegations
    if (len > 0) {
        response_info_t* info = context->get_current_response_info();
        info->is_delegation = !dns_data_soa_exists(label);

        if (info->is_delegation) {
            // We are not authorative in this case
            h->flags = DNS_HEADER_AA_UNSET(h->flags, 1);
            if (context->dnssec_do) {
                info->assign_delegation_name(q);

                dns_question q_ds = q;
                q_ds.qtype = DNS_TYPE_DS;

                int ds_len = dns_data_answer_common(context, label, q_ds, pkt_out + len, buf_len, h, wildcard_level);
                if (ds_len < 0) {
                    return -1;
                }
                len += ds_len;
                buf_len -= ds_len;
                info->is_secure_delegation = ds_len > 0;
            }
            // Since we are not authoritative here for this zone this means the NS records should be set in the authority section not the answer section
            h->nscount = h->ancount - original_ancount;
            h->ancount = original_ancount;
        }
    }

    return len;
}

bool dns_data_soa_exists(dns_label* label)
{
    return (label != NULL && dns_data_get_record_type_data(label, DNS_TYPE_SOA) != NULL);
}

int dns_data_answer_cname(request_context_t* context, dns_label* label, dns_question* q, char* pkt_out, int buf_len, struct dns_header* h, bool copy_answer_to_question = true, int wildcard_level = 0)
{
    int size, len, res;
    dns_resource* r;
    dns_resource_v* recordVector = NULL;
    dns_resource_type* typeData = NULL;

    if (label == NULL)
        return 0;

    len = 0;

    typeData = dns_data_get_record_type_data(label, q->qtype);

    if (typeData == NULL)
        return 0;

    recordVector = &typeData->records;

    if (recordVector == NULL)
        return 0;

    size = recordVector->size();

    if (size != 0) {
        r = &(*recordVector)[0];
        ++h->ancount;
        res = dns_resource_encode(*r, *q, pkt_out + len, buf_len);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
        if (len > 0 && context->dnssec_do) {
            res = dns_data_answer_add_rrsigs(label, pkt_out + len, buf_len, *q, &h->ancount);
            if (res < 0) {
                return -1;
            }
            len += res;
            buf_len -= res;
        }
        if (copy_answer_to_question) {
            memmove(q->name, r->rdata, r->rdlength);
            q->qtype = r->rtype;
            q->len = r->rdlength;
        }
    }

    return len;
}

int dns_data_answer_any(request_context_t* context, dns_label* label, dns_question& q, char* pkt_out, int buf_len, struct dns_header* h, int wildcard_level = 0)
{
    int len, qtype, res;

    len = 0;
    qtype = q.qtype;

    q.qtype = DNS_TYPE_A;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    q.qtype = DNS_TYPE_AAAA;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    q.qtype = DNS_TYPE_MX;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    q.qtype = DNS_TYPE_NS;
    res = dns_data_answer_ns(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    if (wildcard_level == 0) {
        q.qtype = DNS_TYPE_SOA;
        res = dns_data_answer_single_record(context, label, q, pkt_out + len, buf_len, h);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
    }
    q.qtype = DNS_TYPE_TXT;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    q.qtype = DNS_TYPE_SPF;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    q.qtype = DNS_TYPE_SRV;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    q.qtype = DNS_TYPE_CNAME;
    res = dns_data_answer_cname(context, label, &q, pkt_out + len, buf_len, h, false, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    if (wildcard_level == 0) {
        q.qtype = DNS_TYPE_PTR;
        res = dns_data_answer_single_record(context, label, q, pkt_out + len, buf_len, h);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
    }
    q.qtype = DNS_TYPE_DNSKEY;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    q.qtype = DNS_TYPE_SSHFP;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    q.qtype = DNS_TYPE_TLSA;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;

    if (!context->dnssec_do) {
        q.qtype = DNS_TYPE_RRSIG;
        res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
    }

    q.qtype = DNS_TYPE_NSEC3PARAM;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    q.qtype = DNS_TYPE_CAA;
    res = dns_data_answer_common(context, label, q, pkt_out + len, buf_len, h, wildcard_level);
    if (res < 0) {
        return -1;
    }
    len += res;
    buf_len -= res;
    // xxx? don't output with any
    //q.qtype = DNS_TYPE_NSEC;
    //len += dns_data_answer_nsec(context, q, pkt_out+len, h, false);
    q.qtype = qtype;

    return len;
}

int dns_data_answer_type(request_context_t* context, dns_label* label, dns_question& q, char* pkt_out, int buf_len, struct dns_header* h, int wildcard_level = 0)
{
    int len = 0;
    switch (q.qtype) {
#ifdef DEBUG_DNSSEC
    /*
     * This is only for debugging purposes, these records should
     * not actually be queriable since they are only used for
     * dnssec validation.
     */
    case DNS_TYPE_NSEC:
    case DNS_TYPE_NSEC3:
#endif
    case DNS_TYPE_A:
    case DNS_TYPE_MX:
    case DNS_TYPE_TXT:
    case DNS_TYPE_SPF:
    case DNS_TYPE_AAAA:
    case DNS_TYPE_SRV:
    case DNS_TYPE_DS:
    case DNS_TYPE_RRSIG:
    case DNS_TYPE_NSEC3PARAM:
    case DNS_TYPE_SSHFP:
    case DNS_TYPE_TLSA:
    case DNS_TYPE_DNSKEY:
    case DNS_TYPE_CAA:
        return dns_data_answer_common(context, label, q, pkt_out, buf_len, h, wildcard_level);

    case DNS_TYPE_CNAME:
        return dns_data_answer_cname(context, label, &q, pkt_out, buf_len, h, true, wildcard_level);

    case DNS_TYPE_PTR:
        len = dns_data_answer_single_record(context, label, q, pkt_out, buf_len, h, wildcard_level);
        return len;

    case DNS_TYPE_SOA:
        return dns_data_answer_single_record(context, label, q, pkt_out, buf_len, h, wildcard_level);

    case DNS_TYPE_NS:
        return dns_data_answer_ns(context, label, q, pkt_out, buf_len, h, wildcard_level);

    case DNS_TYPE_ANY:
        return dns_data_answer_any(context, label, q, pkt_out, buf_len, h, wildcard_level);

    default:
        //syslog(LOG_ERR, "Non implemented type: %d\n", q.qtype);
        return 0;
    }
}

int dns_data_answer_record(request_context_t* context, dns_question* q, char* pkt_out, int buf_len, struct dns_header* h, bool is_cname_redirect, int zone_id)
{
    int len, is_soa, wildcard_level, has_a_record;
    uint16 type;
    struct dns_header temp_header;
    struct dns_domain domainName, mainDomainName;
    struct dns_label *label = NULL, *mainLabel = NULL;
    char qname[DNS_MAX_DOMAIN_LENGTH + 1];

    type = q->qtype;

    memmove(qname, q->name, q->len);
    domainName.name = qname;
    domainName.len = q->len;
    label = dns_data_get_label(context, &domainName);

    // zone_id should always be non-zero when is_cname_redirect is true
    if (label != 0 && is_cname_redirect && label->zone_id != zone_id) {
        return -2;
    }

    len = 0;
    if (!dns_data_label_has_only_nsec3s(label))
        len = dns_data_answer_type(context, label, *q, pkt_out, buf_len, h);

    if (len == -1) {
        return -1;
    }

    if (len > 0) {
        // direct hit
        // possibly needed (andreasv)?  if(type != DNS_TYPE_ANY  && !context->get_current_response_info()->is_wildcard_hit) )
        context->get_current_response_info()->is_direct_hit = true;
        return len;
    }

    // RANDOM HACK?
    q->qtype = DNS_TYPE_A;
    has_a_record = dns_data_answer_common(context, label, *q, pkt_out, buf_len, &temp_header) > 0;
    if (type == DNS_TYPE_CNAME && has_a_record > 0) {
        // MAGIC? context->get_current_response_info()->is_cname_redirection;
        return 0;
    }
    q->qtype = type;

    wildcard_level = 0;
    //Keep a notion of the wildcard level we are in.

    mainLabel = label;
    mainDomainName.name = domainName.name;
    mainDomainName.len = domainName.len;

    while (len == 0 && q->len > 0) {
        if (!has_a_record) {
            // cname redirection
            q->qtype = DNS_TYPE_CNAME;
            len = dns_data_answer_cname(context, label, q, pkt_out, buf_len, h, true, wildcard_level);
            if (len > 0) {
                context->get_current_response_info()->is_cname_redirection = true;
                context->get_current_response_info()->zone_id = label->zone_id;
                if (wildcard_level > 0) {
                    response_info_t* info = context->get_current_response_info();
                    info->is_wildcard_hit = true;
                    info->assign_wildcard_name(domainName);
                }
            } else if (len < 0) {
                return -1;
            }
            q->qtype = type;
        }

        is_soa = dns_data_soa_exists(mainLabel);
        if (len == 0 && !is_soa) {

            // check to see if this is a zone-cut, in which case we are not authoritive for anything under the
            // zone-cut. First check if there are delegation (NS) records, indicating a delegation
            // Do not do this if the question concerns a DS record since those cannot be delegated.
            dns_question q2 = *q;
            q2.name = mainDomainName.name;
            q2.len = mainDomainName.len;
            q2.qtype = DNS_TYPE_NS;

            dns_header ns_header = { 0 };
            int temp_len = dns_data_answer_ns(context, mainLabel, q2, pkt_out, buf_len, &ns_header);

            // if we have NS records, but we do have a SOA over these NS records, we are in the zone apex
            // and thus authoritive by default.
            if (temp_len > 0 && !dns_data_soa_exists(mainLabel)) {
                // delegation, response_info will be set by dns_data_answer_ns
                // We are not authorative in this case
                if (type == DNS_TYPE_DS) {
                    break;
                }
                h->flags = DNS_HEADER_AA_UNSET(h->flags, 1);
                len = temp_len;
                // Since we are not authoritative here this means we should set records in the authority section
                // not in the answer section.
                h->nscount += ns_header.nscount;
            }

            if (temp_len < 0) {
                return -1;
            }
        }

        if (len == 0) {
            //once we cannot find anymore subsections to wildcard or we are crossing an authority boundary, there's no point in calling subfunctions. We're simply done and have found nothing.
            if (is_soa || dns_wildcard_encode(&domainName) <= 0 || domainName.len <= 0)
                break;

            if ((mainLabel != NULL && !dns_data_label_has_only_nsec3s(mainLabel)) || label != NULL) {
                // Empty Non Terminal
                break;
            }

            ++wildcard_level;
            label = dns_data_get_label(context, &domainName);

            // zone_id should always be non-zero when is_cname_redirect is true
            if (label != 0 && is_cname_redirect && label->zone_id != zone_id) {
                return -2;
            }

            len = dns_data_answer_type(context, label, *q, pkt_out, buf_len, h, wildcard_level);

            response_info_t* info = context->get_current_response_info();
            if (label != NULL && (!info->is_wildcard_hit || len > 0)) {
                info->is_wildcard_hit = true;
                info->assign_wildcard_name(domainName);
            }

            if (len == 0) {
                mainDomainName.name = domainName.name + 2;
                mainDomainName.len = domainName.len - 2;
                mainLabel = dns_data_get_label(context, &mainDomainName);

                // zone_id should always be non-zero when is_cname_redirect is true
                if (mainLabel != 0 && is_cname_redirect && mainLabel->zone_id != zone_id) {
                    return -2;
                }
            } else if (len < 0) {
                return -1;
            }
        }
    }

    return len;
}

int dns_data_authority(request_context_t* context, dns_question& q, char* pkt_out, int buf_len, struct dns_header* h)
{
    dns_question q1;
    dns_domain domainName;
    dns_data_iter_t iter;
    dns_resource* r;
    dns_resource_v* recordVector = NULL;
    dns_resource_type* typeData = NULL;
    char qname[DNS_MAX_DOMAIN_LENGTH + 1];
    struct dns_label *queryLabel = NULL, *label = NULL;
    int len = 0, res;
    int size;

    q1 = q;
    q1.qtype = DNS_TYPE_SOA;
    q1.name = qname;
    memmove(q1.name, q.name, q.len);

    domainName.name = q1.name;
    domainName.len = q1.len;

    queryLabel = dns_data_get_label(context, &domainName);
    label = queryLabel;

    while (!dns_data_soa_exists(label) && domainName.name[0] != 0) {
        if (domainName.name[0] + 1 >= domainName.len) {
            context->get_current_response_info()->is_unknown_zone = true;
            return 0;
        }
        domainName.len -= domainName.name[0] + 1;
        memmove(domainName.name, domainName.name + domainName.name[0] + 1, domainName.len);
        label = dns_data_get_label(context, &domainName);
    }

    q1.name = domainName.name;
    q1.len = domainName.len;

    typeData = dns_data_get_record_type_data(label, DNS_TYPE_SOA);

    if (typeData == NULL) {
        context->get_current_response_info()->is_unknown_zone = true;
        return 0;
    } else {
        recordVector = &typeData->records;

        if (recordVector == NULL)
            return 0;

        size = recordVector->size();

        if (size == 0)
            return 0;

        r = &(*recordVector)[0];

        if (!context->get_current_response_info()->is_wildcard_hit && (queryLabel == NULL || dns_data_label_has_only_nsec3s(queryLabel))) {
            context->get_current_response_info()->is_name_error = true;
            h->flags = DNS_HEADER_RCODE_SET(h->flags, DNS_RCODE_NAMEERROR);
        } else {
            context->get_current_response_info()->is_no_data = true;
        }
        ++h->nscount;
        uint32 soaminTtl = 0;
        dns_uint32_decode((r->rdata + r->rdlength - 4), &soaminTtl);
        uint32 minTtl = min(r->ttl, soaminTtl);
        if (minTtl != r->ttl) {
            dns_resource record;
            record.id = r->id;
            record.rclass = r->rclass;
            record.rdata = r->rdata;
            record.rtype = r->rtype;
            record.rdlength = r->rdlength;
            record.ttl = minTtl;
            res = dns_resource_encode(record, q1, pkt_out, buf_len);
            if (res < 0) {
                return -1;
            }
            len += res;
            buf_len -= res;
        } else {
            res = dns_resource_encode(*r, q1, pkt_out, buf_len);
            if (res < 0) {
                return -1;
            }
            len += res;
            buf_len -= res;
        }

        if (len > 0 && context->dnssec_do) {
            res = dns_data_answer_add_rrsigs(label, pkt_out + len, buf_len, q1, &h->nscount, minTtl);
            if (res < 0) {
                return -1;
            }
            len += res;
            buf_len -= res;
        }

        return len;
    }
}

inline int dnssec_pack_nsec(request_context_t* context, dns_resource_named_v* nsecs, int index, dns_question& q, char* pkt_out, int buf_len, struct dns_header* h, nsec_name_t* already_added_names)
{
    if (index < 0)
        return 0;

    dns_resource_named* nsec = &((*nsecs)[index]);

    nsec_name_t name_to_compare = { 0 };
    memcpy(name_to_compare, nsec->name, nsec->name_len);

    for (int i = 0; i < DNS_MAX_NEEDED_NSEC_RECORDS * context->number_of_response_infos; ++i) {
        char* known_name = already_added_names[i];
        if (known_name[0] == '\0') {
            memmove(known_name, name_to_compare, DNS_MAX_DOMAIN_LENGTH + 1);
            break;
        }
        // we do use cmp_label_text here on a FQDN, but we can safely also ignore the length bytes of a FQDN as text.
        else if (dns_util::cmp_label_text(known_name, name_to_compare, DNS_MAX_DOMAIN_LENGTH) == 0) {
            return 0;
        }
    }

    dns_question q2 = { nsec->name, q.qtype, q.qclass, (unsigned char)nsec->name_len };
    int len = dns_resource_encode(*nsec, q2, pkt_out, buf_len);
    if (len < 0) {
        return -1;
    }

    h->nscount++;
    if (len > 0) {
        dns_domain domain;
        domain.name = nsec->name;
        domain.len = nsec->name_len;
        dns_label* label = dns_data_get_label(context, &domain);
        q2.qtype = DNS_TYPE_NSEC;
        int res = dns_data_answer_add_rrsigs(label, pkt_out + len, buf_len, q2, &h->nscount);
        if (res < 0) {
            return -1;
        }
        len += res;
        buf_len -= res;
    }

    return len;
}

int dnssec_find_closest_nsec_encloser(dns_resource_named_v* nsecs, char* name)
{
    int prev_index = -1;
    for (int i = 0; i < nsecs->size(); i++) {
        dns_resource_named* nsec = &((*nsecs)[i]);
        if (nsec->rtype != DNS_TYPE_NSEC)
            continue;

        if (dns_util::cmp_names_canonical(nsec->name, name) > 0) {
            if (prev_index >= 0) {
                return prev_index;
            }

            // Find last NSEC
            for (int j = ((int)nsecs->size())-1; j >= 0; --j) {
                dns_resource_named* nsec = &((*nsecs)[j]);
                if (nsec->rtype == DNS_TYPE_NSEC) {
                    return j;
                }
            }
            break;
        }
        prev_index = i;
    }
    return prev_index;
}

int dnssec_add_nsecs_for_response_info(request_context_t* context, response_info_t* info, char* pkt_out, int buf_len, struct dns_header* h, bool* found_nsec_when_needed, nsec_name_t* already_added_names)
{
    int pkt_out_len = 0, res;
    dns_domain_rrs_t* nsec_data = context->dnssec_nsec_data;

    char domain[DNS_MAX_DOMAIN_LENGTH + 1] = { 0 };
    char wildcard_on_domain[DNS_MAX_DOMAIN_LENGTH + 1] = { 0 };
    char* name_ptr = domain;
    int name_len = dns_domain_decode(info->q.name, domain);
    name_ptr[name_len] = '\0'; // remove the root zone dot
    name_len -= 2; // remove root zone dot and '\0'.

    dns_resource_named_v* nsecs = NULL;

    // Find NSEC's
    while (*name_ptr && name_len) {
        dns_domain d = { name_ptr, (unsigned char)name_len };
        dns_domain_rrs_iter_t iter = nsec_data->find(d);
        if (iter != nsec_data->end()) {
            nsecs = &iter->second;
            break;
        }
        while (*name_ptr && name_len-- && *name_ptr++ != '.');
    }

    if (nsecs == NULL) {
        // no NSEC's found for this domain
        return pkt_out_len;
    }

    if (info->is_no_data && !info->is_wildcard_hit) {
        // Direct hit case, we just need to prove the type doesn't exist
        for (int i = 0; i < nsecs->size(); i++) {
            // Check whether there are any NSEC3's hiding somewhere
            dns_resource_named* nsec = &((*nsecs)[i]);
            if (nsec->rtype != DNS_TYPE_NSEC)
                continue;

            if (dns_util::matches_name(nsec->name, info->q.name)) {
                res = dnssec_pack_nsec(context, nsecs, i, info->q, pkt_out + pkt_out_len, buf_len, h, already_added_names);
                if (res < 0) {
                    return -1;
                }
                pkt_out_len += res;
                buf_len -= res;
                return pkt_out_len;
            }
        }

        // If we can't find a direct match this might be a Empty Non Terminal, lets just add the closest encloser
        int closest_encloser = dnssec_find_closest_nsec_encloser(nsecs, info->q.name);

        if (closest_encloser < 0) {
            *found_nsec_when_needed = 0;
        } else {
            res = dnssec_pack_nsec(context, nsecs, closest_encloser, info->q, pkt_out + pkt_out_len, buf_len, h, already_added_names);
            if (res < 0) {
                return -1;
            }
            pkt_out_len += res;
            buf_len -= res;
        }

        return pkt_out_len;
    }

    if (info->is_wildcard_hit) {
        // Wildcard hit, we need to proof there is no closer encloser
        int closest_encloser = dnssec_find_closest_nsec_encloser(nsecs, info->q.name);

        if (closest_encloser < 0) {
            *found_nsec_when_needed = 0;
        } else {
            res = dnssec_pack_nsec(context, nsecs, closest_encloser, info->q, pkt_out + pkt_out_len, buf_len, h, already_added_names);
            if (res < 0) {
                return -1;
            }
            pkt_out_len += res;
            buf_len -= res;
        }

        if (info->is_no_data) {
            // We need to disprove the wildcard has the right data
             for (int i = 0; i < nsecs->size(); i++) {
                // Check whether there are any NSEC3's hiding somewhere
                dns_resource_named* nsec = &((*nsecs)[i]);
                if (nsec->rtype != DNS_TYPE_NSEC)
                    continue;

                if (dns_util::matches_name(nsec->name, info->wildcard_name)) {
                    res = dnssec_pack_nsec(context, nsecs, i, info->q, pkt_out + pkt_out_len, buf_len, h, already_added_names);
                    if (res < 0) {
                        return -1;
                    }
                    pkt_out_len += res;
                    buf_len -= res;
                    return pkt_out_len;
                }
             }

             // Somethings missing here
            *found_nsec_when_needed = 0;
        }
        return pkt_out_len;
    }

    if (info->is_name_error) {
        // We need to provide closest_encloser and potential wildcard closest encloser
        int closest_encloser = dnssec_find_closest_nsec_encloser(nsecs, info->q.name);

        if (closest_encloser < 0) {
            *found_nsec_when_needed = 0;
        } else {
            res = dnssec_pack_nsec(context, nsecs, closest_encloser, info->q, pkt_out + pkt_out_len, buf_len, h, already_added_names);
            if (res < 0) {
                return -1;
            }
            pkt_out_len += res;
            buf_len -= res;
        }

        int highest_matched_label_count = 0;
        int highest_matched_label_count_index = -1;
        int qname_label_count = dns_util::count_name_labels(info->q.name);
        int nsec_label_count = 0;
        for (int i = 0; i < nsecs->size(); i++) {
            bool no_match = false;
            dns_resource_named* nsec = &((*nsecs)[i]);
            if (nsec->rtype != DNS_TYPE_NSEC)
                continue;

            nsec_label_count = dns_util::count_name_labels(nsec->name);

            if (nsec_label_count <= highest_matched_label_count || nsec_label_count >= qname_label_count) {
                continue;
            }

            for (int j = 0; j < nsec_label_count; j++) {
                if (dns_util::cmp_label_in_name_from_right(info->q.name, qname_label_count, nsec->name, nsec_label_count, j) != 0) {
                    no_match = true;
                    break;
                }
            }
            if (!no_match) {
                highest_matched_label_count = nsec_label_count;
                highest_matched_label_count_index = i;
            }
        }

        if (highest_matched_label_count_index == -1) {
            *found_nsec_when_needed = 0;
            return pkt_out_len;
        }

        dns_resource_named* nsec = &((*nsecs)[highest_matched_label_count_index]);

        wildcard_on_domain[0] = '\1';
        wildcard_on_domain[1] = '*';
        memmove(wildcard_on_domain + 2, nsec->name, nsec->name_len);

        int wildcard_closest_encloser = dnssec_find_closest_nsec_encloser(nsecs, wildcard_on_domain);
        if (wildcard_closest_encloser < 0) {
            *found_nsec_when_needed = 0;
        } else {
            res = dnssec_pack_nsec(context, nsecs, wildcard_closest_encloser, info->q, pkt_out + pkt_out_len, buf_len, h, already_added_names);
            if (res < 0) {
                return -1;
            }
            pkt_out_len += res;
            buf_len -= res;
        }
        return pkt_out_len;
    }

    // Bit weird that we go here, but lets just move on
    return pkt_out_len;
}

int dnssec_add_nsecs(request_context_t* context, char* pkt_out, int buf_len, struct dns_header* h, bool* found_nsec_when_needed)
{
    int len = 0, res;
    nsec_name_t* already_added_names = (nsec_name_t*)malloc(sizeof(nsec_name_t) * DNS_MAX_NEEDED_NSEC_RECORDS * (context->number_of_response_infos)); // already known hashes
    for (int i = 0; i < DNS_MAX_NEEDED_NSEC_RECORDS * (context->number_of_response_infos); i++) {
        already_added_names[i][0] = '\0';
    }

    // loop over each response info, so we do an NSEC lookup for each part of a CNAME chain also
    // we say we found all nsec records when needed, when each part of the chain has its nsec records found.
    int added_all_nsecs = 1;
    for (int i = 0; i < context->number_of_response_infos; ++i) {
        response_info_t* response_info = &context->response_info_chain[i];

        bool added_nsecs = false;
        res = dnssec_add_nsecs_for_response_info(context, response_info, pkt_out + len, buf_len, h, &added_nsecs, already_added_names);
        if (res < 0) {
            free(already_added_names);
            return -1;
        }
        len += res;
        buf_len -= res;
        added_all_nsecs &= added_nsecs;
    }

    if (found_nsec_when_needed != NULL) {
        *found_nsec_when_needed = added_all_nsecs;
    }

    free(already_added_names);

    return len;
}

int send_truncated_response(char* pkt, int pkt_len, struct dns_header h, struct edns_options opts, bool do_edns, bool dnssec_do)
{
    h.flags = DNS_HEADER_TC_SET(h.flags, 1);
    h.ancount = 0;
    h.nscount = 0;
    h.arcount = 0;

    if (do_edns) {
        opts.extended_flags = DNS_EXT_HEADER_DO_SET(opts.extended_flags, dnssec_do ? 1 : 0);
        int y = edns_answer_packet(pkt + pkt_len, MAX_PACKET_SIZE - pkt_len, &h, &opts);
        if (y > 0) {
            pkt_len += y;
        } else {
            h.arcount = 0;
        }
    }

    dns_header_encode(h, pkt);

    return pkt_len;
}

int send_servfail_response(char* pkt, int pkt_len, struct dns_header h, struct edns_options opts, bool do_edns, bool dnssec_do)
{
    h.flags = DNS_HEADER_RCODE_SET(h.flags, DNS_RCODE_SERVERFAILURE);
    h.ancount = 0;
    h.nscount = 0;
    h.arcount = 0;

    if (do_edns) {
        opts.extended_flags = DNS_EXT_HEADER_DO_SET(opts.extended_flags, dnssec_do ? 1 : 0);
        int y = edns_answer_packet(pkt + pkt_len, MAX_PACKET_SIZE - pkt_len, &h, &opts);
        if (y > 0) {
            pkt_len += y;
        } else {
            h.arcount = 0;
        }
    }

    dns_header_encode(h, pkt);

    return pkt_len;
}

int send_badvers_response(char* pkt, int pkt_len, struct dns_header h, struct edns_options opts, bool do_edns, bool dnssec_do)
{
    h.flags = DNS_HEADER_RCODE_SET(h.flags, 0);
    h.ancount = 0;
    h.nscount = 0;
    h.arcount = 0;

    if (do_edns) {
        opts.extended_rcode = DNS_RCODE_BADVERS >> 4;
        opts.extended_flags = DNS_EXT_HEADER_DO_SET(opts.extended_flags, dnssec_do ? 1 : 0);
        int y = edns_answer_packet(pkt + pkt_len, MAX_PACKET_SIZE - pkt_len, &h, &opts);
        if (y > 0) {
            pkt_len += y;
        } else {
            h.arcount = 0;
        }
    }

    dns_header_encode(h, pkt);

    return pkt_len;
}

int dns_data_answer(request_context_t* context)
{
    char* pkt_in = context->buf;
    const int len = context->query_len;
    char* pkt_out;
    const bool is_udp = context->request_type == REQUEST_TYPE_UDP;

    int pkt_in_len, pkt_out_len = 0, x, y, z, buf_len, reslen, ednsres;
    struct dns_question q;
    struct dns_header h;
    bool loop_detected;
    struct dns_resource_fixed rf;
    char qname_buf[DNS_MAX_RDATA_LENGTH + 1];
    int max_udp_packet_size = DNS_MAX_UDP_PACKET;
    int do_edns_response = 0;

    struct edns_options opts = { 0 };
    int no_authority_found = 0;

    if (len < DNS_HEADER_LENGTH) {
        return 0;
    }

    pkt_in_len = dns_header_decode(pkt_in, &h);

    pkt_out_len = 0;
    h.ancount = 0;
    h.nscount = 0;
    h.arcount = 0;
    h.flags = DNS_HEADER_RA_UNSET(h.flags, 1); // remove the RA flag, since we are not a recursor and thus there is no recursion available
    h.flags = DNS_HEADER_RESERVED_UNSET(h.flags, 1); // remove the last RESERVED flag, since we don't know its meaning and thus it should be 0
    h.flags = DNS_HEADER_AD_UNSET(h.flags, 1); // remove the AD flag, since we don't validate any of the dnssec data at all (we are not a resolver)
    h.flags = DNS_HEADER_QR_SET(h.flags, 1);

    q.name = qname_buf;
    loop_detected = false;

    /*if( h.ancount!=0 )
        syslog(LOG_ERR, "WARNING! ANCount = %d", h.ancount);
    if( h.nscount!=0 )
        syslog(LOG_ERR, "WARNING! NSCount = %d", h.nscount);
    if( h.arcount!=0 )
        syslog(LOG_ERR, "WARNING! ARCount = %d", h.arcount);
    if( h.qdcount!= 1 )
        syslog(LOG_ERR, "WARNING! QDCount = %d", h.qdcount);
    if( DNS_HEADER_RCODE_GET(h.flags)!=0 )
        syslog(LOG_ERR, "WARNING! RCODE = %d", DNS_HEADER_RCODE_GET(h.flags));
    if( DNS_HEADER_QR_GET(h.flags)!=0 )
        syslog(LOG_ERR, "WARNING! QR = %d", DNS_HEADER_QR_GET(h.flags));
    //if( DNS_HEADER_OPCODE_GET(h.flags)!=0 )
    //  syslog(LOG_ERR, "WARNING! opcode = %d", DNS_HEADER_OPCODE_GET(h.flags));
    if( DNS_HEADER_TC_GET(h.flags)!=0 )
        syslog(LOG_ERR, "WARNING! TC = %d", DNS_HEADER_TC_GET(h.flags));
    */

    // Set the Authoritative Answer early on, so we can unset it in case of a subzone where we are not authorative.
    h.flags = DNS_HEADER_AA_SET(h.flags, 1);

    //for( x=0;x<h.qdcount;++x )
    {
        if ((len - pkt_in_len) < 6 || h.qdcount != 1) {
            // Invalid packet
            return 0;
        }
        reslen = dns_question_decode(pkt_in + pkt_in_len, len - pkt_in_len, &q);
        if (reslen <= 0) {
            return 0;
        }
        pkt_in_len += reslen;

        if (support_edns) {
            opts.udp_payload_size = max_udp_packet_size;

            ednsres = edns_handle_packet(pkt_in, len, &opts);
            if (ednsres < 0) {
                return 0;
            }
            if (ednsres > 0) {
                do_edns_response = 1;
                max_udp_packet_size = opts.udp_payload_size;
                if (max_udp_packet_size < 512) {
                    // As per RFC 6891 6.2.3
                    max_udp_packet_size = 512;
                }
                // Unset any invalid edns flags
                opts.extended_flags &= DNS_EXT_HEADER_VALID_MASK;

                // Check the dnssec flag
                context->dnssec_do = DNS_EXT_HEADER_DO_GET(opts.extended_flags);

                // Check whether the edns version is valid
                if (opts.version > 0) {
                    opts.version = 0;
                    return send_badvers_response(pkt_in, pkt_in_len, h, opts, do_edns_response, context->dnssec_do);
                }
            }
        }

        pkt_out = pkt_in + pkt_in_len;

        buf_len = MAX_PACKET_SIZE - pkt_in_len;

        // cname_used and zone_id are intertwined, make sure that if you set is_cname_redirection in response info to also set zone_id
        bool cname_used = false;
        int zone_id = 0;
        for (z = 0, y = 0; (y == 0 || cname_used) && z < DNS_MAX_ITERATE; ++z) {
            // since we can have many lookups for one query (e.g. CNAME chains),
            // we start a response_info for each of these lookups. A response info
            // holds meta data about this query (such as the question) and the results of
            // this query, that can be used later on, e.g. when adding NSEC3 items
            // to the results of a query.
            response_info_t* info = context->start_response_info();
            info->assign_question(q);

            y = dns_data_answer_record(context, &q, pkt_out + pkt_out_len, buf_len, &h, cname_used, zone_id);
            cname_used = info->is_cname_redirection;
            zone_id = info->zone_id;

            if (y > 0) {
                if (pkt_out_len + y + DNS_MAX_RDATA_LENGTH < MAX_PACKET_SIZE) {
                    pkt_out_len += y;
                    buf_len -= y;
                } else {
                    syslog(LOG_ERR, "Our packet has become too big: %d %d", pkt_out_len, y);
                    return send_servfail_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
                }
            } else if (cname_used == false && y != -1) {
                break;
            } else if (y == -1) {
                return send_servfail_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
            }
        }

        if (z == DNS_MAX_ITERATE) {
            loop_detected = true;
            if (q.qclass == DNS_CLASS_IN) {
                return send_servfail_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
            } else {
                rf.rtype = DNS_TYPE_TXT;
                rf.rclass = q.qclass;
                rf.ttl = 60;
                strcpy(rf.rdata + 1, "Stop looping me.");
                rf.rdata[0] = 16;
                rf.rdlength = 17;
                h.ancount = 1;
                h.nscount = 0;
                h.arcount = 0;

                pkt_out_len = dns_resource_fixed_encode(rf, q, pkt_out, MAX_PACKET_SIZE - pkt_in_len);
                if (pkt_out_len < 0) {
                    return send_servfail_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
                }
                if (pkt_out_len + pkt_in_len > max_udp_packet_size && is_udp) {
                    return send_truncated_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
                }

                if (support_edns && do_edns_response) {
                    opts.extended_flags = DNS_EXT_HEADER_DO_SET(opts.extended_flags, context->dnssec_do ? 1 : 0);
                    y = edns_answer_packet(pkt_out + pkt_out_len, MAX_PACKET_SIZE - pkt_in_len - pkt_out_len, &h, &opts);

                    if (y < 0) {
                        return send_servfail_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
                    }

                    pkt_out_len += y;
                }

                dns_header_encode(h, pkt_in);

                return pkt_in_len + pkt_out_len;
            }
        }
    }

    //when z>0 and y=0 it means that we found a cname, but it did not resolve to any data.
    bool needs_authority_for_final_cname_chain = z > 0 && y == 0;
    if ((pkt_out_len == 0 || needs_authority_for_final_cname_chain) && !loop_detected) //20121009: added needs_.._chain, because when we cannot resolve the cname chain we need to know wether the domain resides with us, and if so we need to reply with authority to indicate that there is no data.
    {
        y = dns_data_authority(context, q, pkt_out + pkt_out_len, buf_len, &h);
        if (y == 0) {
            no_authority_found = 1;
            context->number_of_response_infos--;
        } else if (y < 0) {
            return send_servfail_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
        } else {
            pkt_out_len += y;
            buf_len -= y;
        }
    }

    if (support_edns && do_edns_response) {
        if (support_dnssec) {
            if (context->dnssec_do && !loop_detected) {
                int did_nsec3 = 0;
                int is_empty_non_terminal_nsec3 = 0;
                if (dnssec_nsec3) {
                    y = dnssec_add_nsec3s(context, pkt_out + pkt_out_len, buf_len, &h, &did_nsec3, &is_empty_non_terminal_nsec3);
                    if (y < 0) {
                        return send_servfail_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
                    }

                    pkt_out_len += y;
                    buf_len -= y;

                    // when using dnssec, we should return NODATA on empty-non terminal responses,
                    // instead of NXDOMAIN according to some (This is an active area of discussion at namedroppers).
                    // We try to be compatible with most validating software at the moment
                    if (dnssec_nsec3_noerror_for_empty_non_terminals) {
                        if (is_empty_non_terminal_nsec3 && DNS_HEADER_RCODE_GET(h.flags) == DNS_RCODE_NAMEERROR) {
                            h.flags = DNS_HEADER_RCODE_UNSET(h.flags, DNS_RCODE_NAMEERROR); // clear the NXDOMAIN flag for empty-non terminals
                        }
                    }
                }

                if (!did_nsec3) {
                    bool did_nsec = false;
                    y = dnssec_add_nsecs(context, pkt_out + pkt_out_len, buf_len, &h, &did_nsec);

                    if (y < 0) {
                        return send_servfail_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
                    }

                    pkt_out_len += y;
                    buf_len -= y;
                }
            }
        }
    }

    x = pkt_in_len + pkt_out_len;

    //Do not set rd flag, take whatever value was there. h.flags = DNS_HEADER_RD_SET(h.flags, 0);
    if (pkt_out_len == 0) {
        if (no_authority_found) {
            h.flags = DNS_HEADER_RCODE_SET(h.flags, DNS_RCODE_REFUSED);
        }
    }

    if (support_compression) {
        if ((is_udp && x > max_udp_packet_size) || compress_all_packages) {
            dns_header_encode(h, pkt_in);

            char compressed_package[MAX_PACKET_SIZE + 1];
            size_t len = x;
            size_t len_out = 0;
            if (compress_package(pkt_in, len, compressed_package, &len_out) == 0) {
                x = len_out;
                memmove(pkt_in, compressed_package, len_out);
                buf_len = MAX_PACKET_SIZE - len_out;
            }
        }
    }

    if (support_edns && do_edns_response) {
        opts.extended_flags = DNS_EXT_HEADER_DO_SET(opts.extended_flags, context->dnssec_do ? 1 : 0);
        y = edns_answer_packet(pkt_in + x, buf_len, &h, &opts);

        if (y < 0) {
            return send_servfail_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
        }

        x += y;
        buf_len -= y;
    }

    if (x > max_udp_packet_size && is_udp) {
        return send_truncated_response(pkt_in, pkt_in_len, h, opts, support_edns && do_edns_response, context->dnssec_do);
    }

    dns_header_encode(h, pkt_in);

    return x;
}
