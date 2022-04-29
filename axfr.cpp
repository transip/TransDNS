/**
 * This module provides AXFR support for TransDNS
 */

#include "axfr.h"
#include "dns.h"
#include "dns_read.h"
#include "request_context.h"
#include "settings.h"
#include <arpa/inet.h>
#include <assert.h>
#include <memory.h>
#include <mysql/mysql.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

struct aclList {
    int addressCount;
    struct sockaddr_storage* addresses;
};

struct aclList* currentAcl = NULL;
struct aclList* oldAcl = NULL;

void dns_axfr_read_acl()
{
    MYSQL mysql;
    MYSQL_ROW row;
    MYSQL_RES* result;
    const char acl_query[] = "SELECT ip FROM AXFR_ACL";
    struct aclList* newAcl;
    int newAclCount;

    if (oldAcl != NULL) {
        delete[] oldAcl->addresses;
        delete oldAcl;
    }
    oldAcl = currentAcl;

    mysql_init(&mysql);
    if (!mysql_real_connect(&mysql, db_host, db_username, db_password, db_database, 0, NULL, 0)) {
        syslog(LOG_CRIT, "Failed to connect to mysql database! Can not answer AXFR...");
        return;
    }

    mysql_real_query(&mysql, acl_query, strlen(acl_query));
    result = mysql_store_result(&mysql);
    if (result == NULL) {
        syslog(LOG_CRIT, "Could not fetch result from mysql.");
        mysql_close(&mysql);
        return;
    }

    if (mysql_num_rows(result) <= 0) {
        currentAcl = NULL;
        mysql_free_result(result);
        mysql_close(&mysql);
        return;
    }

    newAclCount = mysql_num_rows(result);
    newAcl = new aclList;
    newAcl->addressCount = newAclCount;
    newAcl->addresses = new sockaddr_storage[newAclCount];

    int i = 0;
    while ((row = mysql_fetch_row(result))) {
        // Check whether this is IPv6 or IPv4
        if (strstr(row[0], ":") == NULL) {
            //IPv4
            newAcl->addresses[i].ss_family = AF_INET;
            struct sockaddr_in* saddr = (sockaddr_in*)&(newAcl->addresses[i]);
            inet_pton(AF_INET, row[0], &saddr->sin_addr);
        } else {
            //IPv6
            newAcl->addresses[i].ss_family = AF_INET6;
            struct sockaddr_in6* saddr = (sockaddr_in6*)&(newAcl->addresses[i]);
            inet_pton(AF_INET6, row[0], &saddr->sin6_addr);
        }
        i++;
    }
    currentAcl = newAcl;
    mysql_free_result(result);
    mysql_close(&mysql);
    return;
}

int dns_axfr_answer(request_context_t* context, const char* pkt_in, const int pkt_in_len, struct sockaddr_storage* saddr, const int socket)
{
    MYSQL mysql;
    MYSQL_ROW row;
    MYSQL_RES* result;
    char pkt_out[DNS_MAX_AXFR_PACKET + 500], buf[DNS_MAX_AXFR_PACKET + 1]; //+500 because we might temporarely use more space than MAX AXFR PACKET.
    char domain[DNS_MAX_DOMAIN_LENGTH + 1], soa[DNS_MAX_RDATA_LENGTH + 1];
    char escaped_domain[DNS_MAX_DOMAIN_LENGTH * 2 + 1]; // worst case, every char needs to be escaped
    char source_addr[INET6_ADDRSTRLEN + 1];
    const char records_query[] = "SELECT name, qtype, ttl, rdata FROM Records, Domains WHERE domain='%s' AND domain_id=Domains.id AND qtype!='%d'";
    char records_query_buf[sizeof(records_query) + sizeof(escaped_domain) + 100 + 1]; // 100 for the integer type
    bool allowed, success;
    struct dns_header h;
    struct dns_question q;
    struct dns_resource_fixed record;
    int len, pkt_out_len, soa_len;
    int res = 0;
    char name[DNS_MAX_DOMAIN_LENGTH + 1];
    struct aclList* activeAcl;
    q.name = name;

    allowed = false;

    activeAcl = currentAcl;

    if (activeAcl != NULL) {
        if (saddr->ss_family == AF_INET) {
            struct sockaddr_in* saddr_ipv4 = (sockaddr_in*)saddr;
            struct sockaddr_in* aaddr_ipv4;
            for (int i = 0; i < activeAcl->addressCount; i++) {
                if (activeAcl->addresses[i].ss_family == AF_INET) {
                    aaddr_ipv4 = (sockaddr_in*)&(activeAcl->addresses[i]);
                    if (saddr_ipv4->sin_addr.s_addr == aaddr_ipv4->sin_addr.s_addr) {
                        allowed = true;
                        break;
                    }
                }
            }
        } else if (saddr->ss_family == AF_INET6) {
            struct sockaddr_in6* saddr_ipv6 = (sockaddr_in6*)saddr;
            struct sockaddr_in6* aaddr_ipv6;
            for (int i = 0; i < activeAcl->addressCount; i++) {
                if (activeAcl->addresses[i].ss_family == AF_INET6) {
                    aaddr_ipv6 = (sockaddr_in6*)&(activeAcl->addresses[i]);
                    bool match = true;
                    for (int j = 0; j < 16; j++) {
                        if (saddr_ipv6->sin6_addr.s6_addr[j] != aaddr_ipv6->sin6_addr.s6_addr[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        allowed = true;
                        break;
                    }
                }
            }
        }
    }

    len = dns_header_decode(pkt_in, &h);
    h.flags = DNS_HEADER_QR_SET(h.flags, 1);
    h.flags = DNS_HEADER_AA_SET(h.flags, 1);

    if (allowed) {
        int len2;
        mysql_init(&mysql);
        if (!mysql_real_connect(&mysql, db_host, db_username, db_password, db_database, 0, NULL, 0)) {
            syslog(LOG_CRIT, "Failed to connect to mysql database! Can not answer AXFR...");
            return 0;
        }

        len2 = dns_question_decode(pkt_in + len, pkt_in_len, &q);
        if (len2 <= 0) {
            return 0;
        }
        dns_domain_decode(q.name, domain);
        q.qtype = DNS_TYPE_SOA;
        record.rclass = q.qclass;

        if (h.qdcount != 1) {
            address_from_sockaddr_storage(saddr, source_addr, sizeof(source_addr));
            syslog(LOG_ERR, "AXFR question count was %d instead of 1. Domain: %s, source: %s.", h.qdcount, domain, source_addr);
        }

        dns_domain domainObj;
        domainObj.name = q.name;
        domainObj.len = q.len;
        dns_label* label = dns_data_get_label(context, &domainObj, 0);
        soa_len = dns_data_answer_single_record(context, label, q, soa, DNS_MAX_RDATA_LENGTH, &h, 0);
        if (soa_len == 0) {
            success = false;
        } else {
            success = true;
            memmove(pkt_out + 2, pkt_in, pkt_in_len);
            pkt_out_len = pkt_in_len + 2; //we need 2 bytes for length indicator.
            memmove(pkt_out + pkt_out_len, soa, soa_len);
            pkt_out_len += soa_len;

            //now that we have the soa, fetch all other records.
            mysql_real_escape_string(&mysql, escaped_domain, domain, strlen(domain));
            sprintf(records_query_buf, records_query,
                escaped_domain, DNS_TYPE_SOA);
            mysql_real_query(&mysql, records_query_buf, strlen(records_query_buf));
            result = mysql_use_result(&mysql);
            if (result == NULL)
                syslog(LOG_CRIT, "Could not fetch result from mysql.");

            while (result != NULL && (row = mysql_fetch_row(result)) != NULL && res >= 0) {

                q.len = dns_domain_encode(row[0], q.name);
                record.rtype = atoi(row[1]);
                record.ttl = atoi(row[2]);
                dns_data_parse_record(&record, row[3]);

                len = dns_resource_fixed_encode(record, q, pkt_out + pkt_out_len, DNS_MAX_AXFR_PACKET + 500 - pkt_out_len);
                if (len + pkt_out_len < DNS_MAX_AXFR_PACKET && len >= 0) {
                    pkt_out_len += len;
                    ++h.ancount;
                } else {
                    dns_header_encode(h, pkt_out + 2);
                    dns_uint16_encode(pkt_out_len - 2, pkt_out);
                    res = write(socket, pkt_out, pkt_out_len);
                    memmove(pkt_out + 2, pkt_in, pkt_in_len);
                    pkt_out_len = pkt_in_len + 2;
                    len = dns_resource_fixed_encode(record, q, pkt_out + pkt_out_len, DNS_MAX_AXFR_PACKET + 500 - pkt_out_len);
                    if (len < 0) {
                        // apparently this record is too large for an AXFR packet, lets just skip it
                        continue;
                    }
                    pkt_out_len += len;
                    h.ancount = 1;
                }
            }
            mysql_free_result(result);
            if (res >= 0) {
                if (soa_len + pkt_out_len < DNS_MAX_AXFR_PACKET) {
                    memmove(pkt_out + pkt_out_len, soa, soa_len);
                    pkt_out_len += soa_len;
                    ++h.ancount;
                } else {
                    dns_header_encode(h, pkt_out + 2);
                    dns_uint16_encode(pkt_out_len - 2, pkt_out);
                    res = write(socket, pkt_out, pkt_out_len);
                    memmove(pkt_out + 2, pkt_in, pkt_in_len);
                    pkt_out_len = pkt_in_len + 2;
                    memmove(pkt_out + pkt_out_len, soa, soa_len);
                    pkt_out_len += soa_len;
                    h.ancount = 1;
                }

                dns_header_encode(h, pkt_out + 2);
                dns_uint16_encode(pkt_out_len - 2, pkt_out);
                res = write(socket, pkt_out, pkt_out_len);
            }
        }
        mysql_close(&mysql);
    }

    if ((!allowed || !success) && res >= 0) {
        if (!allowed) {
            address_from_sockaddr_storage(saddr, source_addr, sizeof(source_addr));
            syslog(LOG_NOTICE, "Refused AXFR from %s", source_addr);
        }
        h.flags = DNS_HEADER_RCODE_SET(h.flags, DNS_RCODE_REFUSED);
        memmove(buf + 2, pkt_in, pkt_in_len);
        dns_header_encode(h, buf + 2);
        dns_uint16_encode(pkt_in_len, buf);
        res = write(socket, buf, pkt_in_len + 2);
    }
    return res;
}
