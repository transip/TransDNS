#include "dns_read.h"
#include "settings.h"

#include <mysql/mysql.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define DISPOSE(x) garbage.push_back((void*)(x))

// ======== DNS_DATA =======
// All dns records are stored in an hash-map structure which basically is:
//  question => vector_of_answers. This is the dns_data structure.
//
// Because we want a lock free nameserver, we use a duplicated data structure, which
// we swap after each update. This way, we can safely do writes on the inactive
// copy of the data during an update. When the update is completed, we swap the dns_data
// pointer to point to the inactive copy, which will now be the active copy.
//
// Requests started before the "swap", will still use the old dns_data and thus
// doesn't need to lock the data (nobody writes to it), and the results are fully consistent.
// A request will always use the same dns_data.
//
// Because requests take a small amount of time, there will be plenty of time until the next
// update, which will ensure the now 'inactive' dns_data copy is no longer used by anyone and thus
// can safely be written to at the next update.

dns_data_t* dns_data; // currently active data
dns_data_t dns_data_1; // copy 1
dns_data_t dns_data_2; // copy 2

// ======== DNSSEC_NSEC_DATA =======
//
// For DNSSEC we need an ordered list of NSEC(3) records per zone (since we need to walk them). It's impossible
// to get this list from the dns_data structure, so we hold an additional list of references to the NSEC(3) records.
// dns_domain_rrs_t is a hash-map domain -> vector_of_nsec_record_pointers.
//
// For dnssec_nsec_data, we use the exact same copy-and-swap-on-update semantics.
dns_domain_rrs_t* dnssec_nsec_data; // currently active data
dns_domain_rrs_t dnssec_nsec_data_1; // copy 1
dns_domain_rrs_t dnssec_nsec_data_2; // copy 2

// empty vector, which can be used by reference safely.
static dns_resource_v empty_v;

// vector for garbage we need to dispose off in the next cycle
static std::vector<void*> garbage; // it's all crap

dns_data_t* dns_data_get_current()
{
    return ::dns_data;
}
dns_domain_rrs_t* dns_data_get_current_nsecs(dns_data_t* dns_data)
{
    if (dns_data == &dns_data_1)
        return &dnssec_nsec_data_1;
    else
        return &dnssec_nsec_data_2;
}

void dns_data_get_current_data(dns_data_t** dns_data_ptr, dns_domain_rrs_t** dnssec_nsec_data_ptr)
{
    *dns_data_ptr = dns_data_get_current();
    *dnssec_nsec_data_ptr = dns_data_get_current_nsecs(*dns_data_ptr);
}

// ============================================
#pragma mark PARSING

void dns_data_parse_record(dns_resource_fixed* r, const char* src)
{
    memmove(&r->rdata, src, DNS_MAX_RDATA_LENGTH);
    switch (r->rtype) {
    case DNS_TYPE_A:
        r->rdlength = dns_ip_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_MX:
        r->rdlength = dns_mx_recode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_CNAME:
        r->rdlength = dns_domain_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_NS:
        r->rdlength = dns_domain_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_SOA:
        r->rdlength = dns_soa_encode(r->ttl, r->rdata, r->rdata);
        break;
    case DNS_TYPE_TXT:
    case DNS_TYPE_SPF:
        r->rdlength = dns_txt_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_AAAA:
        r->rdlength = dns_ip6_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_PTR:
        r->rdlength = dns_domain_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_SRV:
        r->rdlength = dns_srv_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_DNSKEY:
        r->rdlength = dns_dnskey_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_DS:
        r->rdlength = dns_ds_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_RRSIG:
        r->rdlength = dns_rrsig_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_NSEC:
        r->rdlength = dns_nsec_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_NSEC3:
        r->rdlength = dns_nsec3_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_NSEC3PARAM:
        r->rdlength = dns_nsec3param_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_SSHFP:
        r->rdlength = dns_sshfp_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_TLSA:
        r->rdlength = dns_tlsa_encode(r->rdata, r->rdata);
        break;
    case DNS_TYPE_CAA:
        r->rdlength = dns_caa_encode(r->rdata, r->rdata);
        break;
    default:
        r->rdlength = strlen(r->rdata);
        break;
    }

    return;
}

int dns_data_get_domain_id_mapping(std::map<int, dns_domain>& mapping, MYSQL* mysql)
{
    MYSQL_ROW row;
    MYSQL_RES* result;
    const char query[] = "SELECT id, domain FROM Domains;";

    mysql_real_query(mysql, query, strlen(query));
    result = mysql_use_result(mysql);
    if (result == NULL) {
        syslog(LOG_ERR, "Could not fetch results from query.");
        return 0;
    }

    while ((row = mysql_fetch_row(result))) {
        int id = atoi(row[0]);
        dns_domain domain = { strdup(row[1]), (unsigned char)strlen(row[1]) };
        mapping.insert(std::make_pair(id, domain));
    }

    mysql_free_result(result);

    return 1;
}

void print_update_message_start(int want_everything, timeval* start)
{
    if (verbosity_print_updates || want_everything) {
        gettimeofday(start, NULL);

        if (want_everything)
            printf("Starting initial data read...");
        else
            printf("Starting updating data read...");

        fflush(stdout);
    }
}

void print_update_message_end(int want_everything, timeval* start, int domain_count)
{
    if (verbosity_print_updates || want_everything) {
        timeval end;
        gettimeofday(&end, NULL);
        float time_took = end.tv_sec - start->tv_sec + 1e-6 * (end.tv_usec - start->tv_usec);
        printf(" took %.1f seconds (%d records)\n", time_took, domain_count);
    }
}

dns_label* dns_read_ensure_label(dns_data_t* data, dns_domain* domain, dns_domain* zone, int zone_id)
{
    dns_label newLabel;
    dns_label* parentLabel;
    dns_data_iter_t iter;
    dns_domain domainCopy;
    std::pair<dns_data_iter_t, bool> res;

    iter = data->find(*domain);

    if (iter == data->end()) {
        newLabel.childs = 0;
        newLabel.zone_id = zone_id;

        domainCopy.len = domain->len;
        domainCopy.name = (char*)malloc(domainCopy.len + 1);
        memset(domainCopy.name, 0, domainCopy.len + 1);
        memmove(domainCopy.name, domain->name, domainCopy.len);

        res = data->insert(std::make_pair(domainCopy, newLabel));
        iter = res.first;

        // Check whether parent exists, first check whether we are not at the apex of the zone
        if (domain->len >= zone->len && memcmp(domain->name, zone->name, domain->len) != 0) {
            dns_domain domainParent;
            char domainBuffer[DNS_MAX_DOMAIN_LENGTH + 1];
            int labelLength = domain->name[0] + 1;
            if (labelLength <= domain->len) {
                domainParent.len = domain->len - labelLength;
                domainParent.name = domainBuffer;
                domainParent.name[domainParent.len] = 0;
                memmove(domainParent.name, domain->name + labelLength, domainParent.len);

                parentLabel = dns_read_ensure_label(data, &domainParent, zone, zone_id);

                parentLabel->childs++;
            }
        }
    }

    return &iter->second;
}

void dns_read_delete_label(dns_data_t* data, dns_data_iter_t iter, dns_domain* domain, dns_domain* zone)
{
    dns_data_iter_t parentIter;
    dns_label* parentLabel;
    // Check whether there are any childs above us, if so do not delete (yet)
    if (iter->second.childs == 0 && iter->second.recordtypes.empty()) {
        // First delete ourselves
        char* oldName = iter->first.name;
        data->erase(iter);
        DISPOSE(oldName);

        // Check whether parent exists, first check whether we are not at the apex of the zone
        if (domain->len >= zone->len && memcmp(domain->name, zone->name, domain->len) != 0) {
            dns_domain domainCopy = *domain;
            int labelLength = domainCopy.name[0] + 1;
            if (labelLength > domainCopy.len)
                return;
            domainCopy.len -= labelLength;
            domainCopy.name += labelLength;

            parentIter = data->find(domainCopy);

            // No such label, shouldn't happen, but lets just ignore
            if (parentIter == data->end())
                return;

            parentLabel = &parentIter->second;
            parentLabel->childs--;
            dns_read_delete_label(data, parentIter, &domainCopy, zone);
        }
    }
}

bool dns_read_delete_record(dns_data_t* data, dns_question* question, dns_resource* record, dns_domain* zone)
{
    struct dns_domain domain;
    dns_data_iter_t iter;
    dns_label* label;
    dns_resource_type_v* rrTypesVector;
    dns_resource_v* rrVector;
    dns_resource* memoryRecord;
    struct dns_resource_type* recordType;
    int sizeTypes, sizeRecords;
    bool found;

    domain.name = question->name;
    domain.len = question->len;
    iter = data->find(domain);

    // No such domain
    if (iter == data->end())
        return false;

    label = &iter->second;

    rrTypesVector = &label->recordtypes;

    for (found = false, sizeTypes = rrTypesVector->size(); sizeTypes > 0; --sizeTypes) {
        recordType = &(*rrTypesVector)[sizeTypes - 1];
        if (recordType->rtype == question->qtype) {
            found = true;
            break;
        }
    }

    // No such type on this label
    if (!found)
        return false;

    rrVector = &recordType->records;

    for (found = false, sizeRecords = rrVector->size(); sizeRecords > 0; --sizeRecords) {
        memoryRecord = &(*rrVector)[sizeRecords - 1];
        if (memoryRecord->id == record->id) {
            found = true;
            break;
        }
    }

    if (!found)
        return false;

    DISPOSE(memoryRecord->rdata);
    rrVector->erase(rrVector->begin() + sizeRecords - 1);
    if (rrVector->empty()) {
        rrTypesVector->erase(rrTypesVector->begin() + sizeTypes - 1);
        if (rrTypesVector->empty()) {
            dns_read_delete_label(data, iter, &domain, zone);
        }
    }
    return true;
}

void dns_read_update_record(dns_data_t* data, dns_question* question, dns_resource* record, int want_everything, dns_domain* zone, int zone_id)
{
    struct dns_domain domain;
    dns_data_iter_t iter;
    dns_label* label;
    dns_resource_type_v* rrTypesVector;
    dns_resource_v* rrVector;
    dns_resource* memoryRecord;
    struct dns_resource_type* recordType;
    int sizeTypes, sizeRecords;
    bool found;
    std::pair<dns_data_iter_t, bool> res;

    domain.len = question->len;
    domain.name = question->name;

    label = dns_read_ensure_label(data, &domain, zone, zone_id);

    rrTypesVector = &label->recordtypes;

    for (found = false, sizeTypes = rrTypesVector->size(); sizeTypes > 0; --sizeTypes) {
        recordType = &(*rrTypesVector)[sizeTypes - 1];
        if (recordType->rtype == question->qtype) {
            found = true;
            break;
        }
    }

    // No such type on this label
    if (!found) {
        dns_resource_type newType;
        newType.rtype = question->qtype;
        rrTypesVector->push_back(newType);
        recordType = &(*rrTypesVector)[rrTypesVector->size() - 1];
    }

    rrVector = &recordType->records;

    found = false;
    if (!want_everything) {
        for (sizeRecords = rrVector->size(); sizeRecords > 0; --sizeRecords) {
            memoryRecord = &(*rrVector)[sizeRecords - 1];
            if (memoryRecord->id == record->id) {
                found = true;
                break;
            }
        }
    }

    if (!found) {
        rrVector->push_back(*record);
    } else {
        DISPOSE(memoryRecord->rdata);
        (*rrVector)[sizeRecords - 1] = *record;
    }
    return;
}

// synthesizes version.bind. records in the CH class
void add_version_records(dns_data_t* dns_data)
{
    dns_resource_named ra;
    dns_question qa;
    dns_resource_v va;
    dns_resource_fixed rf;
    dns_domain domain;

    const char* version_bind = "version.bind.";

    char name[DNS_MAX_DOMAIN_LENGTH + 1];
    int len = dns_domain_encode(version_bind, name);

    domain.name = name;
    domain.len = len;

    qa.len = len;
    qa.name = (char*)malloc(qa.len + 1);
    if (qa.name == NULL) {
        syslog(LOG_CRIT, "Could not allocate memory for qa.name!");
        return;
    }
    memset(qa.name, 0, qa.len + 1);
    memmove(qa.name, name, qa.len);

    ra.name = qa.name;
    ra.name_len = qa.len;

    ra.rclass = qa.qclass = DNS_CLASS_CH;

    rf.rtype = ra.rtype = qa.qtype = DNS_TYPE_TXT;
    rf.ttl = ra.ttl = 86400;
    rf.id = ra.id = 0;

    dns_data_parse_record(&rf, transdns_version);

    ra.rdata = (char*)malloc(rf.rdlength + 1);
    if (ra.rdata == NULL) {
        syslog(LOG_CRIT, "Could not allocate memory for ra.rdata!");
        free(qa.name); // don't dispose, free directly, not used by anything else
        return;
    }
    memset(ra.rdata, 0, rf.rdlength + 1);
    memmove(ra.rdata, rf.rdata, rf.rdlength);
    ra.rdlength = rf.rdlength;

    dns_read_update_record(dns_data, &qa, &ra, 1, &domain, 0);
}

int dns_data_read(int want_everything)
{
    MYSQL mysql;
    char buf[1024], *p1, name[DNS_MAX_DOMAIN_LENGTH + 1];
    MYSQL_ROW row;
    MYSQL_RES* result;
    dns_question qa;
    dns_resource ra;
    dns_data_iter_t iter;
    int size, domain_count;
    bool found;
    dns_resource_fixed rf;
    dns_data_t* temp_dns_data;
    dns_domain_rrs_t* temp_dnssec_nsec_data;
    std::unordered_map<dns_domain, int> nsec_datas_to_sort;
    std::map<int, dns_domain> domain_id_mapping;
    std::vector<dns_label*> labelsWithUpdatedRRSigs;
    struct timeval time_start;

    dns_axfr_read_acl();

    print_update_message_start(want_everything, &time_start);

    // clean up the old garbage
    for (std::vector<void*>::iterator iter = garbage.begin(); iter != garbage.end(); ++iter) {
        void* ptr = *iter;
        free(ptr);
        *iter = NULL;
    }

    garbage.clear();
    // the garbage has been disposed

    //printf("%s %s %s %s\n", db_host, db_database, db_username, db_password);
    mysql_init(&mysql);
    if (!mysql_real_connect(&mysql, db_host, db_username, db_password, db_database, 0, NULL, 0)) {
        syslog(LOG_ERR, "Failed to connect to mysql database!");
        return -1;
    }

    if (want_everything) {
        if (support_dnssec) {
            strcpy(buf, "SELECT name, qtype, ttl, rdata, deleted, id, domain_id FROM Records WHERE updated=0 AND deleted=0;");
        } else {
            strcpy(buf, "SELECT name, qtype, ttl, rdata, deleted, id FROM Records WHERE updated=0 AND deleted=0;");
        }
    } else {
        strcpy(buf, "SELECT GET_LOCK('update_lock',30);");
        mysql_real_query(&mysql, buf, strlen(buf));
        result = mysql_use_result(&mysql);
        if (result == NULL) {
            syslog(LOG_ERR, "Could not fetch results from query.");
            mysql_close(&mysql);
            return -1;
        }

        row = mysql_fetch_row(result);
        if (row[0][0] != '1') {
            syslog(LOG_NOTICE, "Could not obtain lock!");
            mysql_free_result(result);
            mysql_close(&mysql);
            return -1;
        }
        mysql_free_result(result);
        if (support_dnssec) {
            strcpy(buf, "SELECT name, qtype, ttl, rdata, deleted, id, domain_id FROM Records WHERE updated=1;");
        } else {
            strcpy(buf, "SELECT name, qtype, ttl, rdata, deleted, id FROM Records WHERE updated=1;");
        }
    }

    // only fetch our domain_id_mapping from the db if we actually have changed dns entries
    // and support_dnssec of course.
    if (support_dnssec) {
        int num_counted_changes = 0;
        if (!want_everything) {
            const char num_changes_query[] = "SELECT COUNT(*) FROM Records WHERE updated=1;";
            mysql_real_query(&mysql, num_changes_query, strlen(num_changes_query));
            result = mysql_use_result(&mysql);
            if (result == NULL) {
                syslog(LOG_ERR, "Could not fetch results from query.");

                // clear our lock
                strcpy(buf, "SELECT RELEASE_LOCK('update_lock');");
                mysql_real_query(&mysql, buf, strlen(buf));

                mysql_close(&mysql);
                return -1;
            }

            row = mysql_fetch_row(result);
            num_counted_changes = row ? atoi(row[0]) : 0;
            mysql_free_result(result);

            // bail out early, we know there are no changes to process at all.
            // This also closes a possible race-condition between the count(*) query and the actual query:
            // if we did not load the domain_id_mapping because num_counted_changes was 0, but
            // the actual query returned results, domain_id_mapping would be empty and things
            // would go horribly wrong

            if (num_counted_changes == 0) {
                // clear our lock
                strcpy(buf, "SELECT RELEASE_LOCK('update_lock');");
                mysql_real_query(&mysql, buf, strlen(buf));

                mysql_close(&mysql);

                print_update_message_end(want_everything, &time_start, 0);
                return 0;
            }
        }

        // always load the mapping here. if there were no changes, we would
        // have bailed before
        if (!dns_data_get_domain_id_mapping(domain_id_mapping, &mysql)) {
            syslog(LOG_NOTICE, "Could not obtain get domain_id_mapping from mysql!");

            // clear our lock
            strcpy(buf, "SELECT RELEASE_LOCK('update_lock');");
            mysql_real_query(&mysql, buf, strlen(buf));

            mysql_close(&mysql);
            return -1;
        }
    }

    // copy our data structures, so we don't need explicit locking

    if (dns_data == &dns_data_1) {
        dns_data_2.clear();
        dns_data_2 = dns_data_1;
        temp_dns_data = &dns_data_2;

        dnssec_nsec_data_2.clear();
        dnssec_nsec_data_2 = dnssec_nsec_data_1;
        temp_dnssec_nsec_data = &dnssec_nsec_data_2;
    } else {
        dns_data_1.clear();
        dns_data_1 = dns_data_2;
        temp_dns_data = &dns_data_1;

        dnssec_nsec_data_1.clear();
        dnssec_nsec_data_1 = dnssec_nsec_data_2;
        temp_dnssec_nsec_data = &dnssec_nsec_data_1;
    }

    if (want_everything && serve_version_records) {
        add_version_records(temp_dns_data);
    }

    mysql_real_query(&mysql, buf, strlen(buf));
    result = mysql_use_result(&mysql);
    if (result == NULL) {
        syslog(LOG_ERR, "Could not fetch results from query.");
    } else {
        qa.qclass = DNS_CLASS_IN;
        ra.rclass = DNS_CLASS_IN;
        domain_count = 0;
        while ((row = mysql_fetch_row(result))) {
            ++domain_count;
            //printf("Loaded: %s qtype: %s\n", row[0], row[1]);
            qa.len = dns_domain_encode(row[0], name);
            qa.name = (char*)malloc(qa.len + 1);
            if (qa.name == NULL) {
                syslog(LOG_CRIT, "Could not allocate memory for qa.name!");
                continue;
            }
            if (qa.len <= 1) {
                syslog(LOG_CRIT, "Invalid name specified for record name!");
                continue;
            }
            memset(qa.name, 0, qa.len + 1);
            memmove(qa.name, name, qa.len);

            rf.rtype = ra.rtype = qa.qtype = atoi(row[1]);
            rf.ttl = ra.ttl = atoi(row[2]);
            rf.id = ra.id = atoi(row[5]);

            dns_data_parse_record(&rf, row[3]);

            ra.rdata = (char*)malloc(rf.rdlength + 1);
            if (ra.rdata == NULL) {
                syslog(LOG_CRIT, "Could not allocate memory for ra.rdata!");
                free(qa.name); // don't dispose, free directly, not used by anything else
                continue;
            }
            memset(ra.rdata, 0, rf.rdlength + 1);
            memmove(ra.rdata, rf.rdata, rf.rdlength);
            ra.rdlength = rf.rdlength;

            int domain_id = atoi(row[6]);
            dns_domain& d = domain_id_mapping[domain_id];
            dns_domain zone = d;
            char tempZoneName[DNS_MAX_DOMAIN_LENGTH + 1];
            memmove(tempZoneName, d.name, d.len);
            tempZoneName[d.len] = '.';
            tempZoneName[d.len + 1] = '\0';
            char zoneName[DNS_MAX_DOMAIN_LENGTH + 1];
            zone.name = zoneName;
            dns_domain_encode(tempZoneName, zone.name);

            //dns_domain_decode( qa.name, buf );
            if (row[4][0] == '1') {
                dns_read_delete_record(temp_dns_data, &qa, &ra, &zone);
            } else {
                dns_read_update_record(temp_dns_data, &qa, &ra, want_everything, &zone, domain_id);
            }

            if (want_everything) { //hack to make startup faster.

                if (support_dnssec) {
                    if (DNS_TYPE_NSEC == ra.rtype || DNS_TYPE_NSEC3 == ra.rtype) {
                        dns_resource_named ra_named;
                        ra_named.assign_from(ra);
                        ra_named.name = strdup(qa.name);
                        ra_named.name_len = qa.len;

                        dns_domain_rrs_iter_t rrs_iter = temp_dnssec_nsec_data->find(d);
                        if (rrs_iter == temp_dnssec_nsec_data->end()) {
                            dns_domain domain_to_insert = { strdup(d.name), d.len };
                            nsec_datas_to_sort[domain_to_insert] = 1;

                            dns_resource_named_v va;
                            va.push_back(ra_named);

                            temp_dnssec_nsec_data->insert(make_pair(domain_to_insert, va));
                        } else {
                            dns_resource_named_v* v = &rrs_iter->second;
                            v->push_back(ra_named);
                        }
                    }
                }
            } else {
                if (support_dnssec) {
                    // 3 possibilities
                    //  new domain + new record (updated=1, domain not found)
                    //  existing domain + new record (updated = 1, domain found, nsec record not found)
                    //  existing domain + updated record(updated = 1, domain found, nsec record found)
                    //  existing domain + delete record (updated = 1, deleted = 1)
                    if (DNS_TYPE_NSEC == ra.rtype || DNS_TYPE_NSEC3 == ra.rtype) {
                        dns_domain_rrs_iter_t rrs_iter = temp_dnssec_nsec_data->find(d);

                        if (row[4][0] != '1') {
                            dns_resource_named ra_named;
                            ra_named.assign_from(ra);
                            ra_named.name = strdup(qa.name);
                            ra_named.name_len = qa.len;

                            if (rrs_iter == temp_dnssec_nsec_data->end()) {
                                // new domain, so new records also
                                dns_domain domain_to_insert = { strdup(d.name), d.len };
                                nsec_datas_to_sort[domain_to_insert] = 1;
                                dns_resource_named_v va;
                                va.push_back(ra_named);
                                temp_dnssec_nsec_data->insert(make_pair(domain_to_insert, va));
                            } else {
                                dns_resource_named_v* v = &rrs_iter->second;
                                size = v->size();
                                found = false;
                                for (int i = 0; i < size; ++i) {
                                    dns_resource_named* r_named = &((*v)[i]);
                                    if (ra_named.id == r_named->id) {
                                        // update
                                        DISPOSE(r_named->name); // r_named will no longer be referenced, so dispose its name buffer
                                        (*v)[i] = ra_named;

                                        found = true;
                                        break;
                                    }
                                }

                                if (!found) {
                                    // new record
                                    v->push_back(ra_named);
                                }

                                nsec_datas_to_sort[rrs_iter->first] = 1;
                            }
                        } else //if(row[4][0] == '1') // delete
                        {
                            if (rrs_iter == temp_dnssec_nsec_data->end()) {
                                printf("Wanted to delete NSEC(3) record, but domain not found (%s)\n", d.name);
                            } else {
                                dns_resource_named_v* v = &rrs_iter->second;
                                size = v->size();
                                found = false;
                                for (int i = 0; i < size; ++i) {
                                    dns_resource_named* r_named = &((*v)[i]);
                                    if (ra.id == r_named->id) {
                                        DISPOSE(r_named->name); // r_named will no longer be referenced, so dispose its name buffer

                                        v->erase(v->begin() + i);
                                        if (v->empty()) {
                                            p1 = rrs_iter->first.name;
                                            nsec_datas_to_sort.erase(rrs_iter->first);

                                            temp_dnssec_nsec_data->erase(rrs_iter);
                                            DISPOSE(p1);
                                        } else {
                                            nsec_datas_to_sort[rrs_iter->first] = 1;
                                        }

                                        found = true;
                                        break;
                                    }
                                }

                                if (!found) {
                                    //printf("could not remove nsec record %s for domain %s\n", ra.name, d.name);
                                }
                            }
                        }
                    }
                }
            }
            free(qa.name);
        }

        mysql_free_result(result);
        if (!want_everything) {
            strcpy(buf, "UPDATE Records SET updated=0 WHERE updated=1");
            mysql_real_query(&mysql, buf, strlen(buf));
            strcpy(buf, "SELECT RELEASE_LOCK('update_lock');");
            mysql_real_query(&mysql, buf, strlen(buf));
        }
    }

    mysql_close(&mysql);

    if (support_dnssec) {
        for (std::unordered_map<dns_domain, int>::const_iterator iter = nsec_datas_to_sort.begin();
             iter != nsec_datas_to_sort.end();
             ++iter) {
            dns_domain_rrs_iter_t rrs_iter = temp_dnssec_nsec_data->find(iter->first);
            if (rrs_iter != temp_dnssec_nsec_data->end()) {
                dns_resource_named_v* v = &rrs_iter->second;
                std::sort(v->begin(), v->end());
            }
        }

        // clean up our mapping, ensure allocated names are free'd()
        for (std::map<int, dns_domain>::const_iterator iter = domain_id_mapping.begin();
             iter != domain_id_mapping.end();
             ++iter) {
            free(iter->second.name);
        }
    }

    dns_data = temp_dns_data;
    dnssec_nsec_data = temp_dnssec_nsec_data;

    print_update_message_end(want_everything, &time_start, domain_count);

    return domain_count;
}
