#ifndef DNS_READ_H
#define DNS_READ_H

#include "axfr.h"
#include "dns_data.h"

void dns_data_parse_record(dns_resource_fixed* r, const char* src);
int dns_data_read(int want_everything = 0);

void dns_data_get_current_data(dns_data_t** dns_data_ptr, dns_domain_rrs_t** dnssec_nsec_data_ptr);

#endif //DNS_READ_H
