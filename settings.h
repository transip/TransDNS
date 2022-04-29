/**
 * Module that is concerned with reading and
 * storing settings.
 */

#ifndef _SETTINGS_H
#define _SETTINGS_H

// global data
extern const char* transdns_version;

// globally available settings
// for ips, use get_ip_to_bind_to()

extern int serve_version_records;

extern const char* db_host;
extern const char* db_database;
extern const char* db_username;
extern const char* db_password;

extern int update_interval;
extern int support_notifies;
extern int support_axfr;
extern int support_compression;
extern int compress_all_packages;
extern int support_edns;
extern int support_dnssec;
extern int dnssec_nsec3;
extern int max_udp_payload_size;

extern int verbosity_print_updates;

extern int dnssec_nsec3_bind9_wildcard_compatibility;
extern int dnssec_nsec3_noerror_for_empty_non_terminals;
extern int dnssec_nsec3_hash_cache_size;

extern int use_translog;
extern int translog_max_queries;
extern const char* translog_filename;

extern int notify_handle_interval;

extern int udp_thread_count;
extern int tcp_thread_count;

extern const char* port_to_bind;

char* get_ip_to_bind_to(unsigned int index);
char* get_auto_reverse_range(unsigned int index);
int handle_commandline(int argc, char** argv);
int settings_have_been_read_from_config_file();

#endif //_SETTINGS_H
