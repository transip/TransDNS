/**
 * Module that is concerned with settings.
 * All setting symbols should be defined
 * in here with sensible defaults.
 */

#include "simple_config.h"
#include <stdio.h>
#include <string.h>
#include <vector>

// global data
const char* transdns_version = VERSION;

int serve_version_records = 1;

const char* db_host = "localhost";
const char* db_database = "transdns";
const char* db_username = "transdns";
const char* db_password = "";

// current defaults for these settings are all compatible
// with the old, non settings aware version of transdns

int update_interval = 60;
int support_notifies = 0;
int support_axfr = 1;
int support_compression = 0;
int compress_all_packages = 0;
int support_edns = 0;
int support_dnssec = 0;
int dnssec_nsec3 = 0;

int max_udp_payload_size = 1200;

// verbosity
int verbosity_print_updates = 0;

int send_default_replies_when_no_match = 1;

int use_translog = 0;
int translog_max_queries = 1000000;
const char* translog_filename = "/usr/translog";

int notify_handle_interval = 20;
int dnssec_nsec3_bind9_wildcard_compatibility = 1;
int dnssec_nsec3_noerror_for_empty_non_terminals = 1;
int dnssec_nsec3_hash_cache_size = 20000;

int udp_thread_count = 4;
int tcp_thread_count = 1;

const char* port_to_bind = "53";

// ip settings
std::vector<char*> ips_to_bind_to;

// flags
int settings_are_from_config_file = 0;

static void print_support_flag(const char* flag_name, int value)
{
    printf("%s: %s\n", flag_name, value ? "enabled" : "disabled");
}

/**
 * Handles the commandline arguments passed to TransDNS
 * by either reading a config file or interpreting the 
 * arguments as ips to bind to.
 *
 * @param int argc the argument count as passed to main()
 * @param char** argv a list of arguments as passed to main()
 * @return int the number of ips to bind to
 */
int handle_commandline(int argc, char** argv)
{
    if (argc >= 2) {
        config_file_t* config = config_file_open(argv[1]);
        if (NULL == config) {
            settings_are_from_config_file = 0;

            printf("%s does not seem to be a config file, skipping...\n", argv[1]);
            for (int i = 1; i < argc; ++i) {
                ips_to_bind_to.push_back(strdup(argv[i]));
            }
        } else {
            settings_are_from_config_file = 1;

            printf("successfully read config file %s\n", argv[1]);

            serve_version_records = config_file_get_bool(config, "serve-version-records", serve_version_records, 0);

            db_host = strdup(config_file_get_string(config, "db-host", db_host, 0));
            db_username = strdup(config_file_get_string(config, "db-user", db_username, 0));
            db_password = strdup(config_file_get_string(config, "db-password", db_password, 0));
            db_database = strdup(config_file_get_string(config, "db-database", db_database, 0));

            int temp = config_file_get_int(config, "update-interval", update_interval, 0);
            if (temp > 0)
                update_interval = temp;

            int temp_notify_interval = config_file_get_int(config, "notify-handle-interval", notify_handle_interval, 0);
            if (temp_notify_interval >= 0)
                notify_handle_interval = temp_notify_interval;

            support_notifies = config_file_get_bool(config, "support-notifies", support_notifies, 0);
            support_axfr = config_file_get_bool(config, "support-axfr", support_axfr, 0);
            support_compression = config_file_get_bool(config, "support-compression", support_compression, 0);
            compress_all_packages = config_file_get_bool(config, "compress-all-packages", compress_all_packages, 0);
            support_edns = config_file_get_bool(config, "support-edns", support_edns, 0);
            support_dnssec = config_file_get_bool(config, "support-dnssec", support_dnssec, 0);
            dnssec_nsec3 = config_file_get_bool(config, "dnssec-nsec3", dnssec_nsec3, 0);
            dnssec_nsec3_bind9_wildcard_compatibility = config_file_get_bool(config, "dnssec-nsec3-bind9-wildcard-compatibility",
                dnssec_nsec3_bind9_wildcard_compatibility, 0);
            dnssec_nsec3_noerror_for_empty_non_terminals = config_file_get_bool(config, "dnssec-nsec3-empty-non-terminals-return-no-data",
                dnssec_nsec3_noerror_for_empty_non_terminals, 0);
            dnssec_nsec3_hash_cache_size = config_file_get_int(config, "dnssec-nsec3-hash-cache-size", dnssec_nsec3_hash_cache_size, 0);

            verbosity_print_updates = config_file_get_bool(config, "verbosity-print-updates", verbosity_print_updates, 0);

            use_translog = config_file_get_bool(config, "log-queries", use_translog, 0);
            translog_max_queries = config_file_get_int(config, "log-queries-max", translog_max_queries, 0);
            translog_filename = strdup(config_file_get_string(config, "log-queries-filename", translog_filename, 0));

            max_udp_payload_size = config_file_get_int(config, "max-udp-payload-size", max_udp_payload_size, 0);
            if (max_udp_payload_size <= 0)
                max_udp_payload_size = 512;

            udp_thread_count = config_file_get_int(config, "udp-thread-count", udp_thread_count, 0);
            if (udp_thread_count <= 0)
                udp_thread_count = 4;

            tcp_thread_count = config_file_get_int(config, "tcp-thread-count", tcp_thread_count, 0);
            if (tcp_thread_count <= 0)
                tcp_thread_count = 1;

            port_to_bind = strdup(config_file_get_string(config, "port-to-bind", port_to_bind, 0));
            if (atoi(port_to_bind) <= 0)
                port_to_bind = "53";

            int ips_count = config_file_key_count(config, "ip");
            for (int i = 0; i < ips_count; ++i) {
                const char* ip = config_file_get_string(config, "ip", NULL, i);
                if (ip != NULL) {
                    ips_to_bind_to.push_back(strdup(ip));
                }
            }

            config_file_close(config);
        }
    }

    print_support_flag("notifies", support_notifies);
    print_support_flag("axfr", support_axfr);
    print_support_flag("edns", support_edns);
    print_support_flag("dnssec", support_dnssec);
    print_support_flag("nnsec3", dnssec_nsec3);
    print_support_flag("nsec3-bind9-wildcard-compatibility", dnssec_nsec3_bind9_wildcard_compatibility);
    print_support_flag("nsec3-empty-non-terminals-return-no-data", dnssec_nsec3_noerror_for_empty_non_terminals);
    print_support_flag("compression", support_compression);
    print_support_flag("include-version-records", compress_all_packages);
    print_support_flag("include-version-records", serve_version_records);
    print_support_flag("query logging", use_translog);
    print_support_flag("verbosity-print-updates:", verbosity_print_updates);
    printf("udp-thread-count: %d\n", udp_thread_count);
    printf("tcp-thread-count: %d\n", tcp_thread_count);
    printf("port-to-bind: %s\n", port_to_bind);

    return ips_to_bind_to.size();
}

/**
 * Gets an IP to bind to
 *
 * @param unsigned int the index of the ip to retrieve
 * @return char* the requested ip to bind to from the list,if available. 
 *               if index is out of bounds, NULL is returned.
 *               the caller does not get ownership of the returned pointer.
 */
char* get_ip_to_bind_to(unsigned int index)
{
    return index < ips_to_bind_to.size() ? ips_to_bind_to[index] : NULL;
}

/**
 * Returns whether the settings has been read from a config file,
 * instead of interpreting the commandline as ips to bind to.
 *
 * @return int 0 if the commandline was interpreted as ips t bind to,
 *             a non-zero value if the settings have been read from a 
 *             config file.
 */
int settings_have_been_read_from_config_file()
{
    return settings_are_from_config_file;
}
