/**
 * This module provides notify support for TransDNS
 *
 * Notifies are an extension to the DNS protocol and
 * are outlined in RFC 1996.
 *
 * The module works by decoding a notify package
 * and storing the domain name for the notify in the
 * database.
 *
 * The transdnsnotifies cron script, will, in turn
 * handle all these notifies by forcing an axfr update
 * for all domains in the database and removing the
 * handled entries.
 *
 * Incoming notifies are added into a queue quickly,
 * which in turn is processed by a consumer thread that
 * adds them into the mysql. We don't want the handler
 * to add them directly into mysql, since that would
 * make a resource attack possible.
 */

#include "notify.h"
#include "dns.h"
#include "request_context.h"
#include "settings.h"
#include <assert.h>
#include <memory.h>
#include <mysql/mysql.h>
#include <netinet/in.h>
#include <pthread.h>
#include <queue>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

// forward declarations
int notify_add_domain_to_database(MYSQL* mysql, const char* domain, const char* source);

struct notify_queue_item {
public:
    char domain[DNS_MAX_DOMAIN_LENGTH]; // the domain we got a notify for
    char source[INET_ADDRSTRLEN + 1]; // the source sending us the notify
};

static int can_queue_notifies = 0; // boolean flag that keeps track if we can queue notifies
static std::queue<notify_queue_item> notify_queue; // our notify queue, containing items that still need to be processed
static pthread_mutex_t notify_queue_cs_mutex = PTHREAD_MUTEX_INITIALIZER; // critical section for access to notify_queue
#define MAX_NOTIFY_QUEUE_SIZE 4000 // current maximum queued items we will hold - make a setting in future versions

pthread_cond_t has_items_condition = PTHREAD_COND_INITIALIZER;
pthread_mutex_t has_items_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Queues an incoming notify for processing. Actual processing will be done 
 * on a later point in time, so this function returns quickly.
 *
 * @param const char* domain the domain for which we got the notify
 * @param const char* source the source that did send us the notify request (ipv4 or ipv6 address string)
 * @return int A non-zero value iff the item has been queued successfully, 0 if the item was not queued.
 */
int add_notify_queue_item(const char* domain, const char* source)
{
    int res = 0;
    if (can_queue_notifies && strlen(domain) < DNS_MAX_DOMAIN_LENGTH && strlen(source) < INET_ADDRSTRLEN + 1) {
        notify_queue_item item;
        strcpy(item.domain, domain);
        strcpy(item.source, source);

        // ensure the notify queue is only modified by one thread at the same time:
        // modify it inside a critical section
        pthread_mutex_lock(&notify_queue_cs_mutex);
        if (notify_queue.size() < MAX_NOTIFY_QUEUE_SIZE) {
            notify_queue.push(item);
            res = 1;
        }
        pthread_cond_signal(&has_items_condition);
        pthread_mutex_unlock(&notify_queue_cs_mutex);
    }

    return res;
}

/**
 * Consumes items in the notify queue as long as there are items.
 */
void consume_notify_queue_items()
{
    notify_queue_item item;
    int queue_is_empty = 0;
    MYSQL mysql;

    // ensure we are connected to the mysql database in which we store notifies
    mysql_init(&mysql);
    if (!mysql_real_connect(&mysql, db_host, db_username, db_password, db_database, 0, NULL, 0)) {
        syslog(LOG_CRIT, "Failed to connect to mysql database! Can not start notify consumer...");
        return;
    }

    while (!queue_is_empty) {
        // ensure we only access the notify_queue as the one-and-only
        // thread: use a critical section to do so, but hold onto it as shortly
        // as possible.
        pthread_mutex_lock(&notify_queue_cs_mutex);
        queue_is_empty = notify_queue.empty();
        if (!queue_is_empty) {
            item = notify_queue.front();
            notify_queue.pop();
        }
        pthread_mutex_unlock(&notify_queue_cs_mutex);

        // we process our item (if we have any) outside of the critical section
        if (!queue_is_empty) {
            notify_add_domain_to_database(&mysql, item.domain, item.source);
        }
    }

    mysql_close(&mysql);
}

/**
 * This function blocks until there are items in the queue
 */
void wait_for_notify_queue_items()
{
    // check if we need to wait for new items, and if so, do that.
    pthread_mutex_lock(&notify_queue_cs_mutex);
    while (notify_queue.empty()) {
        pthread_cond_wait(&has_items_condition, &notify_queue_cs_mutex);
    }
    pthread_mutex_unlock(&notify_queue_cs_mutex);
}

/**
 * Thread function that acts as the consumer of the notify queue.
 * Will setup a consumer and keep on consuming items as long as they are available.
 *
 * @param void* arg thread argument - ignored.
 */
void* notify_consumer_thread(void* arg)
{
    int done = 0;

    // lift off, we can now record notifies
    can_queue_notifies = 1;

    // Our consumer loop:
    // sleep for some time in case mysql is down: we don't wait to reconnect to mysql in a tight loop
    // wait for new items to become available
    // and process them when they are available
    while (!done) {
        sleep(notify_handle_interval);
        wait_for_notify_queue_items();
        consume_notify_queue_items();
    }

    // stop accepting notifies, since we can no longer handle them
    can_queue_notifies = 0;

    // we leak a mutex and a conditional variable here, but there is no safe
    // way to clean them up. Also, this thread is never exited at the moment.
    pthread_exit(NULL);
    return NULL;
}

/**
 * This function will start the notify handler
 * in a separate thread.
 */
void notify_start_handler()
{
    pthread_t thread;
    struct sched_param sparam;

    pthread_create(&thread, NULL, notify_consumer_thread, NULL);
    sparam.sched_priority = 10;
    pthread_setschedparam(thread, SCHED_OTHER, &sparam);
}

/**
 * Answers a notify request
 *
 * @param request_context_t* context the context to use
 * @return int the length of the response package or 0 on failure
 */
int dns_notify_answer(request_context_t* context)
{
    char* pkt_in = context->buf;
    const int len = context->query_len;
    char* pkt_out = pkt_in;

    int pkt_in_len;
    int pkt_out_len;
    struct dns_question q;
    struct dns_header h;
    char name[DNS_MAX_RDATA_LENGTH + 1];
    char domain[DNS_MAX_RDATA_LENGTH + 1];
    int ok = 0;

    // make sure our question rdata buffer exists when decoding
    q.name = name;

    if (len < DNS_HEADER_LENGTH) {
        return 0;
    }

    pkt_in_len = dns_header_decode(pkt_in, &h);
    if (h.qdcount == 1) {
        pkt_in_len += dns_question_decode(pkt_in + pkt_in_len, len, &q);
        if (q.qtype == DNS_TYPE_SOA && q.qclass == DNS_CLASS_IN) {
            dns_domain_decode(q.name, domain);
            dns_domain domainObj;
            domainObj.name = q.name;
            domainObj.len = q.len;
            dns_label* label = dns_data_get_label(context, &domainObj, 0);
            if (dns_data_soa_exists(label)) {
                // we know the domain, so let's queue it for processing
                ok = add_notify_queue_item(domain, context->get_source_address());
            } else {
                // log?
            }
        }
    }

    if (!ok) {
        h.flags = DNS_HEADER_RCODE_SET(h.flags, DNS_RCODE_SERVERFAILURE);
    } else {
        h.flags = DNS_HEADER_QR_SET(h.flags, 1);
        h.flags = DNS_HEADER_AA_SET(h.flags, 1);
    }

    pkt_out_len = len;
    if (len > DNS_MAX_UDP_PACKET && context->request_type == REQUEST_TYPE_UDP) {
        h.flags = DNS_HEADER_TC_SET(h.flags, 1);
        pkt_out_len = DNS_MAX_UDP_PACKET;
    }

    // per RFC 1996, we can (and should) return the exact same
    // response as request, but with the QR flag set on success
    // or failure flags set otherwise.
    // So, we are lazy and just copy over the request package
    // to the response and copy our new header with the new
    // flags on top of it again.
    dns_header_encode(h, pkt_out);

    return pkt_out_len;
}

/**
 * Adds a domain to the notify database
 *
 * @param MYSQL* mysql the mysql object to connect to. Cannot be NULL.
 * @param const char* domain the domain to add to the notify database
 * @param const char* source the source of where the notify is coming from
 * @return int 0 on failure, any other value otherwise
 */
int notify_add_domain_to_database(MYSQL* mysql, const char* domain, const char* source)
{
    char escaped_domain[DNS_MAX_RDATA_LENGTH * 2 + 1]; // worst case, each character must be encoded
    char escaped_source[INET_ADDRSTRLEN * 2 + 1];
    char insert_query[] = "INSERT INTO `Notifies` (`domain`, `source`, `ts`) VALUES('%s', '%s', NOW())";
    char query[sizeof(escaped_domain) + sizeof(insert_query) + sizeof(escaped_source) + 1];

    if (NULL == source) {
        syslog(LOG_CRIT, "Did not get a source address in notify_add_domain_to_database()");
        return 0;
    }

    mysql_real_escape_string(mysql, escaped_domain, domain, strlen(domain));
    mysql_real_escape_string(mysql, escaped_source, source, strlen(source));

    sprintf(query, insert_query, escaped_domain, escaped_source);
    if (mysql_real_query(mysql, query, strlen(query))) {
        syslog(LOG_CRIT, "Could not insert NOTIFY domain.");
        return 0;
    }

    return 1;
}
