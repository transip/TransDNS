#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef BSD
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif
#include "axfr.h"
#include "dns.h"
#include "dns_data.h"
#include "dns_read.h"
#include "hash_cache.h"
#include "log.h"
#include "notify.h"
#include "request_context.h"
#include "settings.h"
#include "taskqueue.h"
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>
#include <unistd.h>
#include <vector>

#define BIND_RETRIES 100
#define BIND_WAIT 10

std::atomic<unsigned int> threads;
unsigned long* thread_queries;

/*
* Bind a socket to a specific local address
* Code "borrowed" from libfetch
*/
int bind_socket(int sd, int af, int st, const char* port, const char* addr)
{
    struct addrinfo hints, *res, *res0;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = st;
    hints.ai_protocol = 0;
    if ((err = getaddrinfo(addr, port, &hints, &res0)) != 0)
        return (-1);
    for (res = res0; res; res = res->ai_next)
        if (bind(sd, res->ai_addr, res->ai_addrlen) == 0)
            return (0);
    return (-1);
}

struct dns_udp_t {
    int udp_skt;
    socklen_t cli_len;
    struct sockaddr_storage cli;
};

unsigned long query_cnt, time_start;
pthread_mutex_t tcp_handler_mutex;
unsigned char keep_running;
int ips_count = 0;

extern int errno;

void* dns_udp_worker(void* arg)
{
    int len;
    int recv_length;
    char buf[MAX_PACKET_SIZE + 1];
    struct dns_udp_t worker = *((struct dns_udp_t*)arg);
    unsigned int thread_id = threads++;

    hash_cache* thread_hash_cache = new hash_cache;

    recv_length = MAX_UDP_RECV_SIZE * UDP_RECV_QUEUE;
    if (setsockopt(worker.udp_skt, SOL_SOCKET, SO_RCVBUF, &recv_length, sizeof(recv_length)) < 0) {
        syslog(LOG_ERR, "Failed to set the UDP receive buffer, aborting.");
        exit(0);
    }

    while (keep_running) {
        len = recvfrom(worker.udp_skt, buf, MAX_UDP_RECV_SIZE, 0, (struct sockaddr*)&worker.cli, &worker.cli_len);
        if (len < 0) {
            syslog(LOG_ERR, "Got error reading UDP packet");
            continue;
        }

        if (len < DNS_HEADER_LENGTH + 5) {
            // At least one byte for question domain (.) and 4 bytes QCLASS and QTYPE
            syslog(LOG_ERR, "Got too short packet");
            continue;
        }

        // build our request context
        request_context_t context;
        memset(&context, 0, sizeof(context));
        context.request_type = REQUEST_TYPE_UDP;
        context.sockaddr = (struct sockaddr_storage*)&worker.cli;
        context.buf = buf;
        context.query_len = len;
        context.dnssec_hash_cache = thread_hash_cache;
        context.thread_id = thread_id;
        dns_data_get_current_data(&context.dns_data, &context.dnssec_nsec_data);

        // log request stuff
        log_request(&context);

        // handle the request
        if (support_notifies && is_notify_request(buf, len)) {
            len = dns_notify_answer(&context);
        } else {
            len = dns_data_answer(&context);
        }

        if (len <= 0) {
            continue;
        }

        // debugging
        // context.debug_print();

        sendto(worker.udp_skt, buf, len, 0, (struct sockaddr*)&worker.cli, worker.cli_len);
        ++query_cnt;
        thread_queries[thread_id]++;
    }

    delete thread_hash_cache;
    delete (struct dns_udp_t*)arg;
    pthread_exit(NULL);
}

void signal_usr1(int)
{
    syslog(LOG_NOTICE, "TransDNS statistics:\t%lu queries\t%lu running\t%lu q/s\n", query_cnt, time(NULL) - time_start, query_cnt / (time(NULL) - time_start));
    for (unsigned int i = 0; i < (ips_count * udp_thread_count) + (ips_count * tcp_thread_count); i++) {
        syslog(LOG_NOTICE, "TranDNS thread %u:\t%lu queries\n", i, thread_queries[i]);
    }
}

void signal_term(int)
{
    syslog(LOG_NOTICE, "Got shutdown request... cleaning up");
    keep_running = 0;
    exit(0);
}

void signal_panic(int)
{
    syslog(LOG_CRIT, "Something really bad happened... trying to preserve log");
    exit(0);
}

void* dns_udp_run(void* arg)
{
    int bind_retries;
    struct sockaddr_storage cli;
    struct sched_param sparam;
    struct dns_udp_t* worker;
    pthread_t thread;
    int is_ipv6;
    int udp_skt;
    int family;

    time_start = time(NULL);
    query_cnt = 0;

    is_ipv6 = strchr((char*)arg, ':') != NULL;

    //Bind to socket
    if (!is_ipv6) {
        udp_skt = socket(AF_INET, SOCK_DGRAM, 0);
        family = AF_INET;
    } else {
        udp_skt = socket(AF_INET6, SOCK_DGRAM, 0);
        family = AF_INET6;
    }

    if (udp_skt < 0) {
        perror("Could not create udp socket");
        exit(1);
    }

    int value = 1;

    if (setsockopt(udp_skt, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) != 0) {
        syslog(LOG_ERR, "Failed to set the UDP resuseport buffer, aborting.");
    }

    for (bind_retries = 0; bind_retries < BIND_RETRIES; bind_retries++) {
        if (bind_socket(udp_skt, family, SOCK_DGRAM, port_to_bind, (char*)arg) < 0) {
            perror("Could not bind to udp socket");
            sleep(BIND_WAIT);
        } else
            break;
    }
    //done!;

    for (int i = 0; i < udp_thread_count; i++) {
        worker = new dns_udp_t;
        worker->cli_len = sizeof(cli);
        worker->udp_skt = udp_skt;

        sparam.sched_priority = 100;
        pthread_create(&thread, NULL, dns_udp_worker, (void*)worker);
        pthread_setschedparam(thread, SCHED_OTHER, &sparam);
        pthread_detach(thread);
    }

    pthread_exit(NULL);
}

class TCPClient {
public:
    char buf[MAX_PACKET_SIZE + 1];
    struct sockaddr_storage saddr;
    socklen_t saddrLen;
    uint16 bufLen;
    uint16 packetLen;
    int socket;

    TCPClient()
        : bufLen(0)
        , packetLen(0)
        , socket(-1)
    {
    }

    bool removePacketFromBufAndReset()
    {
        if (this->bufLen >= this->packetLen + 2) {
            if (this->packetLen != 0) {
                memmove(this->buf, this->buf + (this->packetLen + 2), this->bufLen - (this->packetLen + 2));
                this->bufLen -= (this->packetLen + 2);
            }
            uint16 newPacketLen = 0;
            if (this->bufLen >= 2) {
                dns_uint16_decode(this->buf, &newPacketLen);
                if (newPacketLen > MAX_PACKET_SIZE) {
                    this->packetLen = 0;
                    return false;
                }
            }
            this->packetLen = newPacketLen;
        } else {
            this->bufLen = 0;
            this->packetLen = 0;
        }
        return true;
    }

    bool handlePacket(hash_cache* thread_hash_cache, unsigned int thread_id)
    {
        char buf[MAX_PACKET_SIZE + 1];
        int len;

        if (this->packetLen < DNS_HEADER_LENGTH + 5) {
            // Packet too small, lets bail out
            return false;
        }

        // build our request context
        request_context_t context;
        memset(&context, 0, sizeof(context));
        context.request_type = REQUEST_TYPE_TCP;
        context.sockaddr = &this->saddr;
        context.dnssec_hash_cache = thread_hash_cache;
        context.thread_id = thread_id;

        memcpy(buf + 2, this->buf + 2, this->packetLen);

        // fill in the other fields of our context
        context.buf = buf + 2;
        context.query_len = this->packetLen;
        dns_data_get_current_data(&context.dns_data, &context.dnssec_nsec_data);

        // check wether we have to do AXFR. Given that lengths for AXFR's are quite large, we have seperated this
        // from our normal operation
        if (support_axfr && is_axfr_request(this->buf + 2, this->packetLen)) {
            return dns_axfr_answer(&context, this->buf + 2, this->packetLen, &this->saddr, this->socket) >= 0;
        } else {
            if (support_notifies && is_notify_request(this->buf + 2, this->packetLen)) {
                len = dns_notify_answer(&context);
            } else {
                len = dns_data_answer(&context);
            }

            if (len <= 0) {
                return false;
            }

            dns_uint16_encode(len, buf);
            return write(this->socket, buf, len + 2) >= 0;
        }
    }
};

struct dns_tcp_task {
    TCPClient* client;
};

struct dns_tcp_t {
    int queue;
    TaskQueue<struct dns_tcp_task>* taskQueue;
};

void* dns_tcp_worker(void* wsPointer)
{
    int queue = ((struct dns_tcp_t*)wsPointer)->queue;
    TaskQueue<struct dns_tcp_task>* taskQueue = ((struct dns_tcp_t*)wsPointer)->taskQueue;

    unsigned int thread_id = threads++;

    hash_cache thread_hash_cache;
#ifdef BSD
    struct kevent insert;
#else
    struct epoll_event insert;
#endif

    while (keep_running) {
        struct dns_tcp_task task = taskQueue->read();
        bool closed = false;

        while (task.client->packetLen + 2 <= task.client->bufLen && task.client->packetLen != 0) {
            if (!task.client->handlePacket(&thread_hash_cache, thread_id)) {
#ifndef BSD
                epoll_ctl(queue, EPOLL_CTL_DEL, task.client->socket, NULL);
#endif
                close(task.client->socket);
                delete task.client;
                closed = true;
                break;
            }
            if (!task.client->removePacketFromBufAndReset()) {
#ifndef BSD
                epoll_ctl(queue, EPOLL_CTL_DEL, task.client->socket, NULL);
#endif
                close(task.client->socket);
                delete task.client;
                closed = true;
                break;
            }
            thread_queries[thread_id]++;
        }
        if (!closed) {
            int lowat = task.client->packetLen + 2 - task.client->bufLen;
#ifdef BSD
            EV_SET(&insert, task.client->socket, EVFILT_READ, EV_ENABLE, NOTE_LOWAT, lowat, task.client);
            kevent(queue, &insert, 1, NULL, 0, NULL);
#else
            setsockopt(task.client->socket, SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof(int));
            insert.events = EPOLLIN | EPOLLONESHOT | EPOLLRDHUP;
            insert.data.ptr = task.client;
            epoll_ctl(queue, EPOLL_CTL_MOD, task.client->socket, &insert);
#endif
        }
    }
    pthread_exit(NULL);
}

void* dns_tcp_run(void* arg)
{
    int tcp_skt, bind_retries, queue;
    int is_ipv6;
    int family;
    pthread_t thread;
    struct sched_param sparam;
    TaskQueue<struct dns_tcp_task> taskQueue;

    is_ipv6 = strchr((char*)arg, ':') != NULL;
    if (!is_ipv6) {
        tcp_skt = socket(AF_INET, SOCK_STREAM, 0);
        family = AF_INET;
    } else {
        tcp_skt = socket(AF_INET6, SOCK_STREAM, 0);
        family = AF_INET6;
    }

    if (tcp_skt < 0) {
        perror("Could not create tcp socket");
        exit(1);
    }

    int value = 1;

    if (setsockopt(tcp_skt, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) != 0) {
        syslog(LOG_ERR, "Failed to set the tcp reuseport flag, aborting.");
    }

    for (bind_retries = 0; bind_retries < BIND_RETRIES; bind_retries++) {
        if (bind_socket(tcp_skt, family, SOCK_STREAM, port_to_bind, (char*)arg) < 0) {
            perror("Could not bind to tcp socket");
            sleep(BIND_WAIT);

        } else
            break;
    }

    if (listen(tcp_skt, DNS_MAX_BACKLOG) < 0) {
        perror("Could not listen on tcp socket");
        exit(1);
    }

#ifdef BSD
    queue = kqueue();
#else
    queue = epoll_create1(0);
#endif

    struct dns_tcp_t tcpParams;
    tcpParams.queue = queue;
    tcpParams.taskQueue = &taskQueue;

    for (int i = 0; i < tcp_thread_count; i++) {
        pthread_create(&thread, NULL, dns_tcp_worker, &tcpParams);
        sparam.sched_priority = 100;
        pthread_setschedparam(thread, SCHED_OTHER, &sparam);
        pthread_detach(thread);
    }

#ifdef BSD
    struct kevent inserts[256];
    int insertCount = 1;
    EV_SET(&inserts[0], tcp_skt, EVFILT_READ, EV_ADD, 0, 0, NULL);
    struct kevent results[64];
#else
    struct epoll_event results[64];
    struct epoll_event insert;
    int lowat = 2;
    insert.events = EPOLLIN;
    insert.data.fd = tcp_skt;
    epoll_ctl(queue, EPOLL_CTL_ADD, tcp_skt, &insert);
    int flags = fcntl(tcp_skt, F_GETFL, 0);
    fcntl(tcp_skt, F_SETFL, flags | O_NONBLOCK);
#endif

    while (keep_running) {
#ifdef BSD
        int resultCount = kevent(queue, inserts, insertCount, results, 64, NULL);
        insertCount = 0;
#else
        int resultCount = epoll_wait(queue, results, 64, -1);
#endif

        for (int i = 0; i < resultCount; i++) {
#ifdef BSD
            if (results[i].ident == tcp_skt) {
                for (int j = 0; j < std::min((int)results[i].data, 256 - (resultCount - 1)); j++) {
#else
            if (results[i].data.fd == tcp_skt) {
                for (int j = 0; j < 256 - (resultCount - 1); j++) {
#endif
                    TCPClient* client = new TCPClient();
                    client->saddrLen = sizeof(struct sockaddr_storage);
                    client->socket = accept(tcp_skt, (struct sockaddr*)&client->saddr, &client->saddrLen);
                    if (client->socket < 0) {
#ifndef BSD
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            syslog(LOG_ERR, "Got error accepting tcp socket! Err: %d", errno);
                        }
#endif
                        delete client;
                        break;
                    }
#ifdef BSD
                    // Put low water for this connection at 2 bytes so we get notified as soon as we have packet length data
                    EV_SET(&inserts[insertCount], client->socket, EVFILT_READ, EV_ADD | EV_DISPATCH, NOTE_LOWAT, 2, client);
                    insertCount++;
#else
                    lowat = 2;
                    setsockopt(client->socket, SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof(int));
                    insert.events = EPOLLIN | EPOLLONESHOT | EPOLLRDHUP;
                    insert.data.ptr = client;
                    epoll_ctl(queue, EPOLL_CTL_ADD, client->socket, &insert);
#endif
                }
            } else {
#ifdef BSD
                if ((results[i].flags & EV_EOF) != 0) {
                    close(results[i].ident);
                    delete (TCPClient*)results[i].udata;
                } else if (results[i].data != 0) {
                    TCPClient* client = (TCPClient*)results[i].udata;
                    int len = read(client->socket, client->buf + client->bufLen, std::min((int)results[i].data, MAX_PACKET_SIZE - client->bufLen));
#else
                TCPClient* client = (TCPClient*)results[i].data.ptr;
                if ((results[i].events & (EPOLLIN)) == 0) {
                    epoll_ctl(queue, EPOLL_CTL_DEL, client->socket, NULL);
                    close(client->socket);
                    delete client;
                } else {
                    int len = read(client->socket, client->buf + client->bufLen, MAX_PACKET_SIZE - client->bufLen);
#endif
                    if (len <= 0) {
#ifndef BSD
                        epoll_ctl(queue, EPOLL_CTL_DEL, client->socket, NULL);
#endif
                        close(client->socket);
                        delete client;
                    } else {
                        client->bufLen += len;
                        if (client->packetLen == 0) {
                            if (!client->removePacketFromBufAndReset()) {
#ifndef BSD
                                epoll_ctl(queue, EPOLL_CTL_DEL, client->socket, NULL);
#endif
                                close(client->socket);
                                delete client;
                                continue;
                            }
                        }

                        if (client->bufLen >= (client->packetLen + 2)) {
                            struct dns_tcp_task task = { client };
                            taskQueue.write(task);
                        } else {
#ifdef BSD
                            // Wait till we have enough data to finish the packet
                            EV_SET(&inserts[insertCount], client->socket, EVFILT_READ, EV_ENABLE, NOTE_LOWAT, (client->packetLen + 2) - client->bufLen, client);
                            insertCount++;
#else
                            lowat = (client->packetLen + 2) - client->bufLen;
                            setsockopt(client->socket, SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof(int));
                            insert.events = EPOLLIN | EPOLLONESHOT | EPOLLRDHUP;
                            insert.data.ptr = client;
                            epoll_ctl(queue, EPOLL_CTL_MOD, client->socket, &insert);
#endif
                        }
                    }
#ifdef BSD
                } else {
                    close(results[i].ident);
                    delete (TCPClient*)results[i].udata;
#endif
                }
            }
        }
    }

    // Close TCP client sockets somehow (dunno how yet)

    close(tcp_skt);
    pthread_exit(NULL);
}

void dns_update_run()
{
    while (keep_running) {
        dns_data_read(0);
        sleep(update_interval);
    }
}

int main(int argc, char** argv)
{
    pthread_t thread;
    struct sched_param sparam;
    int i;
    keep_running = 1;

    threads.store(0);

    printf("%s\n\n", transdns_version);

    ips_count = handle_commandline(argc, argv);

    log_start();

    // open logging daemon connection and initialize our randomizer
    openlog("TransDNS", 0, LOG_DAEMON);
    srand(time(NULL));

    fflush(stdout);

    printf("\n");
    if (dns_data_read(1) < 0) {
        printf("\ndns_data_read exited with error...\n");
        exit(1);
    }

    if (ips_count == 0) {
        if (settings_have_been_read_from_config_file())
            printf("There are no ips specified in the config file (%s)\n", argv[1]);
        else
            printf("Usage: %s config_file|ip1 [ip2] [ip3] ...\nWhere each ip is an ip you want me to bound to!\n", argv[0]);
        exit(0);
    }

    signal(SIGUSR1, signal_usr1);
    signal(SIGTERM, signal_term);
    signal(SIGHUP, signal_panic);
    signal(SIGINT, signal_term);
    tcp_handler_mutex = PTHREAD_MUTEX_INITIALIZER;

    thread_queries = new unsigned long[(ips_count * udp_thread_count) + (ips_count * tcp_thread_count)];
    for (unsigned int i = 0; i < (ips_count * udp_thread_count) + (ips_count * tcp_thread_count); i++) {
        thread_queries[i] = 0;
    }

    // we need to do this before firing up the udp en tcp
    // threads, since those can handle notifies.
    if (support_notifies) {
        notify_start_handler();
    }

    for (i = 0; i < ips_count; i++) {
        char* ip = get_ip_to_bind_to(i);
        if (ip != NULL) {
            printf("binding to ip %s\n", ip);

            pthread_create(&thread, NULL, dns_udp_run, ip);
            pthread_detach(thread);
            pthread_create(&thread, NULL, dns_tcp_run, ip);
            pthread_detach(thread);
        }
    }
    printf("Up and running.\n");

    // We put this at very low priority so the update thread doesn't cause starvation, resulting in unresponsiveness.
    sparam.sched_priority = 0;
    pthread_setschedparam(pthread_self(), SCHED_OTHER, &sparam);

    dns_update_run();

    return 0;
}
