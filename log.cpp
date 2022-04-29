/**
 * This module provides Logging support for TransDNS
 */

#include "log.h"
#include "settings.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static FILE* fpLog = NULL;
unsigned int log_count = 0;

void log_start()
{
    if (use_translog) {
        log_count = 0;
        fpLog = fopen(translog_filename, "a");
        if (fpLog == NULL) {
            printf("Could not open logfile '%s'\n", translog_filename);
            exit(1);
        }
    }
}

void log_end()
{
    if (fpLog != NULL) {
        fclose(fpLog);
        fpLog = NULL;
    }
}

void log_request(request_context_t* context)
{
    if (use_translog) {
        char time_buffer[100];
        time_t curtime;
        struct timeval tv;

        gettimeofday(&tv, NULL);
        curtime = tv.tv_sec;
        strftime(time_buffer, 100, "%m-%d-%Y  %T.", localtime(&curtime));

        if (log_count >= translog_max_queries) {
            log_count = 0;
            fclose(fpLog);
            unlink(translog_filename);
            fpLog = fopen(translog_filename, "a");
        }
        log_count++;
        fprintf(fpLog, "%s%ld %s %d\n\n", time_buffer, tv.tv_usec, context->get_source_address(), context->query_len);
        fwrite(context->buf, context->query_len, 1, fpLog);
    }
}
