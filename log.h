/**
 * This module provides logging support for TransDNS
 */

#ifndef _LOG_H
#define _LOG_H

#include "request_context.h"

void log_start();
void log_end();
void log_request(request_context_t* context);

#endif //_LOG_H
