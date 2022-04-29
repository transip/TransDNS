/**
 * This module provides notify support for TransDNS
 */

#ifndef _NOTIFY_H
#define _NOTIFY_H

#include "dns_data.h"

/**
 * Answers a notify request
 *
 * @param request_context_t* context the request context to use
 * @return int the length of the response package or 0 on failure
 */
int dns_notify_answer(request_context_t* context);

/**
 * This function will start the notify handler
 * in a separate thread.
 */
void notify_start_handler();

#endif //_NOTIFY_H
