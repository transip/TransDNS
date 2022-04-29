/**
 * This module provides support functions for the request context
 */

#include "request_context.h"
#include "misc.h"
#include <cassert>
#include <stdio.h>

char* request_context_t::get_source_address()
{
    if (this->source_addr[0] == '\0' && this->sockaddr != NULL) {
        address_from_sockaddr_storage(this->sockaddr, this->source_addr, sizeof(this->source_addr));
    }

    return this->source_addr;
}

void request_context_t::_new_response_info()
{
    number_of_response_infos++;
}

response_info_t* request_context_t::get_current_response_info()
{
    // ensure that we have an initial response info
    if (number_of_response_infos == 0)
        _new_response_info();

    assert(number_of_response_infos > 0);

    response_info_t* info = &response_info_chain[number_of_response_infos - 1];
    if (info->q.name == NULL) // ensure qname is set in q
        info->q.name = info->qname;

    return info;
}

response_info_t* request_context_t::start_response_info()
{
    // this will automatically create the first response info when needed
    _new_response_info();
    return get_current_response_info();
}

void request_context_t::debug_print()
{
    for (int i = 0; i < number_of_response_infos; ++i) {
        printf("RESPONSE INFO %d =================\n", i);
        response_info_chain[i].debug_print();
    }
}
