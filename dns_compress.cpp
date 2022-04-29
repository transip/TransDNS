#include "dns_compress.h"

/**
 * calculates the size of a dns name
 *
 * @param byte* in the encoded dns name
 * @return the length of the name, including size bytes
 */
static size_t compress_dns_name_length(byte* in)
{
    size_t len = 1;
    while (*in != 0) {
        if (*in > DNS_MAX_NAME_PART)
            return 0;

        len += *in + 1;
        in += *in + 1;
    }

    return len;
}

/**
 * Tries to compress a dns name by searching the existing dictionaries
 * or, if a label could not be compressed, add that label to the dictionary
 * so that it can be used later on.
 * A label is always added from its current point to the end of a dns-name,
 * since per the RFC, a compressed name must end with either a 0-sized label
 * or a pointer.
 *
 * @param byte* base the start of the work buffer
 * @param byte** work a pointer to the current position of the working buffer
 * @param byte* in the current position of the package being compressed
 * @param size_t len the length of the dns name  at in
 * @param dictionary_entry* entries the dictionary_entries
 * @param size_t* cur_dict_len a pointer to the current dictionary length
 * @param size_t max_dict_len the maximum length of the dictionary
 * @return size_t the number of bytes written to the work buffer (the work
 *                  buffers pointer will already be advanced further)
 */
static size_t compress_try_dns_name(byte* base,
    byte** work,
    byte* in,
    size_t len,
    dictionary_entry* entries,
    size_t* cur_dict_len,
    size_t max_dict_len)
{
    byte* in_start = in;
    size_t offset_start = *work - base;

    int seen_len = 0;
    while (*in != 0) {
        size_t item_len = len - seen_len;

        // try to see if we have a dns name we 've already seen
        // that runs to the end of the name we are examining
        for (size_t i = 0; i < *cur_dict_len; i++) {
            if (entries[i].len == item_len && memcmp(entries[i].name, in, item_len) == 0) {
                // encode pointer
                uint16 pointer = DNS_ENCODE_COMPRESSED_PTR(entries[i].offset);

                DBG_MSG("found match %s for %s @%x, ptr:%u",
                    entries[i].name,
                    in,
                    (int)entries[i].offset,
                    (unsigned)pointer);

                // copy the part of the label that we could not compress
                memcpy(*work, in_start, seen_len);
                *work += seen_len;

                // the part that already has been seen somewhere else
                // could be compressed by providing a pointer to it
                *((unsigned short*)*work) = htons(pointer);
                *work += 2;

                return seen_len + 2;
            }
        }

        // make sure we do not overflow our dictionary
        if (*cur_dict_len >= max_dict_len)
            break;

        // XXX for best performance, sort the lookup dictionary on size,
        //      so that we can end a possible search much earlier

        // we add the current position in the dns name to the end to our
        // dictionary
        entries[*cur_dict_len].name = in;
        entries[*cur_dict_len].len = item_len;
        entries[*cur_dict_len].offset = offset_start + seen_len;
        (*cur_dict_len)++;

#ifdef DEBUG
        char temp_name[DNS_MAX_NAME_PART + 1] = { 0 };
        memcpy(temp_name, in + 1, *in);
        DBG_MSG("%s (%x) [%i]", temp_name,
            (int)offset_start + seen_len,
            (int)*cur_dict_len);
#endif
        // advance thru the dns name
        seen_len += *in + 1;
        in += *in + 1;
    }

    // we were unable to compress the dns name, so
    // just copy it completely into the working buffer
    memcpy(*work, in_start, len);
    *work += len;

    return len;
}

/**
 * Compresses a dns resource record
 *
 * @param byte* base the start of the working buffer
 * @param byte** work a pointer to the current position of the working buffer
 * @param byte* in the current position of the package being compressed
 * @param dictionary_entry* entries the dictionary_entries
 * @param size_t* cur_dict_len a pointer to the current dictionary length
 * @param size_t max_dict_len the maximum length of the dictionary
 * @return int 0 on success, any other value otherwise
 */
static int compress_resource_record(byte* base,
    byte** work,
    byte** in,
    dictionary_entry* entries,
    size_t* cur_dict_len,
    size_t max_dict_len)
{
    size_t name_len = compress_dns_name_length(*in);
    compress_try_dns_name(base,
        work,
        *in,
        name_len,
        entries,
        cur_dict_len,
        max_dict_len);
    *in += name_len;

    // just copy the type, class and ttl fields
    memcpy(*work, *in, 8);
    *work += 8;

    *in += 2; // type
    *in += 2; // class
    *in += 4; // ttl

    // keep a pointer to the rdata len in the work buffer,
    // since we update it later on when we have compressed a dns name
    // in the rdata field

    short rdata_len = ntohs(*((short*)*in));
    *in += 2; // rdlength

#ifdef COMPRESS_RECORD_RDATA_CONTENTS

    // RFC5035#3.3:
    // In particular, NS, SOA, CNAME, and PTR
    // will be used in all classes, and have the same format in all classes.
    // Because their RDATA format is known, all domain names in the RDATA
    // section of these RRs may be compressed

    int rdata_offset = 0;
    if (DNS_TYPE_CNAME == type)
        rdata_offset = 0;

    int rdata_is_dns_name = DNS_TYPE_CNAME == type; // not 100% sure if this works correctly,
    // disabled via the COMPRESS_RECORD_RDATA_CONTENTS define

    // some rdata fields start with a "header", e.g. MX
    // rdata fields have a  2 byte priority before the dns name.
    // if the rdata_offset is set, we just copy these from the input package
    // to the work buffer and skip it for the compress operation
    if (rdata_offset > 0) {
        memcpy(*work, *in, rdata_offset); // priority or other 'header' fields.
        *work += rdata_offset;
    }

    if (rdata_is_dns_name) {

        name_len = compress_dns_name_length((*in + rdata_offset));
        *rdata_len_ptr = (short)compress_try_dns_name(base,
            work,
            (*in + rdata_offset),
            name_len,
            entries,
            cur_dict_len,
            max_dict_len);
    } else
#endif // COMPRESS_RECORD_RDATA_CONTENTS
    {
        // we can't compress rdata sections without dns names,
        // so just copy these over
        *((short*)*work) = htons(rdata_len);
        *work += 2;
        memcpy(*work, *in, rdata_len);
        *work += rdata_len;
    }

    // always skip the complete rdata contents field -> we have handled it
    *in += rdata_len;

    return 0;
}

/**
 * @param byte* the data of the package to compress
 * @param size_t len in the length of the package data
 * @param byte* out a buffer that will receive the compressed package,
 *                  must be at least len_in bytes long
 * @param size_t* len_out a pointer to a variable that will receive the  real 
 *                          size of the compressed buffer
 * @return int 0 on success, any other value on failure
 */
int compress_package(byte* in, size_t len_in, byte* out, size_t* len_out)
{
    byte* work = out;
    byte* base = work;

    uint16 num_questions = ntohs(offset_buffer(in, 4, short));
    uint16 num_answers = ntohs(offset_buffer(in, 6, short));
    uint16 num_authority = ntohs(offset_buffer(in, 8, short));
    uint16 num_additional = ntohs(offset_buffer(in, 10, short));

    DBG_MSG("questions: %d, answers: %d, authority: %d, additional: %d",
        num_questions,
        num_answers,
        num_authority,
        num_additional);

    // copy the header over, since we cannot compress it at all
    memcpy(work, in, 12);
    work += 12;
    in += 12; // package header

    // we use a dictionary to keep track of the possible names
    // that can be used for compression
    dictionary_entry dict_entries[COMPRESS_DICT_LEN] = { { 0 } };
    size_t cur_dict_len = 0;

    // skip questions
    for (short i = 0; i < num_questions; ++i) {
        size_t name_len = compress_dns_name_length(in);
        if (name_len == 0 || name_len >= DNS_MAX_DOMAIN_LENGTH) {
            return DNS_COMPRESS_FAILURE_INVALID_NAME_LENGTH; // bail-out, invalid name
        }

        compress_try_dns_name(base,
            &work,
            in,
            name_len,
            dict_entries,
            &cur_dict_len,
            COUNTOF(dict_entries));
        in += name_len;

        // don't touch the resource type and class fields
        memcpy(work, in, 4);
        work += 4;
        in += 2; // resource type
        in += 2; // class
    }

    // loop over all resource records of all sections and compress them
    uint16 num_all_answers = num_answers + num_authority + num_additional;
    for (uint16 i = 0; i < num_all_answers; ++i) {
        compress_resource_record(base,
            &work,
            &in,
            dict_entries,
            &cur_dict_len,
            COUNTOF(dict_entries));
    }

    *len_out = work - base;

    return 0;
}
