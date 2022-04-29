/**
 * Base32 conversion routines
 */

#ifndef _BASE32_H
#define _BASE32_H

int base32_encode(unsigned char const* src, int srclength, char* target, int targsize);
int base32_decode(const char* str, unsigned char* output, int output_len);

#endif //_BASE32_H
