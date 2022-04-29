/**
 * Hash support for NSEC3
 *
 * Currently, we only support sha1 hashes
 */

#include <openssl/sha.h>

int iterated_hash(unsigned char out[SHA_DIGEST_LENGTH],
    const unsigned char* salt, int saltlength,
    const unsigned char* in, int inlength, int iterations);
