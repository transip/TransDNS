/**
 * Hash support for NSEC3
 *
 * Currently, we only support sha1 hashes
 */

#include <openssl/sha.h>

#ifndef HASH_CACHE_H
#define HASH_CACHE_H

#define HASH_MAX_SALT_LENGTH 256
#define HASH_MAX_IN_LENGTH 256
#define HASH_OUT_LEN 256

class hash_cache_t;

class hash_cache {
protected:
    hash_cache_t* cacheMap;

public:
    hash_cache();
    ~hash_cache();

    int get_iterated_hash(unsigned char out[HASH_OUT_LEN],
        const unsigned char* salt, int saltlength,
        const unsigned char* in, int inlength, int iterations);
};

int iterated_cached_hash(hash_cache* cache, unsigned char out[HASH_OUT_LEN],
    const unsigned char* salt, int saltlength,
    const unsigned char* in, int inlength, int iterations);

#endif //HASH_CACHE_H
