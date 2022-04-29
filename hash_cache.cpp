/**
 * SHA1 hash support for NSEC3
 *
 */

#include "hash_cache.h"
#include "hash.h"
#include "settings.h"
#include <functional>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <unordered_map>

struct hash_cache_key {
    int iterations;
    unsigned char salt[256];
    int saltlength;

    unsigned char in[256];
    int inlength;
    const bool operator==(const hash_cache_key& h) const
    {
        if (iterations != h.iterations)
            return false;

        if (saltlength != h.saltlength)
            return false;

        if (inlength != h.inlength)
            return false;

        if (memcmp(salt, h.salt, saltlength) != 0)
            return false;

        if (memcmp(in, h.in, inlength) != 0)
            return false;

        return true;
    }
};

struct hash_cache_entry {
    unsigned char hash[SHA_DIGEST_LENGTH];
};

class hash_cache_key_hash_functor : public std::unary_function<hash_cache_key, size_t> {
public:
    size_t operator()(const hash_cache_key& q) const
    {
        size_t hash = 5381;

        for (int i = 0; i < q.saltlength; ++i)
            hash = ((hash << 5) + hash) + q.salt[i];

        for (int i = 0; i < q.inlength; ++i)
            hash = ((hash << 5) + hash) + q.in[i];

        return ((hash << 5) + hash) + q.iterations;
    }
};

// trickery so we can do a forward declare, speeding up compiliation times
typedef std::unordered_map<hash_cache_key, hash_cache_entry, hash_cache_key_hash_functor> hash_cache_base_t;
typedef hash_cache_base_t::iterator hash_cache_iter_t;
class hash_cache_t : public hash_cache_base_t {
};

hash_cache::hash_cache()
{
    cacheMap = new hash_cache_t;
}

hash_cache::~hash_cache()
{
    delete cacheMap;
}

int hash_cache::get_iterated_hash(unsigned char out[HASH_OUT_LEN],
    const unsigned char* salt, int saltlength,
    const unsigned char* in, int inlength, int iterations)
{
    bool should_use_cache = true;
    hash_cache_key key;

    if (should_use_cache) {
        // built our cache key
        key.iterations = iterations;
        key.inlength = inlength;
        key.saltlength = saltlength;
        memcpy(key.salt, salt, saltlength);
        memcpy(key.in, in, inlength);

        // check the per-thread cache for the existance of our hash
        const hash_cache_iter_t& iter = cacheMap->find(key);
        if (iter != cacheMap->end()) {
            memcpy(out, iter->second.hash, SHA_DIGEST_LENGTH);
            return SHA_DIGEST_LENGTH;
        }
    }

    int result = iterated_hash(out, salt, saltlength, in, inlength, iterations);

    if (should_use_cache) {
        // if our cache is full, half it
        if (cacheMap->size() >= dnssec_nsec3_hash_cache_size) {
            cacheMap->clear();
            /*

            hash_cache_iter_t start = cacheMap->begin();
            hash_cache_iter_t mid   = start + (cacheMap->size() / 2);
            cacheMap->erase(start, mid);
            */
        }

        // add our calculated hash to the cache
        hash_cache_entry entry;
        memcpy(entry.hash, out, SHA_DIGEST_LENGTH);
        cacheMap->insert(std::make_pair(key, entry));
    }

    return result;
}

int iterated_cached_hash(hash_cache* cache, unsigned char out[HASH_OUT_LEN],
    const unsigned char* salt, int saltlength,
    const unsigned char* in, int inlength, int iterations)
{
    if (cache != NULL && dnssec_nsec3_hash_cache_size > 0) {
        return cache->get_iterated_hash(out, salt, saltlength, in, inlength, iterations);
    } else {
        return iterated_hash(out, salt, saltlength, in, inlength, iterations);
    }
}
