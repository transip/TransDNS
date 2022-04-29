/**
 * SHA1 hash support for NSEC3
 *
 */

#include <openssl/sha.h>
#include <stdio.h>

int iterated_hash(unsigned char out[SHA_DIGEST_LENGTH],
    const unsigned char* salt, int saltlength,
    const unsigned char* in, int inlength, int iterations)
{
    SHA_CTX ctx;
    int n;
    for (n = 0; n <= iterations; ++n) {
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, in, inlength);
        if (saltlength > 0)
            SHA1_Update(&ctx, salt, saltlength);
        SHA1_Final(out, &ctx);
        in = out;
        inlength = SHA_DIGEST_LENGTH;
    }
    return SHA_DIGEST_LENGTH;
}
