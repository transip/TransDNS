#include "dns.h"
#include <stdint.h>
#include <stdio.h>
#include <time.h>

int main(int argc, char** argv)
{
    char root[] = { 0 }; // '.'
    char goodname[] = { 7, 't', 'r', 'a', 'n', 's', 'i', 'p', 2, 'n', 'l', 0 };
    char badname[] = { 7, 't', 'r', 'a', 'n', 's', 'i', 'p', 3, 'n', 'l', 0 };
    char reallybadname[] = { 7, 't', 'r', 'a', 'n', 's', 'i', 'p', -9, 'n', 'l', 0 };
    int res = 0;
    bool failed = false;
    printf("Testing a few names for domain_name_length\n");

    res = dns_domain_length(root, sizeof(root));
    if (res != sizeof(root)) {
        printf("Failed root test, got %d instead of %lu\n", res, sizeof(root));
        failed = true;
    }

    res = dns_domain_length(goodname, sizeof(goodname));
    if (res != sizeof(goodname)) {
        printf("Failed goodname test, got %d instead of %lu\n", res, sizeof(goodname));
        failed = true;
    }

    res = dns_domain_length(badname, sizeof(badname));
    if (res != 0) {
        printf("Failed badname test, got %d instead of 0\n", res);
        failed = true;
    }

    res = dns_domain_length(reallybadname, sizeof(reallybadname));
    if (res != 0) {
        printf("Failed reallybadname test, got %d instead of 0\n", res);
    }

    if (failed) {
        printf("Some tests failed!\n");
        return 1;
    }
    printf("Tests successfull for all names\n");
    return 0;
}
