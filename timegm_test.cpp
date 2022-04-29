#include "misc.h"
#include <stdint.h>
#include <stdio.h>
#include <time.h>

int main(int argc, char** argv)
{
    printf("Testing all possible 32-bits values for custom_timegm\n");

    for (time_t clock = 0; clock < UINT32_MAX; clock++) {
        struct tm* time = gmtime(&clock);
        unsigned long customResult = custom_timegm(time);

        if (customResult != clock) {
            printf("Test failed for clock: %lu, customResult: %lu\n", clock, customResult);
            return 1;
        }
    }

    printf("Tests successfull for all values between 0 and UINT32_MAX\n");
    return 0;
}
